/*
 * lzma/mayhem/lzma_selftest.c — known-answer / round-trip oracle for the vendored LZMA SDK.
 *
 * This is a PATCH-grade behavioral test: it asserts BYTE-EXACT results, so a no-op / exit(0)
 * patch (or any change that corrupts the codecs) fails it. Built with NORMAL flags by build.sh;
 * test.sh only RUNS it. Prints one "TEST <name>: PASS|FAIL" line per case and exits non-zero on
 * any failure.
 *
 * Cases:
 *   1) lzma_roundtrip  — LzmaEnc a known payload, LzmaDec it, assert decoded bytes == original.
 *   2) lzma2_roundtrip — Lzma2Enc a known payload, Lzma2Decode it, assert decoded bytes == original.
 *   3) xz_roundtrip    — XzEnc a known payload, XzDecMt_Decode it, assert decoded bytes == original.
 *   4) crc32_kat       — CrcCalc over "123456789" == 0xCBF43926 (standard CRC-32 known answer).
 *   5) sha256_kat      — SHA-256("abc") == the published digest (NIST known-answer test).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "7zCrc.h"
#include "XzCrc64.h"
#include "Sha256.h"
#include "LzmaEnc.h"
#include "LzmaDec.h"
#include "Lzma2Enc.h"
#include "Lzma2Dec.h"
#include "Xz.h"
#include "XzEnc.h"

static void *SzAlloc(ISzAllocPtr p, size_t s) { (void)p; return malloc(s); }
static void SzFree(ISzAllocPtr p, void *a) { (void)p; free(a); }
static const ISzAlloc g_Alloc = { SzAlloc, SzFree };

/* A simple in-memory output stream for the encoders. */
typedef struct {
  ISeqOutStream vt;
  Byte *buf;
  size_t size;
  size_t cap;
} MemOut;

static size_t MemOut_Write(const ISeqOutStream *pp, const void *data, size_t size) {
  MemOut *m = (MemOut *)pp;
  if (m->size + size > m->cap) {
    size_t ncap = (m->size + size) * 2 + 64;
    m->buf = (Byte *)realloc(m->buf, ncap);
    m->cap = ncap;
  }
  memcpy(m->buf + m->size, data, size);
  m->size += size;
  return size;
}

typedef struct {
  ISeqInStream vt;
  const Byte *data;
  size_t size;
  size_t pos;
} MemIn;

static SRes MemIn_Read(const ISeqInStream *pp, void *data, size_t *size) {
  MemIn *m = (MemIn *)pp;
  size_t want = *size;
  size_t avail = m->size - m->pos;
  if (want > avail) want = avail;
  memcpy(data, m->data + m->pos, want);
  m->pos += want;
  *size = want;
  return SZ_OK;
}

static int g_fail = 0;
static void report(const char *name, int ok) {
  printf("TEST %s: %s\n", name, ok ? "PASS" : "FAIL");
  if (!ok) g_fail = 1;
}

static const char kPayload[] =
    "The quick brown fox jumps over the lazy dog. "
    "Pack my box with five dozen liquor jugs. "
    "0123456789 LZMA SDK round-trip known-answer test payload.";

static void test_lzma_roundtrip(void) {
  const size_t inSize = sizeof(kPayload) - 1;
  CLzmaEncProps props;
  LzmaEncProps_Init(&props);
  props.level = 5;
  props.dictSize = 1 << 16;

  Byte propsEnc[LZMA_PROPS_SIZE];
  SizeT propsSize = LZMA_PROPS_SIZE;
  CLzmaEncHandle enc = LzmaEnc_Create(&g_Alloc);
  if (!enc) { report("lzma_roundtrip", 0); return; }

  MemOut out = { { MemOut_Write }, NULL, 0, 0 };
  MemIn in = { { MemIn_Read }, (const Byte *)kPayload, inSize, 0 };

  int ok = 1;
  ok = ok && (LzmaEnc_SetProps(enc, &props) == SZ_OK);
  ok = ok && (LzmaEnc_WriteProperties(enc, propsEnc, &propsSize) == SZ_OK);
  ok = ok && (LzmaEnc_Encode(enc, &out.vt, &in.vt, NULL, &g_Alloc, &g_Alloc) == SZ_OK);
  ok = ok && (out.size > 0);

  if (ok) {
    Byte *dec = (Byte *)malloc(inSize);
    SizeT destLen = inSize;
    SizeT srcLen = out.size;
    ELzmaStatus status;
    SRes r = LzmaDecode(dec, &destLen, out.buf, &srcLen, propsEnc, propsSize,
                        LZMA_FINISH_END, &status, &g_Alloc);
    ok = ok && (r == SZ_OK) && (destLen == inSize) &&
         (memcmp(dec, kPayload, inSize) == 0);
    free(dec);
  }
  LzmaEnc_Destroy(enc, &g_Alloc, &g_Alloc);
  free(out.buf);
  report("lzma_roundtrip", ok);
}

static void test_lzma2_roundtrip(void) {
  const size_t inSize = sizeof(kPayload) - 1;
  CLzma2EncProps props;
  Lzma2EncProps_Init(&props);
  props.lzmaProps.level = 5;
  props.lzmaProps.dictSize = 1 << 16;
  Lzma2EncProps_Normalize(&props);

  CLzma2EncHandle enc = Lzma2Enc_Create(&g_Alloc, &g_Alloc);
  if (!enc) { report("lzma2_roundtrip", 0); return; }

  MemOut out = { { MemOut_Write }, NULL, 0, 0 };
  MemIn in = { { MemIn_Read }, (const Byte *)kPayload, inSize, 0 };

  int ok = (Lzma2Enc_SetProps(enc, &props) == SZ_OK);
  Byte propByte = Lzma2Enc_WriteProperties(enc);
  ok = ok && (Lzma2Enc_Encode2(enc, &out.vt, NULL, 0, &in.vt, NULL, 0, NULL) == SZ_OK);
  ok = ok && (out.size > 0);

  if (ok) {
    Byte *dec = (Byte *)malloc(inSize);
    SizeT destLen = inSize;
    SizeT srcLen = out.size;
    ELzmaStatus status;
    SRes r = Lzma2Decode(dec, &destLen, out.buf, &srcLen, propByte,
                         LZMA_FINISH_END, &status, &g_Alloc);
    ok = ok && (r == SZ_OK) && (destLen == inSize) &&
         (memcmp(dec, kPayload, inSize) == 0);
    free(dec);
  }
  Lzma2Enc_Destroy(enc);
  free(out.buf);
  report("lzma2_roundtrip", ok);
}

static void test_xz_roundtrip(void) {
  const size_t inSize = sizeof(kPayload) - 1;
  CrcGenerateTable();
  Crc64GenerateTable();

  CXzProps props;
  XzProps_Init(&props);
  props.checkId = XZ_CHECK_CRC32;

  MemOut out = { { MemOut_Write }, NULL, 0, 0 };
  MemIn in = { { MemIn_Read }, (const Byte *)kPayload, inSize, 0 };

  CXzEncHandle enc = XzEnc_Create(&g_Alloc, &g_Alloc);
  int ok = (enc != NULL);
  ok = ok && (XzEnc_SetProps(enc, &props) == SZ_OK);
  XzEnc_SetDataSize(enc, inSize);
  ok = ok && (XzEnc_Encode(enc, &out.vt, &in.vt, NULL) == SZ_OK);
  ok = ok && (out.size > 0);

  if (ok) {
    CXzDecMtProps dprops;
    XzDecMtProps_Init(&dprops);
    MemOut decout = { { MemOut_Write }, NULL, 0, 0 };
    MemIn decin = { { MemIn_Read }, out.buf, out.size, 0 };
    CXzStatInfo stats;
    int isMt;
    CXzDecMtHandle dec = XzDecMt_Create(&g_Alloc, &g_Alloc);
    SRes r = XzDecMt_Decode(dec, &dprops, NULL, 1, &decout.vt, &decin.vt,
                            &stats, &isMt, NULL);
    ok = ok && (r == SZ_OK) && (decout.size == inSize) &&
         (memcmp(decout.buf, kPayload, inSize) == 0);
    XzDecMt_Destroy(dec);
    free(decout.buf);
  }
  if (enc) XzEnc_Destroy(enc);
  free(out.buf);
  report("xz_roundtrip", ok);
}

static void test_crc32_kat(void) {
  CrcGenerateTable();
  /* CRC-32/ISO-HDLC known answer over the ASCII string "123456789". */
  UInt32 crc = CrcCalc("123456789", 9);
  report("crc32_kat", crc == 0xCBF43926u);
}

static void test_sha256_kat(void) {
  /* SHA-256("abc") known-answer test (FIPS 180-4). */
  static const Byte expected[SHA256_DIGEST_SIZE] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
  };
  CSha256 sha;
  Byte digest[SHA256_DIGEST_SIZE];
  Sha256_Init(&sha);
  Sha256_Update(&sha, (const Byte *)"abc", 3);
  Sha256_Final(&sha, digest);
  report("sha256_kat", memcmp(digest, expected, SHA256_DIGEST_SIZE) == 0);
}

int main(void) {
  test_lzma_roundtrip();
  test_lzma2_roundtrip();
  test_xz_roundtrip();
  test_crc32_kat();
  test_sha256_kat();
  if (g_fail) {
    fprintf(stderr, "lzma_selftest: FAILURES present\n");
    return 1;
  }
  printf("lzma_selftest: ALL PASS\n");
  return 0;
}
