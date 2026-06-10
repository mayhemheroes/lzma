#!/usr/bin/env bash
#
# lzma/mayhem/build.sh — build fancycode/lzma-fuzz's OSS-Fuzz harnesses (the LZMA SDK fuzzers,
# 7-Zip SDK 19.00 vendored under sdk/) as sanitized libFuzzer targets (+ a standalone reproducer
# per harness), AND the project's own decode/encode round-trip checks for mayhem/test.sh.
#
# The fuzzed surface is the LZMA SDK codec stack on attacker-controlled compressed bytes:
#   7z_fuzzer        — opens + extracts every entry of a .7z archive (SzArEx_Open / SzArEx_Extract).
#   xzdec_fuzzer     — decodes a .xz stream (XzDecMt_Decode).
#   lzmadec_fuzzer   — decodes a raw LZMA stream (props byte(s) + payload, LzmaDec_DecodeToBuf).
#   lzma2dec_fuzzer  — decodes a raw LZMA2 stream (dict prop byte + payload, Lzma2Dec_DecodeToBuf).
#   filters_fuzzer   — runs the BCJ/Delta/AES/CRC/SHA filters over raw bytes (encode/decode round-trip).
#   xzenc_fuzzer     — encodes raw bytes to .xz then decodes + asserts the round-trip matches.
#   lzmaenc_fuzzer   — LZMA encode (props from first 10 bytes) then decode round-trip assert.
#   lzma2enc_fuzzer  — LZMA2 encode (props from first 10 bytes) then decode round-trip assert.
#   ppmdenc_fuzzer   — PPMd7 range-encode each input byte then decode + assert symbol equality.
# The dec/7z/xzdec harnesses take real compressed inputs; the enc/filters/ppmd harnesses interpret
# leading bytes as codec parameters (see each *_fuzzer.cc).
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). The LZMA SDK C sources ARE compiled with $SANITIZER_FLAGS so the codec
# code (not just the C++ harness) is instrumented.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS

# When building libFuzzer targets the library code MUST be compiled with -fsanitize=fuzzer-no-link
# so clang instruments every basic block with SanitizerCoverage PC-guards.  Without this flag the
# codec objects carry no coverage instrumentation and Mayhem records 0 edges → "Run Failed".
# Guard the flag: only add it when the engine is libFuzzer (contains the word "fuzzer"); the
# standalone / test builds must NOT get -fsanitize=fuzzer-no-link (it requires the fuzzer runtime).
COVERAGE_FLAGS=""
if [[ "$LIB_FUZZING_ENGINE" == *fuzzer* ]]; then
  COVERAGE_FLAGS="-fsanitize=fuzzer-no-link"
fi

# The 7-Zip/LZMA SDK uses type-erased vtables pervasively: e.g. the IMatchFinder
# interface stores MatchFinder_Init (a void(CMatchFinder*)) in an Init field typed
# void(*)(void*) (LzFind.h Mf_Init_Func), and LzmaEnc_CodeOneBlock calls it through that
# pointer (LzmaEnc.c:2267). The same void*-erased-callback idiom recurs across the SDK
# alloc/stream interfaces. UBSan -fsanitize=function (CFI-style function-pointer-type
# check, part of the default undefined set) flags every such call as a runtime error and,
# with -fno-sanitize-recover=all, ABORTS on the first input. That tripped lzmaenc_fuzzer
# and xzenc_fuzzer on their own valid seeds (defect on 0 edges) though the encode is
# correct -- NOT a memory-safety bug. Build the SDK codec library WITHOUT the function
# check only; ASan and every other UBSan check stay on and halting, and the harnesses
# themselves remain fully instrumented.
SDK_NO_SANITIZE="-fno-sanitize=function"

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
SDK="$SRC/sdk/C"
INC="-I$SDK"
# Single-thread SDK build (matches the OSS-Fuzz Makefile default: ENABLE_MT unset -> -D_7ZIP_ST=1),
# plus PPMd support so ppmdenc_fuzzer and 7z PPMd archives work.
SDK_FLAGS="-D_7ZIP_PPMD_SUPPPORT -D_7ZIP_ST=1"

# LZMA SDK C sources compiled into the codec library (from the OSS-Fuzz Makefile C_SOURCES list).
SDK_SRCS="
  7zAlloc.c 7zArcIn.c 7zBuf2.c 7zBuf.c 7zCrc.c 7zCrcOpt.c 7zDec.c 7zFile.c 7zStream.c
  Aes.c AesOpt.c Alloc.c Bcj2.c Bcj2Enc.c Bra86.c Bra.c BraIA64.c CpuArch.c Delta.c
  DllSecur.c LzFind.c Lzma2Dec.c Lzma2DecMt.c Lzma2Enc.c Lzma86Dec.c LzmaDec.c LzmaEnc.c
  LzmaLib.c MtCoder.c MtDec.c Ppmd7.c Ppmd7Dec.c Ppmd7Enc.c Sha256.c Sort.c Xz.c
  XzCrc64.c XzCrc64Opt.c XzDec.c XzEnc.c XzIn.c
"

BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"

# ── 1) Build the LZMA SDK static codec library WITH sanitizers ─────────────────────────────────────
OBJS=()
for s in $SDK_SRCS; do
  obj="$BUILD/${s%.c}.o"
  $CC $SANITIZER_FLAGS $SDK_NO_SANITIZE $COVERAGE_FLAGS $DEBUG_FLAGS $SDK_FLAGS $INC -c "$SDK/$s" -o "$obj"
  OBJS+=("$obj")
done
LIBLZMA="$BUILD/liblzma.a"
rm -f "$LIBLZMA"; ar rcs "$LIBLZMA" "${OBJS[@]}"

# Standalone driver (reads one input file, calls LLVMFuzzerTestOneInput once, no libFuzzer runtime).
# The base ships it as C; compile it as a C object so it links cleanly against the C++ harnesses.
# COVERAGE_FLAGS is intentionally omitted here: the standalone binary uses no fuzzer runtime.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

# ── 2) Build each harness twice: libFuzzer (-> /mayhem/<name>) + standalone reproducer ─────────────
FUZZERS="7z_fuzzer filters_fuzzer lzma2dec_fuzzer lzma2enc_fuzzer lzmadec_fuzzer lzmaenc_fuzzer ppmdenc_fuzzer xzdec_fuzzer xzenc_fuzzer"
for harness in $FUZZERS; do
  # libFuzzer target -> /mayhem/<name>
  $CXX $SANITIZER_FLAGS $COVERAGE_FLAGS $DEBUG_FLAGS $INC \
      "$HARNESS_DIR/$harness.cc" $LIB_FUZZING_ENGINE "$LIBLZMA" \
      -o "/mayhem/$harness"

  # standalone reproducer (no libFuzzer runtime) -> /mayhem/<name>-standalone
  # COVERAGE_FLAGS omitted: no fuzzer runtime linked here.
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
      "$HARNESS_DIR/$harness.cc" "$BUILD/standalone_main.o" "$LIBLZMA" \
      -o "/mayhem/$harness-standalone"

  echo "built $harness (+ standalone)"
done

# ── 3) Build the LZMA SDK self-test (round-trip / known-answer oracle) with NORMAL flags so
#       test.sh only RUNS it. A separate, sanitizer-free object tree keeps test.sh an honest
#       PATCH oracle (asserts byte-exact codec output; a no-op/exit(0) patch fails it). ──────────────
TESTBUILD="$SRC/mayhem-tests"
mkdir -p "$TESTBUILD"
TEST_OBJS=()
for s in $SDK_SRCS; do
  obj="$TESTBUILD/${s%.c}.o"
  $CC $SDK_FLAGS $INC -O2 -c "$SDK/$s" -o "$obj"
  TEST_OBJS+=("$obj")
done
$CC $INC -O2 -c "$SRC/mayhem/lzma_selftest.c" -o "$TESTBUILD/lzma_selftest.o"
$CC -O2 "$TESTBUILD/lzma_selftest.o" "${TEST_OBJS[@]}" -o "$TESTBUILD/lzma_selftest"
echo "built lzma_selftest in mayhem-tests/"

echo "build.sh complete:"
for f in $FUZZERS; do ls -la "/mayhem/$f" "/mayhem/$f-standalone" 2>&1 || true; done
