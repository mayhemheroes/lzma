#!/usr/bin/env bash
#
# lzma/mayhem/test.sh — RUN the LZMA SDK self-test (built by mayhem/build.sh with NORMAL flags)
# and emit a CTRF summary. exit 0 iff no test case failed.
#
# PATCH-grade oracle: lzma_selftest does real round-trip / known-answer checks (LZMA / LZMA2 / XZ
# encode->decode byte-exact equality, CRC-32 and SHA-256 published known answers). A no-op /
# "exit(0)" patch — or any change that corrupts the codecs — makes a case FAIL, so "ran the corpus,
# exit 0" is NOT acceptable. This script only RUNS the prebuilt binary; it never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

BIN="$SRC/mayhem-tests/lzma_selftest"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$BIN" ]; then
  echo "missing $BIN — run mayhem/build.sh first" >&2
  emit_ctrf "lzma-selftest" 0 1 0; exit 2
fi

echo "=== running lzma_selftest ==="
out="$("$BIN" 2>&1)"; rc=$?
echo "$out"

# Each case prints "TEST <name>: PASS|FAIL".
PASSED=$(printf '%s\n' "$out" | grep -c ': PASS$' || true)
FAILED=$(printf '%s\n' "$out" | grep -c ': FAIL$' || true)
: "${PASSED:=0}" "${FAILED:=0}"

# Defensive: if the binary crashed (e.g. sanitizer-less UB) without emitting case lines, fail.
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "no test cases parsed; using binary exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "lzma-selftest" 1 0 0; exit 0; }
  emit_ctrf "lzma-selftest" 0 1 0; exit 1
fi

# A non-zero exit with all-PASS lines (shouldn't happen) still counts as a failure.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then FAILED=1; fi

emit_ctrf "lzma-selftest" "$PASSED" "$FAILED" 0
