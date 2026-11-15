#!/usr/bin/env sh
# Exercises scripts/e2e/totp.sh against RFC 6238 appendix B's SHA-1
# vectors (key "12345678901234567890", whose base32 is below), cut to
# the six digits gauntlet uses: the low six digits of each eight-digit
# answer, since both are the same truncated value modulo a power of ten.
#
# POSIX sh on purpose: the journeys run totp.sh in the helper
# container's busybox sh, so this runs under whatever `sh` is, and
# again under busybox when it is installed.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/totp.sh"

fail=0
check() { # check <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    echo "ok - $3"
  else
    echo "FAIL - $3: expected [$2] got [$1]"
    fail=1
  fi
}

RFC_VECTOR=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ

for vector in 59:287082 1111111109:081804 1111111111:050471 1234567890:005924 2000000000:279037 20000000000:353130; do
  t="${vector%%:*}"
  want="${vector#*:}"
  check "$(totp_code "$RFC_VECTOR" "$((t / 30))")" "$want" "RFC 6238 SHA-1 vector at T=$t"
done

check "$(totp_code "$(printf '%s' "$RFC_VECTOR" | tr 'A-Z' 'a-z')" 1)" 287082 "a lower-case secret gives the same code"
check "$(totp_code "${RFC_VECTOR}======" 1)" 287082 "padding is ignored"

if totp_code 'not!base32' 1 >/dev/null 2>&1; then
  echo "FAIL - a secret that is not base32 was accepted"
  fail=1
else
  echo "ok - a secret that is not base32 is refused"
fi

# The same vectors under busybox sh, the helper container's shell, when
# this machine has it and this is not already that run.
if [ -z "${TOTP_TEST_INNER:-}" ] && command -v busybox >/dev/null 2>&1; then
  echo "== again under busybox sh =="
  TOTP_TEST_INNER=1 busybox sh "$0" || fail=1
fi

exit "$fail"
