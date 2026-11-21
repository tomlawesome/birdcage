#!/usr/bin/env bash
# Exercises scripts/e2e/journey.sh's helper()/poll() bound directly,
# against a fake E2E_STACK so it never needs a real stack or docker:
# a `helper` call that never returns must not block poll()'s retry
# loop past its own stated attempts bound.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fakebin="$(mktemp -d)"
trap 'rm -rf "$fakebin"' EXIT

fail=0
check() { # check <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    echo "ok - $3"
  else
    echo "FAIL - $3: expected [$2] got [$1]"
    fail=1
  fi
}

# Stands in for stack.sh: `helper hang` never returns (a connection
# accepted and then never answering); `helper ok` returns immediately.
cat > "$fakebin/fake-stack.sh" <<'SCRIPT'
#!/usr/bin/env bash
case "$1 $2" in
  "helper hang") sleep 3600 ;;
  "helper ok") exit 0 ;;
  *) exit 1 ;;
esac
SCRIPT
chmod +x "$fakebin/fake-stack.sh"

export E2E_STACK="$fakebin/fake-stack.sh"
export E2E_HELPER_TIMEOUT=1
. "$HERE/journey.sh" >/dev/null

echo "== helper() bounds a hung call instead of blocking forever =="
start="$SECONDS"
helper hang >/dev/null 2>&1
rc=$?
elapsed=$((SECONDS - start))
check "$([ "$elapsed" -le 5 ] && echo bounded || echo unbounded)" "bounded" "helper hang returned within a few seconds, not never"
if [ "$rc" -ne 0 ]; then echo "ok - helper hang reports failure"; else echo "FAIL - helper hang reported success"; fail=1; fi

echo "== helper() still succeeds normally =="
helper ok >/dev/null 2>&1
check "$?" "0" "helper ok succeeds"

echo "== poll()'s own attempts bound holds even when every attempt hangs =="
start="$SECONDS"
poll 3 helper hang >/dev/null 2>&1
rc=$?
elapsed=$((SECONDS - start))
check "$rc" "1" "poll exhausts its attempts and returns failure"
check "$([ "$elapsed" -le 10 ] && echo bounded || echo unbounded)" "bounded" "poll returned within its attempts bound, not blocked indefinitely"

echo "== fail() still exits 1 and names the step when docker is absent =="
stubbin="$(mktemp -d)"
printf '#!/bin/sh\nexit 127\n' > "$stubbin/docker"
chmod +x "$stubbin/docker"
out="$(PATH="$stubbin:$PATH" E2E_PREFIX=e2etest E2E_BIRDCAGE=e2etest-birdcage \
  bash -c '. "$1" >/dev/null; step "probe"; fail "boom"' _ "$HERE/journey.sh" 2>&1)"
rc=$?
rm -rf "$stubbin"
check "$rc" "1" "fail() exits 1 with docker failing"
case "$out" in
  *"step 1 (probe) FAILED: boom"*) echo "ok - fail() prints the step line" ;;
  *) echo "FAIL - fail() did not print the step line: $out"; fail=1 ;;
esac

exit "$fail"
