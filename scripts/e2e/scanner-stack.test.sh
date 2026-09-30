#!/usr/bin/env bash
# Exercises scripts/e2e/scanner-stack.sh's down() itself, with a stub
# `docker` on PATH so it needs no real daemon: proves every leg
# scanner.sh actually runs (four, not the three down() used to loop
# over) gets torn down.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK="$HERE/scanner-stack.sh"
export E2E_PREFIX="birdcage-e2e-scannerselftest"

fail=0
check() { # check <actual> <expected> <label>
  if [ "$1" = "$2" ]; then
    echo "ok - $3"
  else
    echo "FAIL - $3: expected [$2] got [$1]"
    fail=1
  fi
}

fakebin="$(mktemp -d)"
trap 'rm -rf "$fakebin"' EXIT
logfile="$fakebin/docker.log"
cat > "$fakebin/docker" <<SCRIPT
#!/usr/bin/env bash
echo "\$*" >> "$logfile"
exit 0
SCRIPT
chmod +x "$fakebin/docker"

echo "== down is safe and exits 0 =="
PATH="$fakebin:$PATH" "$STACK" down >/dev/null 2>&1
check "$?" "0" "down exits 0"

echo "== down touches every leg scanner.sh runs, including leg 4 =="
calls="$(cat "$logfile")"
for n in 1 2 3 4; do
  case "$calls" in
    *"rm --force ${E2E_PREFIX}-scanner-leg$n"*) echo "ok - down removes leg $n's container" ;;
    *) echo "FAIL - down never touches leg $n's container (${E2E_PREFIX}-scanner-leg$n)"; fail=1 ;;
  esac
  case "$calls" in
    *"volume rm --force ${E2E_PREFIX}-scanner-state-leg$n"*) echo "ok - down removes leg $n's state volume" ;;
    *) echo "FAIL - down never touches leg $n's state volume (${E2E_PREFIX}-scanner-state-leg$n)"; fail=1 ;;
  esac
done

exit "$fail"
