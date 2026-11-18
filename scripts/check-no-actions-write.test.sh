#!/usr/bin/env bash
# Tests for check-no-actions-write.sh (#169, item A). No network and never a
# real dispatch: `curl` (and `gh`) are stubs first on PATH. The stub answers
# by the shape of the request -- a POST to .../dispatches is the dispatch,
# anything else is the ref lookup -- and logs every call's arguments so the
# suite can prove what was and was not called.
#
# Contract pinned here (from the #169 spec):
#   - credential in $GH_TOKEN, repo in $GITHUB_REPOSITORY (owner/name);
#   - HTTP calls go through `curl`, and the credential is never in argv;
#   - the ref lookup is a GET whose HTTP status 404 means "ref absent";
#   - before any ref lookup or dispatch, GET .../actions/workflows/countersign.yml
#     must answer 200, else exit 2 with nothing dispatched (a wrong repo or a
#     renamed workflow answers 404 to everything and must not read as a pass);
#   - GITHUB_API_URL, if set, must start with https:// else exit 2 and no call
#     at all (the token must never travel in clear text);
#   - Deployments write is NOT tested here (that is documented, see
#     releasing-docs.test.sh);
#   - dispatch 403/404 -> exit 0 "no Actions write"; 422 -> exit 1; any 2xx
#     -> exit 1 ("a run may have started"); anything else -> exit 2.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-no-actions-write.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0
token="ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000"

mkdir -p "$work/bin"
cat > "$work/bin/curl" <<'STUB'
#!/usr/bin/env bash
# Stub curl: STUB_LOOKUP / STUB_DISPATCH are HTTP statuses, or "neterr" for a
# network failure (curl exit 7, status 000).
log="$STUB_LOG"
printf '%s\n' "curl $*" >> "$log"
out=""; method="GET"; args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[i]}" in
    -o|--output) out="${args[i+1]}" ;;
    -X|--request) method="${args[i+1]}" ;;
    -d|--data|--data-raw|--data-binary|--json) method="POST" ;;
  esac
done
url="${args[$((${#args[@]} - 1))]}"
[ -t 0 ] || cat > /dev/null
case "$url" in
  */actions/workflows/countersign.yml) kind=workflow; status="${STUB_WORKFLOW:-200}"; echo "WORKFLOW $url" >> "$log" ;;
  *dispatches*) kind=dispatch; status="${STUB_DISPATCH:-403}"; echo "DISPATCH $url" >> "$log" ;;
  *)            kind=lookup;   status="${STUB_LOOKUP:-404}";   echo "LOOKUP $url" >> "$log" ;;
esac
[ -n "$out" ] && [ "$out" != "/dev/null" ] && : > "$out"
if [ "$status" = neterr ]; then printf '000'; exit 7; fi
printf '%s' "$status"
STUB
cat > "$work/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "GH-CALLED $*" >> "$STUB_LOG"
exit 99
STUB
chmod +x "$work/bin/curl" "$work/bin/gh"

# run <lookup-status> <dispatch-status>: sets got, out, and fills $log.
run() {
  log="$work/calls.log"; : > "$log"
  got=0
  out="$(env PATH="$work/bin:$PATH" STUB_LOG="$log" STUB_LOOKUP="$1" STUB_DISPATCH="$2" \
    STUB_WORKFLOW="${STUB_WORKFLOW:-200}" ${API_URL:+"GITHUB_API_URL=$API_URL"} \
    GH_TOKEN="$token" GITHUB_REPOSITORY="example-owner/birdcage" \
    bash "$script" 2>&1)" || got=$?
}
ok()  { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; [ -n "${2:-}" ] && echo "$2" | sed 's/^/       /'; fail=$((fail + 1)); }
dispatches() { grep -c '^DISPATCH ' "$log" || true; }

# expect <name> <lookup> <dispatch> <want-exit> [needle]
expect() {
  local name="$1" lookup="$2" disp="$3" want="$4" needle="${5:-}"
  run "$lookup" "$disp"
  if [ "$got" = "$want" ] && { [ -z "$needle" ] || grep -qiF "$needle" <<<"$out"; }; then
    ok "$name"
  else
    bad "$name: exit $got (want $want${needle:+, needle '$needle'})" "$out"
  fi
}

[ -f "$script" ] || { echo "FAIL check-no-actions-write.sh does not exist"; fail=$((fail + 1)); }

expect "dispatch 403 passes"             404 403 0 "no Actions write"
expect "dispatch 404 passes"             404 404 0 "no Actions write"
expect "dispatch 422 fails: can dispatch" 404 422 1 "can dispatch"
expect "dispatch 200 fails, run may have started" 404 200 1 "may have started"
expect "dispatch 204 fails, run may have started" 404 204 1 "may have started"
expect "dispatch 401 is inconclusive"    404 401 2
expect "dispatch 500 is inconclusive"    404 500 2
expect "dispatch network failure is inconclusive" 404 neterr 2

# Inconclusive is never reported as a pass.
for s in 401 500 neterr; do
  run 404 "$s"
  if grep -qiF "no Actions write" <<<"$out"; then bad "dispatch $s must not print the pass message" "$out"; else ok "dispatch $s does not print the pass message"; fi
done

# A ref that exists is never dispatched against.
run 200 422
if [ "$got" != 0 ] && [ "$(dispatches)" = 0 ]; then ok "existing ref: non-zero and zero dispatch calls"; else bad "existing ref: exit $got, dispatch calls $(dispatches)" "$out"; fi
# A failed lookup is not "absent": nothing is dispatched.
for s in 500 401 neterr; do
  run "$s" 403
  if [ "$got" != 0 ] && [ "$(dispatches)" = 0 ]; then ok "lookup $s: non-zero and zero dispatch calls"; else bad "lookup $s: exit $got, dispatch calls $(dispatches)" "$out"; fi
done

# The dispatch is exactly one POST to the countersign workflow, on a ref
# that was looked up first and is not one of the real branches.
run 404 403
if [ "$(dispatches)" = 1 ] && grep -q '^DISPATCH .*repos/example-owner/birdcage/actions/workflows/countersign.yml/dispatches' "$log"; then ok "one dispatch, to countersign.yml of the named repo"; else bad "dispatch target wrong" "$(cat "$log")"; fi
if grep -q '^LOOKUP ' "$log" && ! grep -qE '^LOOKUP .*/(main|dev|preview|batch-a|batch-b)([?/]|$)' "$log"; then ok "lookup is of a ref other than a real branch"; else bad "lookup missing or of a real branch" "$(cat "$log")"; fi
first="$(grep -oE '^(LOOKUP|DISPATCH)' "$log" | head -1 || true)"
[ "$first" = LOOKUP ] && ok "lookup happens before dispatch" || bad "first lookup/dispatch call was $first, want LOOKUP"
look1="$(grep -m1 "^LOOKUP " "$log" || true)"
run 404 403; look2="$(grep -m1 "^LOOKUP " "$log" || true)"
[ "$look1" != "$look2" ] && ok "ref name is fresh on every run" || bad "same ref name twice: $look1"

# The workflow must exist (200) before anything else: a wrong repository or a
# renamed workflow answers 404 to the dispatch too, which must not be a pass.
for s in 404 403 500 neterr; do
  STUB_WORKFLOW="$s" run 404 403
  if [ "$got" = 2 ] && [ "$(dispatches)" = 0 ] && ! grep -qiF "no Actions write" <<<"$out"; then ok "workflow GET $s: exit 2, nothing dispatched, no pass message"; else bad "workflow GET $s: exit $got, dispatch calls $(dispatches)" "$out"; fi
done
STUB_WORKFLOW=200 run 404 403
first="$(grep -m1 -oE '^(WORKFLOW|LOOKUP|DISPATCH)' "$log" || true)"
dline="$(grep -n '^DISPATCH ' "$log" | head -1 | cut -d: -f1 || true)"; wline="$(grep -n '^WORKFLOW ' "$log" | head -1 | cut -d: -f1 || true)"
if [ -n "$wline" ] && [ -n "$dline" ] && [ "$wline" -lt "$dline" ]; then ok "workflow existence is checked before the dispatch"; else bad "workflow GET not made before dispatch" "$(cat "$log")"; fi
if grep -q '^WORKFLOW .*repos/example-owner/birdcage/actions/workflows/countersign.yml$' "$log"; then ok "workflow GET is of countersign.yml in the named repo"; else bad "workflow GET missing or wrong" "$(cat "$log")"; fi

# GITHUB_API_URL must be https://, or the token could go out in clear text.
for u in http://api.example.test ftp://api.example.test api.example.test "HTTP://api.example.test"; do
  API_URL="$u" run 404 403
  if [ "$got" = 2 ] && [ ! -s "$log" ]; then ok "GITHUB_API_URL '$u': exit 2 and no call made"; else bad "GITHUB_API_URL '$u': exit $got, calls: $(wc -l < "$log")" "$out"; fi
done
API_URL="https://ghe.example.test/api/v3" run 404 403
if [ "$got" = 0 ] && grep -q '^DISPATCH https://ghe.example.test/api/v3/' "$log"; then ok "an https:// GITHUB_API_URL is used"; else bad "https GITHUB_API_URL: exit $got" "$(cat "$log")"; fi
API_URL=""

# The credential: never in argv of any call, never printed, gh never used.
for s in 403 422 200 500; do
  run 404 "$s"
  if grep -qF "$token" "$log"; then bad "credential in the arguments of a call (dispatch $s)" "$(grep -F "$token" "$log" | sed "s/$token/<token>/")"; else ok "credential not in any call's arguments (dispatch $s)"; fi
  if grep -qF "$token" <<<"$out"; then bad "credential printed (dispatch $s)"; else ok "credential not printed (dispatch $s)"; fi
done
run 404 403
grep -q '^GH-CALLED' "$log" && bad "script called gh; contract is curl" || ok "no gh calls"

echo "check-no-actions-write: $pass passed, $fail failed"
[ "$fail" = 0 ]
