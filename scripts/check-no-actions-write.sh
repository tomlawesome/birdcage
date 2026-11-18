#!/usr/bin/env bash
# Does a GitHub credential have Actions write? Answers without ever starting
# a run (#169, item A).
#
# The countersignature is worth something only if no credential on the
# runner host can start countersign.yml. This asks GitHub to dispatch it
# against a ref that does not exist: a credential without Actions write is
# refused (403, or 404 when it cannot see the workflow at all) before the
# ref is even looked at; one with Actions write gets as far as "no such
# ref" (422). The ref name is fresh and random every run and is confirmed
# absent first, so a dispatch that unexpectedly succeeds has nothing real
# to run on -- and if the lookup cannot prove absence, nothing is sent.
#
# Input, from the environment only (never an argument, so it stays out of
# process listings and shell history):
#   GH_TOKEN           the credential to check
#   GITHUB_REPOSITORY  owner/name of the repository holding countersign.yml
#   GITHUB_API_URL     optional, default https://api.github.com
#
# Exit 0: no Actions write (dispatch answered 403 or 404).
# Exit 1: the credential can dispatch (422), or a run may have started (2xx).
# Exit 2: inconclusive -- bad input, the ref lookup failed or found the ref,
#         a network failure, or any other answer (401, 5xx, ...). Never a pass.
#
# Run it after any change to a GitHub credential or its token scopes.
set -euo pipefail

die() { echo "check-no-actions-write: $*" >&2; exit 2; }

[ -n "${GH_TOKEN:-}" ] || die "GH_TOKEN is not set (the credential to check)"
repo="${GITHUB_REPOSITORY:-}"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "GITHUB_REPOSITORY must be owner/name"
api="${GITHUB_API_URL:-https://api.github.com}"
command -v curl >/dev/null || die "curl is required"

# A ref that no branch here would ever be called: prefix, time and 128
# random bits.
rand="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
[ "${#rand}" = 32 ] || die "could not read random bytes"
ref="no-actions-write-probe-$(date -u +%Y%m%d%H%M%S)-$rand"

# call <method> <url> [json-body]: prints the HTTP status ("000" when no
# answer). The Authorization header is read from stdin (`-H @-`), so the
# credential is never in curl's argv.
call() {
  local method="$1" url="$2" body="${3:-}" status rc=0
  local args=(-sS -o /dev/null -w '%{http_code}' --max-time 30
    -H 'Accept: application/vnd.github+json'
    -H 'X-GitHub-Api-Version: 2022-11-28'
    -H @- -X "$method")
  [ -n "$body" ] && args+=(--data-raw "$body")
  status="$(printf 'Authorization: Bearer %s\n' "$GH_TOKEN" | curl "${args[@]}" "$url" 2>/dev/null)" || rc=$?
  [ "$rc" = 0 ] || status=000
  [[ "$status" =~ ^[0-9]{3}$ ]] || status=000
  printf '%s' "$status"
}

# 1. The ref must be provably absent. Branches and tags share the name
#    space a dispatch resolves, so both are looked up.
for kind in heads tags; do
  status="$(call GET "$api/repos/$repo/git/ref/$kind/$ref")"
  case "$status" in
    404) ;;
    2??) die "ref $kind/$ref exists; refusing to dispatch against it" ;;
    *)   die "inconclusive: looking up $kind/$ref answered HTTP $status, so its absence is unproven; nothing was dispatched" ;;
  esac
done

# 2. The dispatch.
status="$(call POST "$api/repos/$repo/actions/workflows/countersign.yml/dispatches" "{\"ref\":\"$ref\"}")"
case "$status" in
  403|404)
    echo "pass: no Actions write -- dispatching countersign.yml on $repo answered HTTP $status"
    exit 0 ;;
  422)
    echo "FAIL: this credential can dispatch workflows on $repo (HTTP 422: it got as far as the missing ref $ref). Remove its Actions write."
    exit 1 ;;
  2??)
    echo "FAIL: dispatch answered HTTP $status -- a run may have started on ref $ref of $repo. Check the Actions tab, cancel it, and remove this credential's Actions write."
    exit 1 ;;
  *)
    echo "inconclusive: dispatch answered HTTP $status; this is not a pass"
    exit 2 ;;
esac
