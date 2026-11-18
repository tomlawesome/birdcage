# shellcheck shell=sh
# first-admin.sh -- the sign-in every dashboard journey shares (#8,
# ADR-0016): create the first admin with the setup code birdcage logged,
# enrol an authenticator app, sign in with password and code, and mint
# the read API token the journeys carry. Along the way it checks the two
# things that can only be seen before an admin exists: the dashboard API
# answers 503 "setup required", and a wrong setup code is refused.
#
# Not run directly. scripts/e2e/stack.sh's sign_in feeds this file,
# after scripts/e2e/totp.sh, to `sh -s` inside the helper container (on
# the stack's network, /work and /tls mounted), so nothing here touches
# the host filesystem, which under a remote Docker socket is not the
# daemon's anyway:
#
#   sh -s -- <dashboard URL> <CA file inside the container>
#
# Input: /work/setup-code, the code from birdcage's log, removed as soon
# as it is read. Output: /work/dashboard-auth, the header line
# `Authorization: Bearer <token>` that journey.sh's DASHBOARD_AUTH hands
# curl with `-H @file`, so the token is never on a command line.
#
# Secrets: the password and the authenticator secret are made here and
# live only in this shell's variables; JSON bodies are built by jq from
# its environment (never its arguments) and piped to curl. Responses that
# carry a secret (the app secret, the recovery codes, the token) are
# never printed: a failure prints only the HTTP status and the problem
# document's title and detail, which gauntlet never puts a secret in.
# Everything this prints goes to stderr, because stack.sh's own stdout is
# what a caller evals.
set -eu

URL="$1"
CACERT="$2"
USERNAME=e2e-admin

say() { echo "sign-in: $*" >&2; }
die() { echo "sign-in: $*" >&2; exit 1; }

# problem prints the last response's problem title and detail, and
# nothing else from it.
problem() {
  jq -r '[.title // empty, .detail // empty] | join(": ")' /tmp/body 2>/dev/null || echo "(not a problem document)"
}

# The cookie jar is kept here rather than by curl: curl stores a cookie
# from a host name without a dot (the stack's container names, such as
# birdcage-e2e-birdcage) but never sends it back. A jar is a file of
# name=value lines; cookie_header turns it into a Cookie header file
# for `curl -H @file`, so no session value is ever on a command line.
cookie_header() { # cookie_header <jar>: the jar as a Cookie header in <jar>.h
  touch "$1"
  awk 'BEGIN { ORS = "" } NR == 1 { print "Cookie: " } NR > 1 { print "; " } { print } END { if (NR) print "\n" }' "$1" > "$1.h"
}
cookie_take() { # cookie_take <jar>: fold /tmp/headers' Set-Cookie lines into <jar>
  touch "$1"
  tr -d '\r' < /tmp/headers | awk -v jar="$1" '
    BEGIN { while ((getline line < jar) > 0) { n = substr(line, 1, index(line, "=") - 1); value[n] = line; order[++k] = n } }
    tolower($0) ~ /^set-cookie:/ {
      line = substr($0, 12); sub(/^[ \t]+/, "", line)
      count = split(line, part, ";"); eq = index(part[1], "=")
      n = substr(part[1], 1, eq - 1); v = substr(part[1], eq + 1); gone = (v == "")
      for (i = 2; i <= count; i++) { a = tolower(part[i]); gsub(/ /, "", a); if (a ~ /^max-age=/ && substr(a, 9) + 0 <= 0) gone = 1 }
      if (!(n in value)) order[++k] = n
      value[n] = gone ? "" : n "=" v
    }
    END { for (i = 1; i <= k; i++) if (value[order[i]] != "" && !printed[order[i]]++) print value[order[i]] }
  ' > "$1.new"
  mv "$1.new" "$1"
}

# get <path> <jar> and post <path> <jar> (JSON body on stdin) leave the
# body in /tmp/body, keep any cookie the answer sets, and print the
# status. Every POST carries X-Requested-With, gauntlet's CSRF header.
get() {
  cookie_header "$2"
  curl -sS -o /tmp/body -D /tmp/headers -w '%{http_code}' --cacert "$CACERT" -H "@$2.h" "$URL$1" || return 1
  cookie_take "$2"
}
post() {
  cookie_header "$2"
  curl -sS -o /tmp/body -D /tmp/headers -w '%{http_code}' --cacert "$CACERT" -H "@$2.h" \
    -H 'X-Requested-With: birdcage' -H 'Content-Type: application/json' \
    --data-binary @- "$URL$1" || return 1
  cookie_take "$2"
}

# expect <status> <what> fails unless the last call answered <status>.
expect() {
  [ "$status" = "$1" ] || die "$2: answered $status, want $1 -- $(problem)"
}

[ -s /work/setup-code ] || die "no setup code was handed over in /work/setup-code"
SETUP_CODE="$(cat /work/setup-code)"
rm -f /work/setup-code

# 1. Before the first admin, the dashboard API answers 503 setup
#    required -- live data is not readable by whoever arrives first.
status="$(get /api/alerts /tmp/anon.jar)"
expect 503 "GET /api/alerts before any admin exists"
jq -e '.title == "Setup required"' /tmp/body >/dev/null \
  || die "GET /api/alerts answered 503 but not \"setup required\": $(problem)"
say "ok   before the first admin, GET /api/alerts answers 503 setup required"

# 2. A wrong setup code is refused, and creates nothing.
status="$(USERNAME="$USERNAME" jq -nc '{username: env.USERNAME, password: "a-password-never-used", setupCode: "not-the-setup-code"}' \
  | post /api/auth/register /tmp/anon.jar)"
expect 401 "POST /api/auth/register with a wrong setup code"
status="$(get /api/auth/session /tmp/anon.jar)"
expect 200 "GET /api/auth/session after the refused code"
jq -e '.setupRequired == true' /tmp/body >/dev/null \
  || die "a wrong setup code was refused but setup is no longer required"
say "ok   a wrong setup code is refused (401) and no account exists"

# 3. The first admin, with the real code. Random per run, never printed.
PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -d '/+=\n')"
[ "${#PASSWORD}" -ge 24 ] || die "could not make a password"
status="$(USERNAME="$USERNAME" PW="$PASSWORD" CODE="$SETUP_CODE" \
  jq -nc '{username: env.USERNAME, password: env.PW, setupCode: env.CODE}' \
  | post /api/auth/register /tmp/setup.jar)"
SETUP_CODE=''
expect 201 "POST /api/auth/register with the logged setup code"
say "ok   created the first admin with the logged setup code"

# 4. Password accounts must hold a second factor before they reach
#    anything: enrol an authenticator app, confirm a code from it, and
#    confirm the recovery codes it answers with were saved.
status="$(PW="$PASSWORD" jq -nc '{password: env.PW}' | post /api/auth/totp/enrol /tmp/setup.jar)"
expect 200 "POST /api/auth/totp/enrol"
TOTP_SECRET="$(jq -r '.secret // empty' /tmp/body)"
rm -f /tmp/body
[ -n "$TOTP_SECRET" ] || die "POST /api/auth/totp/enrol answered no secret"
CODE="$(totp_code "$TOTP_SECRET" "$(($(date +%s) / 30))")" || die "could not compute an authenticator code"
status="$(CODE="$CODE" jq -nc '{code: env.CODE}' | post /api/auth/totp/confirm /tmp/setup.jar)"
expect 200 "POST /api/auth/totp/confirm"
held="$(jq -r '.pendingConfirmation == true and (.recoveryCodes | length) > 0' /tmp/body)"
rm -f /tmp/body
[ "$held" = true ] || die "POST /api/auth/totp/confirm did not hold the app with recovery codes"
status="$(printf '{}' | post /api/auth/recovery-codes/confirm /tmp/setup.jar)"
expect 200 "POST /api/auth/recovery-codes/confirm"
say "ok   enrolled an authenticator app and confirmed its recovery codes"

# 5. Sign in from scratch, the way a person does: password, then a code.
#    The enrolment spent this 30-second step's code, so this uses the
#    next step's, which gauntlet accepts (one step either side) and has
#    not seen.
status="$(USERNAME="$USERNAME" PW="$PASSWORD" jq -nc '{username: env.USERNAME, password: env.PW}' \
  | post /api/auth/login /tmp/login.jar)"
expect 200 "POST /api/auth/login"
jq -e '.secondFactor | index("totp")' /tmp/body >/dev/null \
  || die "POST /api/auth/login did not ask for the authenticator code"
CODE="$(totp_code "$TOTP_SECRET" "$(($(date +%s) / 30 + 1))")" || die "could not compute an authenticator code"
status="$(CODE="$CODE" jq -nc '{code: env.CODE}' | post /api/auth/login/factor /tmp/login.jar)"
expect 200 "POST /api/auth/login/factor"
TOTP_SECRET='' CODE=''
status="$(get /api/auth/session /tmp/login.jar)"
expect 200 "GET /api/auth/session after signing in"
jq -e '.authenticated == true and .role == "admin" and .mustEnrolSecondFactor == false' /tmp/body >/dev/null \
  || die "signed in, but the session is not a usable admin one"
say "ok   signed in with password and authenticator code"

# 6. The read API token the journeys carry. The dashboard API is
#    read-only (internal/api's dashboardRouteSpecs, all GET), so a read
#    token reaches every route a journey calls; minting it asks for the
#    admin's password again.
status="$(PW="$PASSWORD" jq -nc '{name: "e2e-journeys", password: env.PW}' | post /api/tokens /tmp/login.jar)"
PASSWORD=''
expect 201 "POST /api/tokens"
TOKEN="$(jq -r 'select(.kind == "api") | .value // empty' /tmp/body)"
rm -f /tmp/body
[ -n "$TOKEN" ] || die "POST /api/tokens answered no read API token"
(umask 077 && printf 'Authorization: Bearer %s\n' "$TOKEN" > /work/dashboard-auth)
TOKEN=''
say "ok   minted a read API token for the journeys (kept in the work volume, never printed)"
