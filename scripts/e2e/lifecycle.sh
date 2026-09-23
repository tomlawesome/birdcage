#!/usr/bin/env bash
# lifecycle.sh -- issue #78 journey A: the canary's life after enrolment --
# heartbeat, silence, restart, revocation, rotation -- proved against the
# real stack rather than against internal/store's unit tests.
#
# Runs after enrol-and-hit.sh and refusals.sh in the same job, on the
# canary those scripts already enrolled and hit: this file never enrols
# its own. It leaves that canary's live credential working when it
# finishes, because surface.sh (issue #78 journey B) runs after this file
# in the same job and needs to cause a hit on the same canary for its SSE
# check -- see the revocation step below, which mints and revokes a
# throwaway token rather than the one the running agent actually uses.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/enrol-and-hit.sh
#   scripts/e2e/refusals.sh
#   scripts/e2e/lifecycle.sh
set -eu

. "$(dirname "$0")/journey.sh"

step "GET /api/canaries shows the canary ok with a recent heartbeat"
canary_json="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' | jq -c --arg id '$E2E_CANARY_ID' '.canaries[] | select(.id == \$id)'")" \
  || fail "GET /api/canaries did not run" "$E2E_BIRDCAGE"
case "$canary_json" in
  *'"status":"ok"'*) ;;
  *) fail "canary $E2E_CANARY_ID is not ok: $canary_json" "$E2E_BIRDCAGE" ;;
esac
recent="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' | jq -r --arg id '$E2E_CANARY_ID' '(.canaries[] | select(.id == \$id) | .last_heartbeat_at) as \$hb | if \$hb == null then \"absent\" elif (\$hb | test(\"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\")) then \"present\" else \"malformed\" end'")" \
  || fail "could not read last_heartbeat_at" "$E2E_BIRDCAGE"
case "$recent" in
  present) ;;
  absent) fail "last_heartbeat_at is null: $canary_json" "$E2E_BIRDCAGE" ;;
  *) fail "last_heartbeat_at did not look like a timestamp: $canary_json" "$E2E_BIRDCAGE" ;;
esac
# "recent" follows from status == "ok" (already checked above) rather
# than a second, independent age computation here: applyStatus
# (internal/store/canary.go) derives ok/silent purely by comparing now to
# this same last_heartbeat_at against silenceThresholdMultiple x
# heartbeat_interval_s, so a stale beat would already have read silent.
ok "canary $E2E_CANARY_ID: $canary_json (status ok with a real, non-null last_heartbeat_at)"

# Baseline, captured before anything below restarts either container, so
# the next steps can prove nothing new was created and nothing on-disk
# changed by comparing against these.
sessions_before="$("$E2E_STACK" birdcage canary enrol --status | grep -Fc "$(printf '\tname=%s\tlane=' "$E2E_CANARY_NAME")")" \
  || fail "could not count enrolment sessions named $E2E_CANARY_NAME"
canaries_before="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' | jq '.canaries | length'")" \
  || fail "could not count canaries"
serial_before="$(helper 'openssl x509 -in /state/client.pem -noout -serial')" \
  || fail "could not read the client certificate serial" "$E2E_CANARY"
old_token="$(helper 'cat /state/token')" \
  || fail "could not read the canary's current bearer token" "$E2E_CANARY"

step "silent once the heartbeat interval elapses, and ok again once the agent is back"
# There is no enrolment flag, environment variable or agent setting that
# shortens the heartbeat cadence (cmd/mockingbird/heartbeat.go's interval
# is a hard-coded 60s const -- "no channel delivers it to the agent
# today") or the enrolment session's own interval (cmd/birdcage/canary.go
# always mints with store.DefaultHeartbeatIntervalS). What applyStatus
# (internal/store/canary.go) actually reads is the canaries row's own
# heartbeat_interval_s column, so the smallest allowed way to make this
# wait seconds rather than minutes is to set that column directly, the
# same value a future short-interval enrolment flag would eventually
# write to it -- not a fake status, a real one computed by the product's
# own applyStatus against a real elapsed silence.
#
# `stack.sh query` cannot be reused for this write on SQLite: its own
# comment says why it copies the file first ("the database is open in
# the birdcage container and sqlite3 would otherwise take a lock on a
# live file") -- which also means a write through it lands on the copy
# and never reaches the live database at all (confirmed by trying it: the
# column read back unchanged). On Postgres, by contrast, `query` already
# runs directly against the live server, so this only needs a
# SQLite-specific path -- a one-off container with the same data volume
# mounted read-write instead of stack.sh helper()'s hard-coded :ro.
# SQLite's own file locking makes one short UPDATE safe to run alongside
# birdcage's own open connection.
set_heartbeat_interval() {
  if [ "$E2E_BACKEND" = postgres ] || [ -n "${E2E_DATABASE_URL:-}" ]; then
    "$E2E_STACK" query "update canaries set heartbeat_interval_s = $1 where id = '$E2E_CANARY_ID'" >/dev/null
  else
    docker run --rm --volume "$E2E_PREFIX-data:/data" "$E2E_PREFIX-helper" \
      sh -c "sqlite3 /data/birdcage.db \"update canaries set heartbeat_interval_s = $1 where id = '$E2E_CANARY_ID'\"" >/dev/null
  fi
}
set_heartbeat_interval 1 || fail "could not shorten the canary's heartbeat interval"

docker stop "$E2E_CANARY" >/dev/null || fail "could not stop $E2E_CANARY" "$E2E_CANARY"
poll 30 helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' | jq -e --arg id '$E2E_CANARY_ID' '.canaries[] | select(.id == \$id) | .status == \"silent\"'" \
  || fail "the canary never read silent after $((3 * 1))s of silence (30 attempts)" "$E2E_BIRDCAGE"

docker start "$E2E_CANARY" >/dev/null || fail "could not start $E2E_CANARY again" "$E2E_CANARY"
poll 60 helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' | jq -e --arg id '$E2E_CANARY_ID' '.canaries[] | select(.id == \$id) | .status == \"ok\"'" \
  || fail "the canary never returned to ok after restarting" "$E2E_BIRDCAGE" "$E2E_CANARY"
ok "silent while stopped, ok again once restarted"

# Restore the real default now that the transition above is proved --
# otherwise the shortened 3s threshold would read every gap between the
# agent's real 60s heartbeats as silent for the rest of this job,
# including surface.sh's later checks.
set_heartbeat_interval 60 || fail "could not restore the canary's heartbeat interval"

step "the restart came back on stored credentials, not a re-enrolment"
serial_after="$(helper 'openssl x509 -in /state/client.pem -noout -serial')" \
  || fail "could not read the client certificate serial after restart" "$E2E_CANARY"
[ "$serial_after" = "$serial_before" ] \
  || fail "the client certificate serial changed across the restart ($serial_before -> $serial_after), so this was a re-enrolment, not a resume" "$E2E_CANARY"
sessions_after="$("$E2E_STACK" birdcage canary enrol --status | grep -Fc "$(printf '\tname=%s\tlane=' "$E2E_CANARY_NAME")")" \
  || fail "could not count enrolment sessions named $E2E_CANARY_NAME after restart"
[ "$sessions_after" = "$sessions_before" ] \
  || fail "the number of enrolment sessions named $E2E_CANARY_NAME changed ($sessions_before -> $sessions_after): a new session was minted" "$E2E_BIRDCAGE"
canaries_after="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' | jq '.canaries | length'")" \
  || fail "could not count canaries after restart" "$E2E_BIRDCAGE"
[ "$canaries_after" = "$canaries_before" ] \
  || fail "the number of canaries changed ($canaries_before -> $canaries_after): a new canary was registered" "$E2E_BIRDCAGE"
ok "same client certificate (serial $serial_after), no new enrolment session, no new canary"

step "a hit while birdcage was down is queued and arrives once it is back"
ftp_before="$("$E2E_STACK" query "select count(*) from alerts where instance_id = '$E2E_CANARY_ID' and service = 'ftp'")" \
  || fail "could not count existing ftp alerts"
docker stop "$E2E_BIRDCAGE" >/dev/null || fail "could not stop $E2E_BIRDCAGE" "$E2E_BIRDCAGE"
# OpenCanary and the agent's local queue (internal/agent/queue) are both
# local to the canary container and keep running with birdcage down.
# cmd/mockingbird/sender.go retries a failed push once a minute
# (senderRetryInterval, "#48: retries once a minute until birdcage
# acknowledges") -- not the 250ms senderIdleInterval, which only governs
# how often an *empty* queue is checked -- so the wait below is bounded
# generously past that minute rather than at it.
helper "{ printf 'USER x\\r\\nPASS y\\r\\nQUIT\\r\\n'; sleep 2; } | nc -w 5 $E2E_CANARY 21" >/dev/null \
  || fail "the FTP login attempt could not be sent to $E2E_CANARY:21 while birdcage was down" "$E2E_CANARY"
docker start "$E2E_BIRDCAGE" >/dev/null || fail "could not start $E2E_BIRDCAGE again" "$E2E_BIRDCAGE"
poll 60 helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=ftp'" \
  || fail "the dashboard never answered GET /api/alerts again after restarting birdcage" "$E2E_BIRDCAGE"
# A plain poll (journey.sh) only checks exit status, and `stack.sh query`
# exits 0 for any successful SELECT regardless of the count it returns --
# this needs the count itself, so it polls by hand instead.
ftp_after=""
attempt=0
while [ "$attempt" -lt 90 ]; do
  attempt=$((attempt + 1))
  ftp_after="$("$E2E_STACK" query "select count(*) from alerts where instance_id = '$E2E_CANARY_ID' and service = 'ftp'")" \
    || fail "could not count ftp alerts after restarting birdcage"
  [ "$ftp_after" -gt "$ftp_before" ] && break
  sleep 1
done
[ -n "$ftp_after" ] && [ "$ftp_after" -gt "$ftp_before" ] \
  || fail "the queued hit never arrived after 90 attempts ($ftp_before -> ${ftp_after:-$ftp_before} ftp alerts)" "$E2E_CANARY" "$E2E_BIRDCAGE"
ok "the queued hit was delivered once birdcage came back ($ftp_before -> $ftp_after ftp alerts)"

step "rotation: the restart's automatic rotation mints a new token, and the old one stops working"
# cmd/mockingbird/rotate.go rotates once immediately on every process
# start ("rotate immediately on start"), then every 24h -- so the
# container restart above already triggered one; this proves it rather
# than triggering a second. Revocation of the old token only completes
# on the new token's first use (internal/ingest/auth.go's
# completeRotation), audited as ingest.token_rotated -- poll for that
# rather than for the token file changing, so this only asserts once the
# server side has actually finished the swap.
# A plain poll (journey.sh) only checks exit status, and `stack.sh query`
# exits 0 for any successful SELECT regardless of the count it returns --
# this needs the count itself, so it polls by hand instead.
rotated=0
attempt=0
while [ "$attempt" -lt 90 ]; do
  attempt=$((attempt + 1))
  rotated="$("$E2E_STACK" query "select count(*) from audit_log where action = 'ingest.token_rotated' and target = '$E2E_CANARY_ID'")" \
    || fail "could not read the audit log for ingest.token_rotated"
  [ "$rotated" -gt 0 ] && break
  sleep 1
done
[ "$rotated" -gt 0 ] \
  || fail "no ingest.token_rotated audit entry appeared after 90 attempts -- the restart's automatic rotation never completed" "$E2E_CANARY" "$E2E_BIRDCAGE"
new_token="$(helper 'cat /state/token')" || fail "could not read the canary's token after rotation" "$E2E_CANARY"
[ "$new_token" != "$old_token" ] || fail "the token on disk did not change across the restart -- rotation did not run"

old_attempt="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /state/client.pem --key /state/client-key.pem \
  -H \"Authorization: Bearer $old_token\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "the old-token request could not be sent"
case "$old_attempt" in
  *http=401*'"error":"unauthorized"'*|*'"error":"unauthorized"'*http=401*) ;;
  *) fail "the pre-rotation token was not refused with 401 unauthorized: $old_attempt" "$E2E_BIRDCAGE" ;;
esac
new_attempt="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /state/client.pem --key /state/client-key.pem \
  -H \"Authorization: Bearer $new_token\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "the new-token request could not be sent"
case "$new_attempt" in
  *http=400*'at least one event'*|*'at least one event'*http=400*) ;;
  *) fail "the rotated token did not authenticate (expected 400 from the batch handler): $new_attempt" "$E2E_BIRDCAGE" ;;
esac
ok "the pre-rotation token is refused (401 unauthorized); the rotated token authenticates"

step "revocation: birdcage canary revoke refuses the token's next request, and is audited"
# A throwaway token, minted and revoked here, rather than the one
# $E2E_CANARY is actually running on: surface.sh runs after this journey
# in the same job and needs this canary's real credential still working.
mint_output="$("$E2E_STACK" birdcage canary mint "$E2E_CANARY_ID")" \
  || fail "birdcage canary mint did not run"
mint_token_id="$(printf '%s\n' "$mint_output" | sed -n 's/^minted token \([^ ]*\) for canary .*$/\1/p')"
mint_raw="$(printf '%s\n' "$mint_output" | sed -n 's/^token (shown once, record it now): //p')"
[ -n "$mint_token_id" ] && [ -n "$mint_raw" ] \
  || fail "could not parse a token id and raw token out of birdcage canary mint's output"

alerts_before_revoke="$("$E2E_STACK" query "select count(*) from alerts where instance_id = '$E2E_CANARY_ID'")" \
  || fail "could not count alerts before revocation"

revoke_output="$("$E2E_STACK" birdcage canary revoke "$mint_token_id")" \
  || fail "birdcage canary revoke $mint_token_id did not run"
case "$revoke_output" in
  *"revoked token $mint_token_id for canary $E2E_CANARY_ID"*) ;;
  *) fail "revoke did not confirm the expected token/canary: $revoke_output" ;;
esac

revoked_attempt="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
  --cert /state/client.pem --key /state/client-key.pem \
  -H \"Authorization: Bearer $mint_raw\" \
  -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
  || fail "the revoked-token request could not be sent"
case "$revoked_attempt" in
  *http=401*'"error":"unauthorized"'*|*'"error":"unauthorized"'*http=401*) ;;
  *) fail "the revoked token was not refused with 401 unauthorized: $revoked_attempt" "$E2E_BIRDCAGE" ;;
esac

alerts_after_revoke="$("$E2E_STACK" query "select count(*) from alerts where instance_id = '$E2E_CANARY_ID'")" \
  || fail "could not count alerts after revocation"
[ "$alerts_after_revoke" = "$alerts_before_revoke" ] \
  || fail "the alerts count changed across the refused request ($alerts_before_revoke -> $alerts_after_revoke): something was stored despite the 401"

audit="$("$E2E_STACK" query "select reason from audit_log where action = 'canary.token_revoked' and target = '$E2E_CANARY_ID' order by id desc limit 1")" \
  || fail "could not read the audit log for the revocation"
case "$audit" in
  *"revoked via CLI"*) ok "revoked, refused with 401, nothing stored, audited: $audit" ;;
  *) fail "no canary.token_revoked entry naming $E2E_CANARY_ID; got: ${audit:-<nothing>}" ;;
esac

finish
