#!/usr/bin/env bash
# surface.sh -- issue #78 journey B: every dashboard API route and every
# CLI command, run against the live stack and checked on what they
# actually answered, not just their exit status.
#
# Runs after enrol-and-hit.sh, refusals.sh and lifecycle.sh in the same
# job, on the canary those scripts already enrolled and hit -- this file
# never enrols its own honeypot. lifecycle.sh deliberately leaves that
# canary's real credential working (see its own header) so the SSE check
# below can cause a live hit.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/enrol-and-hit.sh
#   scripts/e2e/refusals.sh
#   scripts/e2e/lifecycle.sh
#   scripts/e2e/surface.sh
set -eu

. "$(dirname "$0")/journey.sh"

# api_route checks GET path answers 200 with a body matching jq_filter (a
# boolean expression over the parsed JSON) -- one step, one route, so a
# failure names which route and what it actually returned. The status
# check, the body fetch and the jq filter all run inside one helper()
# call, on the helper container's own /tmp: the response body never
# round-trips through this script's own shell, which would mean
# re-embedding arbitrary JSON (quotes, backslashes) into a second remote
# shell command.
api_route() {
  local path="$1" jq_filter="$2"
  step "GET $path answers 200 with the documented shape"
  if helper "
set -eu
code=\$(curl -sS -o /tmp/resp.json -w '%{http_code}' --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL$path')
[ \"\$code\" = 200 ] || exit 1
jq -e '$jq_filter' /tmp/resp.json >/dev/null
"; then
    local summary
    summary="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL$path' 2>/dev/null | head -c 300")" \
      || summary="(could not re-fetch the body for display)"
    ok "GET $path: $summary"
  else
    local detail
    detail="$(helper "curl -sS -w ' http=%{http_code}' --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL$path'")" \
      || detail="(unreachable)"
    fail "GET $path did not answer 200 with the documented shape ($jq_filter): $detail" "$E2E_BIRDCAGE"
  fi
}

api_route /api/alerts '(.alerts | type == "array") and has("next_before")'
api_route /api/instances '.instances | type == "array"'
api_route /api/stats 'has("total") and has("last_24h") and has("distinct_sources") and has("instances")'
api_route /api/canaries '.canaries | type == "array"'
api_route /api/visitors '(.visitors | type == "array") and has("next_before")'
api_route /api/trace 'has("now") and has("range") and (.canaries | type == "array") and has("last_hit")'
api_route /api/history 'has("range") and has("since") and has("until") and (.periods | type == "array") and (.summary | type == "array")'
api_route /api/mail 'has("configured")'

step "GET /api/stream delivers a real-time event for a live hit"
# The stream's own payload deliberately carries no alert content at all
# (internal/stream/stream.go: PublishAlert "carries NO alert content...
# a contentless notification cannot leak a hit to a stream that outlives
# the session that opened it") -- {"type":"alert"} is the whole of what
# any subscriber ever receives, by design. So this proves delivery -- the
# stream fires for a real hit within the connection's lifetime -- rather
# than the alert's own id appearing in it, which the product never sends
# over this channel; see the report for this journey's named gap.
"$E2E_STACK" helper "curl -sS --max-time 15 --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/stream' > /work/stream-output.txt 2>&1" &
stream_pid=$!
sleep 2
helper "{ printf 'USER x\\r\\nPASS y\\r\\nQUIT\\r\\n'; sleep 2; } | nc -w 5 $E2E_CANARY 21" >/dev/null \
  || fail "the FTP login attempt could not be sent to $E2E_CANARY:21" "$E2E_CANARY"
wait "$stream_pid" || true # curl exits non-zero on its own --max-time timeout; expected
stream_output="$(helper 'cat /work/stream-output.txt')" || fail "could not read the captured stream output"
case "$stream_output" in
  *'data: {"type":"alert"}'*) ok "the stream delivered an alert-stored event: $(printf '%s' "$stream_output" | tr -s '\r\n' ' ')" ;;
  *) fail "no alert-stored event appeared in the stream within 15s: $stream_output" "$E2E_BIRDCAGE" ;;
esac

step "birdcage canary list's output is asserted"
list="$("$E2E_STACK" birdcage canary list)" || fail "birdcage canary list did not run"
case "$list" in
  *"canary=$E2E_CANARY_ID"*"active"*) ok "canary $E2E_CANARY_ID holds an active token: $(printf '%s' "$list" | grep "canary=$E2E_CANARY_ID")" ;;
  *) fail "canary $E2E_CANARY_ID does not show an active token: $list" ;;
esac

step "birdcage canary mint's output is asserted"
mint_output="$("$E2E_STACK" birdcage canary mint "$E2E_CANARY_ID")" || fail "birdcage canary mint did not run"
case "$mint_output" in
  *"minted token "*" for canary $E2E_CANARY_ID"*) ;;
  *) fail "mint did not confirm the expected canary: $mint_output" ;;
esac
mint_token_id="$(printf '%s\n' "$mint_output" | sed -n 's/^minted token \([^ ]*\) for canary .*$/\1/p')"
case "$mint_output" in
  *"token (shown once, record it now): "*) ok "minted token $mint_token_id, raw token shown once" ;;
  *) fail "mint did not print the raw token exactly once: $mint_output" ;;
esac

step "birdcage canary revoke's output is asserted"
revoke_output="$("$E2E_STACK" birdcage canary revoke "$mint_token_id")" || fail "birdcage canary revoke did not run"
case "$revoke_output" in
  *"revoked token $mint_token_id for canary $E2E_CANARY_ID"*) ok "$revoke_output" ;;
  *) fail "revoke did not confirm the expected token/canary: $revoke_output" ;;
esac

step "birdcage canary enrol's printed instructions are asserted"
surface_name="$E2E_CANARY_NAME-surface"
enrol_output="$("$E2E_STACK" birdcage canary enrol --name "$surface_name" --lane "$E2E_CANARY_LANE")" \
  || fail "birdcage canary enrol did not run"
case "$enrol_output" in
  *"docker run -d --name mockingbird"*"MOCKINGBIRD_DEPLOY_TOKEN="*)
    ok "printed a docker run command carrying a deploy token" ;;
  *) fail "enrol did not print the expected docker run command: $(printf '%s' "$enrol_output" | sed 's/MOCKINGBIRD_DEPLOY_TOKEN=[^ ]*/MOCKINGBIRD_DEPLOY_TOKEN=<redacted>/')" ;;
esac

step "birdcage canary enrol --status's output is asserted"
status_output="$("$E2E_STACK" birdcage canary enrol --status)" || fail "birdcage canary enrol --status did not run"
case "$status_output" in
  *"$(printf '\tname=%s\tlane=%s\tkind=honeypot\tstate=minted' "$surface_name" "$E2E_CANARY_LANE")"*)
    ok "the session just minted for $surface_name shows state=minted" ;;
  *) fail "no freshly-minted session named $surface_name in --status: $status_output" ;;
esac

step "birdcage settings list's output is asserted"
settings_list="$("$E2E_STACK" birdcage settings list)" || fail "birdcage settings list did not run"
for key in selftest_enabled selftest_schedule selftest_use_rotation_schedule rotation_schedule \
           admin_approval_address release_address history_last_tick; do
  case "$settings_list" in
    *"$key="*) ;;
    *) fail "settings list is missing $key: $settings_list" ;;
  esac
done
ok "settings list carries all seven known keys"

step "birdcage settings get/set roundtrips a value and puts the original back"
original="$("$E2E_STACK" birdcage settings get selftest_schedule)" || fail "settings get selftest_schedule did not run"
new_value="03:00"
[ "$original" != "$new_value" ] || new_value="04:00" # guaranteed different from whatever is already set
set_output="$("$E2E_STACK" birdcage settings set selftest_schedule "$new_value")" || fail "settings set did not run"
case "$set_output" in
  *"selftest_schedule=$new_value"*) ;;
  *) fail "settings set did not echo the new value: $set_output" ;;
esac
readback="$("$E2E_STACK" birdcage settings get selftest_schedule)" || fail "settings get (readback) did not run"
[ "$readback" = "$new_value" ] || fail "settings get after set returned $readback, want $new_value"
restore_output="$("$E2E_STACK" birdcage settings set selftest_schedule "$original")" || fail "settings set (restore) did not run"
case "$restore_output" in
  *"selftest_schedule=$original"*) ;;
  *) fail "restoring the original value did not echo it back: $restore_output" ;;
esac
restored="$("$E2E_STACK" birdcage settings get selftest_schedule)" || fail "settings get (final readback) did not run"
[ "$restored" = "$original" ] || fail "the original value was not restored: got $restored, want $original"
ok "selftest_schedule: $original -> $new_value -> $original"

step "birdcage approval check's output is asserted"
# A real signature cannot be a fixture (cmd/birdcage/approval.go's own
# doc comment); what is real and checkable without one is the
# door-shutting first check every raw message goes through -- no
# approval-request token in the Subject at all -- run against the actual
# binary rather than assumed from reading the source.
# `docker cp` cannot reach the image's writable /tmp tmpfs: it refuses
# outright against this container ("container rootfs is marked
# read-only", confirmed by trying it) because start_birdcage runs it
# --read-only, and docker cp needs write access to the root layer itself
# even when the destination path is a separate writable mount. The image
# is also distroless (no shell for `docker exec ... sh -c` either), so
# the one writable thing this container actually has that a file can be
# put into from outside is its real, read-write data volume
# ($DATA_VOL:/var/lib/birdcage) -- the same route lifecycle.sh's
# heartbeat-interval step uses for the same class of problem, a one-off
# container mounting that volume read-write rather than through
# stack.sh's own helper(), which mounts it :ro.
printf 'Date: %s\r\nFrom: someone@example.invalid\r\nTo: e2e-admin@e2e.invalid\r\nSubject: hello\r\n\r\nbody\r\n' "$(date -R)" \
  | docker run --rm --interactive --volume "$E2E_PREFIX-data:/data" "$E2E_PREFIX-helper" sh -c \
    'cat > /data/e2e-approval-check.eml && chown 1000:1000 /data/e2e-approval-check.eml && chmod 644 /data/e2e-approval-check.eml' \
  || fail "could not write the .eml fixture into $E2E_BIRDCAGE's data volume"
check_output="$("$E2E_STACK" birdcage approval check /var/lib/birdcage/e2e-approval-check.eml)" \
  || fail "birdcage approval check did not run: $check_output"
case "$check_output" in
  *"the subject carries no"*) ok "checked a token-less subject: $(printf '%s' "$check_output" | head -1)" ;;
  *) fail "approval check did not report the expected no-token result: $check_output" ;;
esac

finish
