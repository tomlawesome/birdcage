#!/usr/bin/env bash
# upgrade.sh -- issue #54: an agent running an older release than
# birdcage is shown as agent_out_of_date, its canary page prints an
# upgrade command, and running that command on the canary host really
# brings the same canary back on its stored credential -- no deploy
# token, no re-enrolment -- until the state clears.
#
# Runs in e2e:enrol-and-hit (both engines) on the canary stack.sh
# enrolled, after refusals.sh and before lifecycle.sh: lifecycle.sh
# presents a rotated-out token on purpose, which holds token_conflict
# for 24 hours (internal/store's tokenConflictQuietPeriod), so the canary
# never reads ok again after it -- and surface.sh ends by revoking the
# canary outright. This journey replaces the canary's containers and
# hands the same canary back ok, self-test passed, on the same
# certificate, which is all the two journeys after it need.
#
# The older release is reported through the real ingest path, never a
# product-side switch: a heartbeat presenting the canary's own bearer
# token and client certificate, sent from inside the canary's own network
# namespace so birdcage sees it from the canary's own address. birdcage
# has no test hook for versions, and must not grow one.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   scripts/e2e/enrol-and-hit.sh
#   scripts/e2e/refusals.sh
#   scripts/e2e/upgrade.sh
#   scripts/e2e/lifecycle.sh
#   scripts/e2e/surface.sh
set -eu

. "$(dirname "$0")/journey.sh"

PAGE="/api/canary?id=$E2E_CANARY_ID&range=1h"
STATE_VOL="$E2E_PREFIX-state"
WORK_VOL="$E2E_PREFIX-work"
HELPER_IMAGE="$E2E_PREFIX-helper"

# ADR-0012 B4's dual-use window (internal/ingest/dualuse.go's
# dualUseWindow): one certificate reporting two agent builds inside it is
# flagged credential_conflict. This journey reports two builds on purpose
# -- the real one, then an older one, then the real one again after the
# upgrade -- so each change of build waits until this long after the
# last heartbeat birdcage recorded. That is a deadline read off a state
# birdcage reports, not a guessed duration; the final step asserts
# credential_conflict never fired, which is what proves the wait was
# long enough.
DUAL_USE_WINDOW_S=60

# page_jq runs one jq program (its arguments, as one string) over a fresh
# GET of this canary's page, inside the helper: the JSON never
# round-trips through this shell.
page_jq() {
  helper "curl -sS --fail --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL$PAGE' | jq $1"
}

page_summary() {
  page_jq "-c '.canary | {status, active_states, agent_version, birdcage_version, last_heartbeat_at}'" 2>/dev/null \
    || echo "(page unreadable)"
}

# last_heartbeat_epoch is birdcage's own last_heartbeat_at for this
# canary, in Unix seconds. Go writes it in UTC with a Z; the fraction is
# cut so jq's fromdate accepts it.
last_heartbeat_epoch() {
  page_jq "-r '.canary.last_heartbeat_at | .[0:19] + \"Z\" | fromdate'"
}

# wait_past_dual_use_window waits until DUAL_USE_WINDOW_S has passed since
# the heartbeat at epoch $1. The helper and birdcage share this host's
# clock, which is what makes the two comparable.
wait_past_dual_use_window() {
  # +2: last_heartbeat_at is cut to the second, and the window is
  # inclusive (dualUseTracker.observe's <=).
  local deadline=$(($1 + DUAL_USE_WINDOW_S + 2)) now
  now="$(date -u +%s)"
  if [ "$now" -lt "$deadline" ]; then
    ok "waiting $((deadline - now)) s, until ${DUAL_USE_WINDOW_S} s after the heartbeat at $1 (ADR-0012 B4's window)"
    sleep "$((deadline - now))"
  fi
}

active_state_is() { # active_state_is <state> <true|false>
  page_jq "-e --arg s '$1' '((.canary.active_states // []) | any(.[]; . == \$s)) == $2'"
}

step "the canary is ok -- its first self-test settled -- before anything here touches it"
# Issue #146's lesson: never disturb a canary whose first self-test is
# still in flight. Straight after enrolment and refusals.sh that first
# self-test is usually still running (it lands a minute or two after
# first contact), and refusals.sh's requests from the helper's address
# can hold credential_conflict for two minutes; this waits on the state
# either way, not on a duration.
poll 180 page_jq "-e '.canary.status == \"ok\"'" \
  || fail "canary $E2E_CANARY_ID never read ok: $(page_summary)" "$E2E_BIRDCAGE" "$E2E_CANARY"

step "a current agent is not out of date, and its page offers no upgrade command"
birdcage_version="$(page_jq "-r '.canary.birdcage_version // \"\"'")" \
  || fail "could not read birdcage_version" "$E2E_BIRDCAGE"
agent_version="$(page_jq "-r '.canary.agent_version // \"\"'")" \
  || fail "could not read agent_version" "$E2E_BIRDCAGE"
# Without a release version on birdcage there is nothing any agent can
# be behind (internal/store/version.go: "dev" is never behind), and every
# absence check below would pass for the wrong reason.
case "$birdcage_version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "birdcage_version is '$birdcage_version', not a release version -- the images must carry scripts/release-version.sh's stamp (build:images, or stack.sh's own build), or this journey proves nothing" ;;
esac
[ "$agent_version" = "$birdcage_version" ] \
  || fail "the enrolled agent reports '$agent_version' but birdcage is '$birdcage_version'; both images come from one build and must agree"
active_state_is agent_out_of_date false >/dev/null \
  || fail "agent_out_of_date is active for an agent at birdcage's own release: $(page_summary)" "$E2E_BIRDCAGE"
# has() first: an absent field would also read as "no command", and this
# check must be able to tell a current agent from a backend that never
# sends one.
page_jq "-e '.canary | has(\"upgrade_command\") and .upgrade_command == \"\"'" >/dev/null \
  || fail "the page's canary object does not carry an empty upgrade_command for a current agent: $(page_jq "-c '.canary.upgrade_command'" 2>&1)" "$E2E_BIRDCAGE"
ok "agent $agent_version == birdcage $birdcage_version, not agent_out_of_date, upgrade_command present and empty"

# An older release than birdcage's own, by MAJOR.MINOR.PATCH -- the only
# part issue #54 compares. The build metadata is kept to prove it is
# ignored.
core="${birdcage_version%%+*}"
major="${core%%.*}"; rest="${core#*.}"; minor="${rest%%.*}"; patch="${rest#*.}"
if [ "$patch" -gt 0 ]; then
  older="$major.$minor.$((patch - 1))"
elif [ "$minor" -gt 0 ]; then
  older="$major.$((minor - 1)).$patch"
elif [ "$major" -gt 0 ]; then
  older="$((major - 1)).$minor.$patch"
else
  fail "birdcage is $birdcage_version: there is no older release to report"
fi
older="$older+e2eolder"

# Baseline for "same canary afterwards", as lifecycle.sh takes it.
serial_before="$(helper 'openssl x509 -in /state/client.pem -noout -serial')" \
  || fail "could not read the client certificate serial" "$E2E_CANARY"
sessions_before="$("$E2E_STACK" birdcage canary enrol --status | grep -Fc "$(printf '\tname=%s\tlane=' "$E2E_CANARY_NAME")")" \
  || fail "could not count enrolment sessions named $E2E_CANARY_NAME"
canaries_before="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' | jq '.canaries | length'")" \
  || fail "could not count canaries"

step "the canary reports an older release ($older) over the real ingest path"
# The real agent is stopped first: left running, its next heartbeat
# would report its own version again within a minute. Stopping it is also
# the state an operator's upgrade starts from.
docker stop "$E2E_CANARY" >/dev/null || fail "could not stop $E2E_CANARY" "$E2E_CANARY"
wait_past_dual_use_window "$(last_heartbeat_epoch)"

# From the holder's network namespace, the canary's own address, so
# birdcage's address-based dual-use check and last_seen_addr (which the
# next self-test probes) both see nothing unusual. The token and
# certificate never leave the container.
reported="$(docker run --rm --network "container:$E2E_HOLDER" \
  --volume "$STATE_VOL:/state:ro" --volume "$WORK_VOL:/work:ro" \
  "$HELPER_IMAGE" sh -c "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
    --cert /state/client.pem --key /state/client-key.pem \
    -H \"Authorization: Bearer \$(cat /state/token)\" \
    -X POST '$BIRDCAGE_INGEST_URL/ingest/heartbeat' \
    -d '{\"queue_depth\":0,\"log_read_ok\":true,\"agent_version\":\"$older\"}'")" \
  || fail "the heartbeat could not be sent: $reported" "$E2E_BIRDCAGE"
case "$reported" in
  *'"ok":true'*http=200*) ok "POST /ingest/heartbeat with the canary's own credential: $(printf '%s' "$reported" | tr '\n' ' ')" ;;
  *) fail "the heartbeat was not accepted: $reported" "$E2E_BIRDCAGE" ;;
esac

step "the API shows agent_out_of_date, and the page prints an upgrade command with no deploy token"
poll 30 active_state_is agent_out_of_date true \
  || fail "agent_out_of_date never became active after reporting $older: $(page_summary)" "$E2E_BIRDCAGE"
page_jq "-e --arg v '$older' '.canary.agent_version == \$v'" >/dev/null \
  || fail "agent_version is not the reported $older: $(page_summary)" "$E2E_BIRDCAGE"
active_state_is credential_conflict false >/dev/null \
  || fail "credential_conflict fired on the older build's heartbeat -- the dual-use wait was not long enough: $(page_summary)" "$E2E_BIRDCAGE"

helper "curl -sS --fail --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL$PAGE' | jq -r '.canary.upgrade_command' > /work/upgrade-command.txt" \
  || fail "could not store the page's upgrade command" "$E2E_BIRDCAGE"
# The token checks run inside the helper so neither token reaches this
# log. Each absence is preceded by its presence where it should be: the
# deploy token is found in the enrolment output first, so a grep that
# could never match anything cannot pass this step.
tokens="$(helper '
set -eu
cmd=/work/upgrade-command.txt
test -s "$cmd" || { echo "upgrade_command is empty"; exit 1; }
if grep -q DEPLOY_TOKEN "$cmd"; then echo "upgrade_command names a DEPLOY_TOKEN variable"; exit 1; fi
deploy=$(sed -n "s/^.*MOCKINGBIRD_DEPLOY_TOKEN=\([0-9a-f]*\).*$/\1/p" /work/enrol-output.txt)
test -n "$deploy" && grep -qF "$deploy" /work/enrol-output.txt || { echo "no deploy token in the enrolment output to compare against"; exit 1; }
if grep -qF "$deploy" "$cmd"; then echo "upgrade_command carries the deploy token"; exit 1; fi
bearer=$(cat /state/token)
test -n "$bearer" || { echo "no bearer token in the state volume"; exit 1; }
if grep -qF "$bearer" "$cmd"; then echo "upgrade_command carries the bearer token"; exit 1; fi
echo "no deploy token, no bearer token"
' 2>&1)" || fail "$tokens" "$E2E_BIRDCAGE"
ok "$tokens"

upgrade_cmd="$(helper 'cat /work/upgrade-command.txt')" \
  || fail "could not read the stored upgrade command back"
printf '%s\n' "$upgrade_cmd" | sed 's/^/    | /'

# The server's own facts must be the ones enrolment printed: the same
# birdcage URL and the same CA pin.
enrol_facts="$(helper "grep -E 'MOCKINGBIRD_(BIRDCAGE_URL|CA_PIN)=' /work/enrol-output.txt | sed 's/^ *//; s/ *\\\\\$//'")" \
  || fail "could not read the enrolment output's URL and pin"
[ "$(printf '%s\n' "$enrol_facts" | grep -c .)" = 2 ] \
  || fail "expected the enrolment output's URL and pin lines, got: $enrol_facts"
while IFS= read -r line; do
  case "$upgrade_cmd" in
    *"$line"*) ;;
    *) fail "the upgrade command lacks enrolment's own '$line'" ;;
  esac
done <<EOF
$enrol_facts
EOF
# The base stack enrolled with the SMB lure on (enrolment's default), so
# the stored facts (migration 0026) must say so: the lure's block has to
# be there to be removed by the edits below.
case "$upgrade_cmd" in
  *"docker run -d --name smb-lure "*) ;;
  *) fail "the upgrade command has no smb-lure block, but this canary was enrolled with the lure on" ;;
esac
ok "same birdcage URL and CA pin as enrolment printed; the lure's block is present"

step "running the printed upgrade command on this host brings the same canary back"
# Edited by rule, the same rules stack.sh applies to the enrolment
# command this re-runs (run_printed_command, run_opencanary_command,
# start_holder) -- collisions with the test environment, never
# disagreements with the product:
#
#   1. Image references: each block's image becomes the one the stack's
#      own container runs (docker inspect), and `docker pull <image>`
#      becomes `docker image inspect <image>`. The stack's images are
#      local builds that no registry holds; the pull's whole job is to
#      have the image on this host, which inspect proves.
#   2. Fixed names (holder, mockingbird, opencanary) and the two named
#      volumes become this stack's prefixed ones, so parallel pipelines
#      never collide; `--network container:holder` follows the holder.
#   3. The holder joins the stack's network under the canary's name --
#      the one thing start_holder adds to the printed holder command.
#   4. Everything SMB-lure (the audit volume, its mounts, the agent's
#      audit path, the lure's own pull/rm/run): this stack deploys no
#      lure, exactly as run_printed_command drops it at enrolment.
#
# Everything else -- the order, `rm -f` before re-run, the hardening
# flags, the URL and pin, and the absence of any token -- runs as printed.
printed_image() { # the image line of one printed `docker run` block
  printf '%s\n' "$upgrade_cmd" | sed -n "/^docker run -d --name $1 /,/[^\\\\]\$/{/[^\\\\]\$/p;}" | sed 's/^ *//'
}
running_image() { docker inspect --format '{{.Config.Image}}' "$1"; }
re() { printf '%s' "$1" | sed 's/[.[\*^$/]/\\&/g'; }

edits=()
for pair in "holder:$E2E_HOLDER" "mockingbird:$E2E_CANARY" "opencanary:$E2E_OPENCANARY"; do
  printed="$(printed_image "${pair%%:*}")"
  running="$(running_image "${pair#*:}")" || fail "could not read the image ${pair#*:} runs"
  [ -n "$printed" ] || fail "the upgrade command has no ${pair%%:*} block"
  ok "image ${pair%%:*}: printed $printed -> this stack's $running"
  edits+=(-e "s|^docker pull $(re "$printed")\$|docker image inspect $running >/dev/null|"
          -e "s|^  $(re "$printed")\$|  $running|")
done
lure_image="$(printed_image smb-lure)"
[ -n "$lure_image" ] || fail "the upgrade command has no smb-lure image line"

script="$(printf '%s\n' "$upgrade_cmd" | sed \
  -e "/^docker pull $(re "$lure_image")\$/d" \
  -e '/^docker rm -f smb-lure$/d' \
  -e '/^docker volume create /,/[^\\]$/d' \
  -e '/^docker run -d --name smb-lure /,/[^\\]$/d' \
  -e '/-v smb-audit:\/audit/d' \
  -e '/MOCKINGBIRD_SMB_AUDIT_PATH/d' \
  "${edits[@]}" \
  -e "s|^docker rm -f holder\$|docker rm -f $E2E_HOLDER|" \
  -e "s|^docker rm -f mockingbird\$|docker rm -f $E2E_CANARY|" \
  -e "s|^docker rm -f opencanary\$|docker rm -f $E2E_OPENCANARY|" \
  -e "s|^docker run -d --name holder |docker run -d --name $E2E_HOLDER --network $E2E_NET --network-alias $E2E_CANARY |" \
  -e "s|--name mockingbird |--name $E2E_CANARY |" \
  -e "s|--name opencanary |--name $E2E_OPENCANARY |" \
  -e "s|-v mockingbird-state:|-v $STATE_VOL:|" \
  -e "s|-v mockingbird-log:|-v $E2E_PREFIX-log:|" \
  -e "s|--network container:holder |--network container:$E2E_HOLDER |")"

# Nothing unprefixed may survive: a literal `holder` or `smb-audit` here
# would create or remove something outside this stack on a shared daemon.
if printf '%s\n' "$script" | grep -Eq -- '--name (holder|mockingbird|opencanary|smb-lure) |container:holder |rm -f (holder|mockingbird|opencanary|smb-lure)$|smb-audit|docker pull|mockingbird-(state|log):'; then
  fail "the edited upgrade command still names something outside this stack:
$script"
fi
for name in "$E2E_HOLDER" "$E2E_CANARY" "$E2E_OPENCANARY"; do
  case "$script" in
    *"docker rm -f $name"*"docker run -d --name $name "*) ;;
    *) fail "the edited upgrade command does not remove then re-run $name:
$script" ;;
  esac
done
printf '%s\n' "$script" | sed 's/^/    > /'

# #112: a concurrent pipeline's prune can take a build tag between this
# job's first use of it and this second one. A no-op outside CI.
for v in MOCKINGBIRD OPENCANARY HOLDER; do
  image_var="${v}_BUILD_IMAGE"; digest_var="${v}_BUILD_DIGEST"
  if [ -n "${!image_var:-}" ] && [ -n "${!digest_var:-}" ]; then
    "$(dirname "$0")/../ci-ensure-image.sh" "${!image_var}" "${!digest_var}" >&2 \
      || fail "could not ensure ${!image_var} is present before the upgrade"
  fi
done

# The older build's heartbeat is now birdcage's last word from this
# certificate; the real agent must not report its own build until the
# dual-use window on that has passed.
wait_past_dual_use_window "$(last_heartbeat_epoch)"
older_beat="$(last_heartbeat_epoch)"
upgrade_started="$(date -u +%s)"
bash -euc "$script" >/dev/null || fail "the upgrade command failed on this host" "$E2E_CANARY" "$E2E_OPENCANARY" "$E2E_HOLDER"
ok "upgrade command ran: holder, agent and OpenCanary replaced"

step "the upgraded agent heartbeats on its original credential and agent_out_of_date clears"
poll 150 page_jq "-e --arg v '$birdcage_version' --argjson after '$older_beat' '
  .canary.agent_version == \$v
  and (.canary.last_heartbeat_at | .[0:19] + \"Z\" | fromdate) > \$after
  and ((.canary.active_states // []) | any(.[]; . == \"agent_out_of_date\") | not)'" \
  || fail "the upgraded agent never reported $birdcage_version with agent_out_of_date cleared: $(page_summary)" "$E2E_CANARY" "$E2E_BIRDCAGE"

serial_after="$(helper 'openssl x509 -in /state/client.pem -noout -serial')" \
  || fail "could not read the client certificate serial after the upgrade" "$E2E_CANARY"
[ "$serial_after" = "$serial_before" ] \
  || fail "the client certificate changed across the upgrade ($serial_before -> $serial_after): that was a re-enrolment" "$E2E_CANARY"
sessions_after="$("$E2E_STACK" birdcage canary enrol --status | grep -Fc "$(printf '\tname=%s\tlane=' "$E2E_CANARY_NAME")")" \
  || fail "could not count enrolment sessions after the upgrade"
[ "$sessions_after" = "$sessions_before" ] \
  || fail "enrolment sessions named $E2E_CANARY_NAME changed ($sessions_before -> $sessions_after)" "$E2E_BIRDCAGE"
canaries_after="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' | jq '.canaries | length'")" \
  || fail "could not count canaries after the upgrade"
[ "$canaries_after" = "$canaries_before" ] \
  || fail "the number of canaries changed ($canaries_before -> $canaries_after): a new canary was registered" "$E2E_BIRDCAGE"
ok "canary $E2E_CANARY_ID, same certificate ($serial_after), no new session, no new canary, agent at $birdcage_version"

step "the upgraded canary passes a self-test and reads ok, with no credential conflict"
# Restarting rotates the token at once (cmd/mockingbird/rotate.go), and a
# completed rotation mints a self-test (selftestsched.RotationSucceeded);
# the agent polls for it within about 70 s. Wait for that run's result,
# not for time to pass.
poll 240 page_jq "-e --argjson after '$upgrade_started' '
  [.self_test_runs[] | select((.issued_at | .[0:19] + \"Z\" | fromdate) >= \$after and .passed == true)] | length > 0'" \
  || fail "no self-test issued after the upgrade passed: $(page_jq "-c '.self_test_runs'" 2>&1) $(page_summary)" "$E2E_CANARY" "$E2E_BIRDCAGE"
poll 60 page_jq "-e '.canary.status == \"ok\"'" \
  || fail "the upgraded canary never read ok: $(page_summary)" "$E2E_CANARY" "$E2E_BIRDCAGE"
active_state_is credential_conflict false >/dev/null \
  || fail "credential_conflict is active after the upgrade: $(page_summary)" "$E2E_BIRDCAGE"
page_jq "-e '.canary.upgrade_command == \"\"'" >/dev/null \
  || fail "the page still offers an upgrade command after the upgrade" "$E2E_BIRDCAGE"
ok "$(page_summary)"

finish
