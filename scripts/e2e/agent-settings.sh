#!/usr/bin/env bash
# agent-settings.sh -- issue #124's live check: changing a per-canary
# setting reaches the already-running canary within one heartbeat, with
# no container restart, and the facts column shows the agent's own
# confirmation.
#
# The write is `birdcage agent settings set`, run on the birdcage host --
# not a dashboard API call. The dashboard API stays read-only until login
# exists (owner, 2026-09-26; #8): reading GET /api/canary's facts.settings
# is fine, but the only door onto store.SetCanarySettings is the CLI (see
# internal/api/api.go's dashboardRouteSpecs and
# cmd/birdcage/agentsettings.go).
#
# Reuses scripts/e2e/poisoner-stack.sh's infrastructure rather than
# standing up a second one: that canary is already paced to burst every
# few seconds and already proves bait lookups go out and reach birdcage
# as poisoner alerts (poisoner.sh). This journey's own job starts where
# that one leaves off -- it changes the segment profile from "windows"
# (the default poisoner-stack.sh enrols with) to "off" through the CLI,
# then proves the change took effect on the running container: no more
# bait lookups go out, the facts column reads the setting as confirmed,
# and the container was never restarted.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/poisoner-stack.sh up)"
#   scripts/e2e/poisoner.sh
#   scripts/e2e/agent-settings.sh
#   scripts/e2e/poisoner-stack.sh down
#   scripts/e2e/stack.sh down
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${POISONER_CANARY:-}" ] && [ -n "${POISONER_CANARY_ID:-}" ] \
  && [ -n "${POISONER_FIXTURE:-}" ] || {
  echo "agent-settings: POISONER_CANARY/_ID or POISONER_FIXTURE unset -- run: eval \"\$(scripts/e2e/poisoner-stack.sh up)\"" >&2
  exit 2
}

# POISONER_CANARY_ADDR is this canary's own address on the shared
# network -- read from the container, the same way poisoner.sh reads the
# fixture's own address from docker inspect rather than assuming one.
POISONER_CANARY_ADDR="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$POISONER_CANARY")"
[ -n "$POISONER_CANARY_ADDR" ] || fail "could not read $POISONER_CANARY's address" "$POISONER_CANARY"

# poisoned_answer_count reads the fixture's own log for how many times it
# has answered THIS canary's bait lookups -- the attacker's own side of
# the wire, the same reasoning poisoner.sh's fixture_poisoned uses, so
# "the canary stopped asking" is proved from the one place that could
# disagree with birdcage's own code.
#
# Scoped to POISONER_CANARY_ADDR, not every line the fixture ever logs:
# the same shared network also carries scripts/e2e/stack.sh's own base
# canary, which runs the poisoner road on its own "windows" default and
# asks once for its own derived neighbour names within (up to) three
# minutes of ITS start (internal/agent/poisoner's own StartupDelay bound)
# -- a burst this journey never touched and has no way to time against.
# CI job 24213 counted that unrelated canary's own startup burst as "the
# pushed profile did not stop the loop": the fixture answered
# 172.20.0.3's derived names (not this canary's e2e-oldfs-01/02/wpad)
# while this canary's own log showed no further hits at all past its
# self-test's own "nothing to send" a few seconds earlier. The trailing
# space after the address matches Responder's LLMNR/NBT-NS lines (one space)
# and its MDNS lines (several, for column alignment) alike, and stops a
# /24 neighbour's address (172.20.0.50) from matching as a prefix.
#
# POISONER_CANARY_ADDR is read once, below, rather than inside this
# function: fail's own exit only ends the subshell a command
# substitution like count="$(poisoned_answer_count)" runs it in, not
# this script, so a failed docker inspect in here would silently read as
# zero instead of stopping the journey.
poisoned_answer_count() {
  docker logs "$POISONER_FIXTURE" 2>&1 | grep -c "Poisoned answer sent to $POISONER_CANARY_ADDR " || true
}

# setting_field reads one field of key's row out of GET /api/canary's
# facts.settings -- one helper() call with the pipe inside it, the same
# shape poisoner.sh's own poisoner_alert_count uses, rather than two
# separate helper containers joined by an outer pipe (untested, and this
# journey has no need to be the first thing that tries it).
setting_field() { # setting_field <key> <jq-field>
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canary?id=$POISONER_CANARY_ID&range=15m' | jq -r '.facts.settings[]? | select(.key==\"$1\") | .$2'"
}

setting_confirmed() { [ "$(setting_field "$1" confirmed 2>/dev/null || true)" = "true" ]; } # setting_confirmed <key>
setting_value() { setting_field "$1" value; } # setting_value <key>, for the journey's own log only

step "the canary's segment profile starts at the enrolled default"
if setting_confirmed segment_profile; then
  fail "segment_profile already reads as confirmed before this journey pushed anything -- a previous run's state was not torn down" "$POISONER_CANARY"
fi
ok "no confirmed segment_profile row yet (poisoner-stack.sh enrols with the default, never writing canary_settings)"

step "the canary is still asking, so there is something to prove stops"
before="$(poisoned_answer_count)"
[ "${before:-0}" -ge 1 ] || fail "the fixture has not logged a single poisoned answer yet -- run scripts/e2e/poisoner.sh first, or wait for its own first burst" "$POISONER_CANARY" "$POISONER_FIXTURE"
ok "$before poisoned answer(s) logged so far"

startedAt="$(docker inspect --format '{{.State.StartedAt}}' "$POISONER_CANARY")" \
  || fail "could not read $POISONER_CANARY's start time" "$POISONER_CANARY"

step "the segment profile is turned off through the CLI"
resp="$("$E2E_STACK" birdcage agent settings set "$POISONER_CANARY_ID" segment_profile=off)" \
  || fail "birdcage agent settings set failed" "$POISONER_CANARY"
case "$resp" in
  *segment_profile=off*) ok "birdcage accepted the write: $resp" ;;
  *) fail "birdcage agent settings set did not echo segment_profile=off: $resp" "$POISONER_CANARY" ;;
esac

step "the running canary stops asking within one heartbeat -- no restart"
# heartbeatInterval (cmd/mockingbird/heartbeat.go) is a hard-coded 60s:
# the push above lands in birdcage's reply to whichever heartbeat request
# is in flight or next due, so the agent has applied it, live, well
# inside one interval from here. 75s is that one interval plus headroom
# for a loaded runner's scheduling delay, not uncertainty about the
# cadence.
sleep 75
after_wait="$(poisoned_answer_count)"
ok "poisoned answers before the push: $before, once one heartbeat interval has passed: $after_wait"

nowStartedAt="$(docker inspect --format '{{.State.StartedAt}}' "$POISONER_CANARY")" \
  || fail "could not re-read $POISONER_CANARY's start time" "$POISONER_CANARY"
[ "$nowStartedAt" = "$startedAt" ] \
  || fail "the canary container restarted (was $startedAt, now $nowStartedAt) -- the setting must reach it live" "$POISONER_CANARY"
ok "the container never restarted (still started at $startedAt)"

step "the canary keeps not asking -- the stop was not a one-off gap between bursts"
# The fixture's own tight pacing (poisoner-stack.sh's 2s ceiling) would
# have landed several more bursts in this window if the agent were still
# asking on the old profile.
sleep 15
final="$(poisoned_answer_count)"
[ "$final" = "$after_wait" ] \
  || fail "the fixture logged $((final - after_wait)) more poisoned answer(s) after the profile was pushed off -- the live push did not actually stop the burst loop" "$POISONER_CANARY" "$POISONER_FIXTURE"
ok "no further poisoned answers ($final, unchanged)"

step "the facts column shows the agent's own confirmation"
# Confirmation needs a second heartbeat, not the first: the one that
# carried the push also has to report back the resulting hash before
# birdcage can say the agent is actually running with it (an honest
# "confirmed" cannot be assumed from the push alone -- see
# internal/ingest/heartbeat.go's pushSettings). Two heartbeat intervals
# plus generous scheduling headroom, not one, is the right bound here.
poll 200 setting_confirmed segment_profile \
  || fail "segment_profile never confirmed after 200s, though the canary provably stopped asking above -- the agent's own reported hash never reached birdcage" "$POISONER_CANARY"
ok "segment_profile confirmed, value $(setting_value segment_profile)"

finish
