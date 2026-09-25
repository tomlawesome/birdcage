#!/usr/bin/env bash
# scanner.sh -- issue #108 slice 1, commit 5: the live journey that
# proves Nightjar end to end -- enrolled by the real `birdcage canary
# enrol --kind scanner` command, run from its own printed `docker run`
# line exactly as enrol-and-hit.sh and smb.sh run theirs, scanning a
# fixture standing in for the operator's host filesystem with the real,
# freshly-fetched Grype and posting a real snapshot to POST
# /ingest/scans.
#
# Four legs. From #108's "second opinion on the host mount": masking
# blinds the scan rather than merely being present (leg 1); an edited
# command that drops one mask flag is refused rather than silently
# losing the covering (leg 2); a database that cannot be trusted fails
# the scan rather than reporting a clean host (leg 3); the snapshot's
# identity is the enrolling token's (folded into leg 1). From ADR-0012
# (#116): a new scanner is pending until an ordered scan passes, its
# run's stages advance on the read model (leg 1), a failed scan fails
# the proof and never registers the node (leg 2), and an unreachable
# mirror is reported at once and reads db_stale after a day (leg 4).
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/scanner-stack.sh up)"
#   scripts/e2e/scanner.sh
#   scripts/e2e/scanner-stack.sh down
#   scripts/e2e/stack.sh down
set -eu

. "$(dirname "$0")/journey.sh"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

[ -n "${SCANNER_NIGHTJAR_IMAGE:-}" ] && [ -n "${SCANNER_FIXTURE_VOL:-}" ] && [ -n "${SCANNER_DB_VOL:-}" ] && [ -n "${SCANNER_EMPTY_DB_VOL:-}" ] || {
  echo "SCANNER_NIGHTJAR_IMAGE/SCANNER_FIXTURE_VOL/SCANNER_DB_VOL/SCANNER_EMPTY_DB_VOL unset -- run: eval \"\$(scripts/e2e/scanner-stack.sh up)\"" >&2
  exit 2
}

# MIRROR_UNREACHABLE is run_scanner's extra_env for legs 3 and 4:
# Grype's database mirror moved to a port nothing listens on, so the
# refresh step fails the way an unreachable mirror does.
MIRROR_UNREACHABLE='GRYPE_DB_UPDATE_URL=http://127.0.0.1:9/listing.json'

# The exact masked_paths list a fully-covered snapshot must carry --
# internal/hostmask.Masks' own declaration order, mirrored here the way
# every other journey mirrors a product constant it has no import path
# to (this is a shell script, not Go).
WANT_MASKED_PATHS='["/etc/shadow","/etc/gshadow","/etc/ssh","/root","/proc","/run","/sys","/dev","/tmp","/var/tmp","/home"]'

# scan_check and scan_field both re-query GET /api/scans fresh rather
# than passing an already-fetched JSON blob back through another shell
# layer -- hostmask.Check's own failure text (leg 2 and leg 3's
# "reason") is free prose that can carry a comma, and Grype's own
# stderr, which that text sometimes wraps, is not birdcage's to
# constrain either. Only canary_id (a plain hex string) and a
# constant jq expression ever cross the shell/container boundary here,
# never the response body itself.
#
# scan_check is a plain jq -e boolean test against the newest snapshot
# for canary_id -- the same idiom enrol-and-hit.sh's and smb.sh's own
# `curl ... | jq -e '...'` assertions use.
scan_check() { # scan_check <canary_id> <jq-boolean-expr>
  local canary_id="$1" expr="$2"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/scans' \
    | jq -e --arg id '$canary_id' '[.scans[] | select(.canary_id == \$id)][0] | $expr'" \
    >/dev/null 2>&1
}

# scan_field prints one jq projection of the newest snapshot for
# canary_id, for a failure message only -- never for a pass/fail
# decision (scan_check above is exact).
scan_field() { # scan_field <canary_id> <jq-filter>
  local canary_id="$1" filt="$2"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/scans' \
    | jq -r --arg id '$canary_id' '[.scans[] | select(.canary_id == \$id)][0] | $filt'"
}

# scan_by_id_check/scan_by_id_field are scan_check/scan_field's own
# shape, keyed on scan_snapshots.id rather than canary_id -- ADR-0012
# decision 11: the Runs list carries a run's answering snapshot_id, and
# GET /api/scans is filtered by id here to check the two agree, never by
# assuming the newest snapshot for a canary is the one a given run
# answered.
scan_by_id_check() { # scan_by_id_check <snapshot_id> <jq-boolean-expr>
  local id="$1" expr="$2"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/scans' \
    | jq -e --argjson id '$id' '[.scans[] | select(.id == \$id)][0] | $expr'" \
    >/dev/null 2>&1
}
scan_by_id_field() { # scan_by_id_field <snapshot_id> <jq-filter>
  local id="$1" filt="$2"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/scans' \
    | jq -r --argjson id '$id' '[.scans[] | select(.id == \$id)][0] | $filt'"
}

# canary_check/canary_field are scan_check/scan_field's own shape, over
# GET /api/canaries instead of GET /api/scans -- ADR-0012 decisions 6, 9
# and 10 put pending, the open run's stage, the scanner's last_run and
# its db_refresh state on this read model, never on /api/scans.
canary_check() { # canary_check <canary_id> <jq-boolean-expr>
  local canary_id="$1" expr="$2"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' \
    | jq -e --arg id '$canary_id' '[.canaries[] | select(.id == \$id)][0] | $expr'" \
    >/dev/null 2>&1
}
canary_field() { # canary_field <canary_id> <jq-filter>
  local canary_id="$1" filt="$2"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries' \
    | jq -r --arg id '$canary_id' '[.canaries[] | select(.id == \$id)][0] | $filt'"
}

# runs_check/runs_field are the same shape again, over GET
# /api/canaries/{id}/runs' own "runs" array (ADR-0012 decision 11's Runs
# list) -- newest first, completed runs only, never the run id.
runs_check() { # runs_check <canary_id> <jq-boolean-expr-over-the-runs-array>
  local canary_id="$1" expr="$2"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries/$canary_id/runs' \
    | jq -e '.runs | $expr'" >/dev/null 2>&1
}
runs_field() { # runs_field <canary_id> <jq-filter-over-the-runs-array>
  local canary_id="$1" filt="$2"
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/canaries/$canary_id/runs' \
    | jq -r '.runs | $filt'"
}

# reference_count is leg 1's proof that /home/user/app's copy of the
# vulnerable manifest is blind rather than merely present: Grype, run
# directly against the fixture's /opt/app alone (already warm from
# scanner-stack.sh's own prefetch), finds some number of matches: if
# Nightjar's own snapshot -- scanning the whole covered fixture, /home
# included -- reports the same count, the masked copy contributed
# nothing. Taken fresh here rather than hard-coded, since the database
# updates and the exact CVE set can drift (build_fixture's own comment
# has the count measured when this file was written).
reference_count() {
  # First of several later uses of the nightjar build tag in this job,
  # after scanner-stack.sh's own build_image/prefetch_db already used it
  # -- and enrol_scanner and stack.sh up have run since, more window for
  # a concurrent pipeline's prune (#112) to have deleted it again. A
  # no-op outside CI, where these variables are unset.
  if [ -n "${NIGHTJAR_BUILD_IMAGE:-}" ] && [ -n "${NIGHTJAR_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$NIGHTJAR_BUILD_IMAGE" "$NIGHTJAR_BUILD_DIGEST" >&2 \
      || fail "could not ensure $NIGHTJAR_BUILD_IMAGE is present before computing the reference count"
  fi
  docker run --rm \
    --volume "$SCANNER_FIXTURE_VOL:/host:ro" \
    --volume "$SCANNER_DB_VOL:/var/lib/nightjar-grype-db" \
    --entrypoint /usr/local/bin/grype \
    "$SCANNER_NIGHTJAR_IMAGE" dir:/host/opt/app -o json 2>/dev/null \
    | grep -o '"vulnerability":{"id"' | wc -l | tr -d ' '
}

# enrol_scanner mints a scanner enrolment session exactly the way
# stack.sh's own enrol_canary does, --kind scanner added (issue #105).
# NIGHTJAR_IMAGE is set from scanner-stack.sh's own build/override so
# the printed command names the image this journey actually runs.
enrol_scanner() { # enrol_scanner <name> <lane> <work-file>
  local name="$1" lane="$2" workfile="$3" output
  output="$(docker exec --env "NIGHTJAR_IMAGE=$SCANNER_NIGHTJAR_IMAGE" "$E2E_BIRDCAGE" \
    /birdcage canary enrol --name "$name" --lane "$lane" --kind scanner)" \
    || fail "birdcage canary enrol --kind scanner failed for $name" "$E2E_BIRDCAGE"
  printf '%s\n' "$output" | "$E2E_STACK" write-work "$workfile" \
    || fail "could not store $name's enrolment output" "$E2E_BIRDCAGE"
}

# run_scanner takes the printed docker run command from workfile and
# runs it, edited by rule the same way stack.sh's run_printed_command
# and smb-stack.sh's run_smb_canary are: a name and a network so it can
# run at all in this harness, the fixture volume standing in for `/`,
# and this leg's own state volume so each of the three enrolments gets
# its own credentials rather than fighting over one.
#
# drop, when given, is a literal substring naming one whole flag to
# delete outright -- leg 2's own `--tmpfs /host/home:ro`, matched with
# grep -F so nothing in it is read as a pattern. extra_env, when given,
# is one more `-e NAME=VALUE` docker flag, folded into the same line
# that already renames the two volumes -- leg 3's
# GRYPE_DB_AUTO_UPDATE=false.
run_scanner() { # run_scanner <container-name> <state-vol> <db-vol> <workfile> [drop] [extra_env]
  local container="$1" statevol="$2" dbvol="$3" workfile="$4" drop="${5:-}" extra_env="${6:-}" command

  docker volume create "$statevol" >/dev/null || fail "creating volume $statevol failed"

  # Another use of the nightjar build tag in this job (three per run,
  # one per leg) -- re-check immediately before each one, same as
  # reference_count above, rather than trust an earlier check still
  # holds. A no-op outside CI, where these variables are unset.
  if [ -n "${NIGHTJAR_BUILD_IMAGE:-}" ] && [ -n "${NIGHTJAR_BUILD_DIGEST:-}" ]; then
    "$REPO_ROOT/scripts/ci-ensure-image.sh" "$NIGHTJAR_BUILD_IMAGE" "$NIGHTJAR_BUILD_DIGEST" >&2 \
      || fail "could not ensure $NIGHTJAR_BUILD_IMAGE is present before starting $container"
  fi

  # First `docker run` block only, and quit: the enrolment output has
  # carried two since #87 (see stack.sh run_printed_command).
  command="$(helper "sed -n '/^docker run /,/[^\\\\]\$/{p;/[^\\\\]\$/q;}' /work/$workfile")" \
    || fail "could not read $container's printed docker run command"

  command="$(printf '%s\n' "$command" | sed \
    -e "s|^docker run -d --name nightjar --restart unless-stopped |docker run -d --network $E2E_NET --name $container --restart unless-stopped |" \
    -e "s|-v /:/host:ro|-v $SCANNER_FIXTURE_VOL:/host:ro|" \
    -e "s|-v nightjar-state:/var/lib/nightjar -v nightjar-grype-db:/var/lib/nightjar-grype-db \\\\|-v $statevol:/var/lib/nightjar -v $dbvol:/var/lib/nightjar-grype-db${extra_env:+ -e $extra_env} \\\\|" \
  )"

  if [ -n "$drop" ]; then
    command="$(printf '%s\n' "$command" | grep -vF -- "$drop")"
  fi

  case "$command" in
    docker\ run\ *"$container"*"$SCANNER_NIGHTJAR_IMAGE"*) ;;
    *) fail "$container's printed docker run command did not look the way this harness expects; got: $(printf '%s' "$command" | sed 's/NIGHTJAR_DEPLOY_TOKEN=[^ ]*/NIGHTJAR_DEPLOY_TOKEN=<redacted>/')" ;;
  esac

  log_line="$(printf '%s' "$command" | tr -d '\\' | tr -s ' \n' ' ' | sed 's/NIGHTJAR_DEPLOY_TOKEN=[^ ]*/NIGHTJAR_DEPLOY_TOKEN=<redacted>/')"
  echo "  running: $log_line"
  eval "$command" >/dev/null || fail "$container's docker run command failed to start" "$container"
}

# wait_for_scanner blocks until name's enrolment session reaches
# provisioned, the same shape smb-stack.sh's wait_for_smb_canary
# follows (tail -1: a name can repeat if a prior down did not reach the
# database, which only scanner-stack.sh's/stack.sh's own down touches).
wait_for_scanner() { # wait_for_scanner <name> <container>
  local name="$1" container="$2" status line
  for _ in $(seq 1 60); do
    status="$(docker exec "$E2E_BIRDCAGE" /birdcage canary enrol --status 2>/dev/null || true)"
    line="$(printf '%s\n' "$status" | grep "name=${name}[[:space:]]" | tail -1 || true)"
    case "$line" in
      *state=provisioned*)
        SCANNER_CANARY_ID="$(printf '%s\n' "$line" | sed -n 's/.*[[:space:]]canary=\([^[:space:]]*\).*/\1/p')"
        [ -n "$SCANNER_CANARY_ID" ] || fail "$name is provisioned but --status printed no canary id" "$container"
        return 0
        ;;
    esac
    sleep 1
  done
  fail "$name never contacted birdcage" "$container" "$E2E_BIRDCAGE"
}

# wait_for_scan_snapshot polls GET /api/scans for the newest snapshot
# whose canary_id is canary_id -- ListScanSnapshots orders newest first,
# so the first match is this leg's own scan, whichever status it holds.
# 45 attempts: warm-cache legs post within a few seconds, but the
# container also has to start, dial birdcage over mutual TLS and
# complete enrolment first.
wait_for_scan_snapshot() { # wait_for_scan_snapshot <canary_id> <container>
  local canary_id="$1" container="$2"
  poll 45 helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/scans' \
    | jq -e --arg id '$canary_id' '[.scans[] | select(.canary_id == \$id)] | length > 0'" \
    || fail "GET /api/scans never held a snapshot for canary $canary_id after 45 attempts" "$container" "$E2E_BIRDCAGE"
}

# scan_stage_rank mirrors ADR-0012 decision 9's own closed, ordered
# vocabulary (internal/store/scanrun.go's stageRank) -- a plain shell
# case, since this is a shell script with no import path to the Go
# constant. Unknown or absent reads as -1, below every real stage.
scan_stage_rank() { # scan_stage_rank <stage-or-"none">
  case "$1" in
    ordered) echo 0 ;;
    collected) echo 1 ;;
    mounts_checked) echo 2 ;;
    db_refreshed) echo 3 ;;
    scanning) echo 4 ;;
    answered) echo 5 ;;
    *) echo -1 ;;
  esac
}

# wait_for_stage_progression polls canary_id's open proof run until its
# stage reaches "scanning" or later. It never polls for the literal
# string "collected" -- Nightjar's own command poll is jittered up to 70s
# (commandPollInterval +/- commandPollJitter), and a claim's own
# collected -> mounts_checked -> db_refreshed transition can be faster
# than this loop's one-second granularity, so a poll landing exactly on
# "collected" is not guaranteed. What is guaranteed is the ordering:
# AdvanceRunStage only ever moves a run forward (internal/store/
# scanrun.go), and handleCommands sets collected unconditionally at
# claim, before Nightjar can report anything later -- so observing
# "scanning" or "answered" is itself the proof the run passed through
# collected on its way there. Bound 5 minutes for the same jitter reason
# wait_for_registered below states.
wait_for_stage_progression() { # wait_for_stage_progression <canary_id> <container>
  local canary_id="$1" container="$2" stage rank attempt
  for attempt in $(seq 1 300); do
    stage="$(canary_field "$canary_id" 'if .run then .run.stage elif .last_run then "answered" else "none" end' 2>/dev/null)"
    [ -n "$stage" ] || stage="none"
    rank="$(scan_stage_rank "$stage")"
    if [ "$rank" -ge 4 ]; then
      ok "run's stage reached $stage after $attempt attempt(s) (having necessarily passed through collected first: stages only move forward)"
      return 0
    fi
    sleep 1
  done
  fail "the run's stage never reached scanning within 5 minutes -- last stage seen: $stage" "$container" "$E2E_BIRDCAGE"
}

# wait_for_registered polls until canary_id reads ok -- ADR-0012
# decision 4/6: only a passing ordered run calls SettlePending, so this
# is the same "pending -> registered" wait lifecycle.sh's own honeypot
# journey makes, bound at 5 minutes rather than 3 because a scanner's
# proof run also waits out Nightjar's own jittered command poll
# (up to 70s) before it can even start.
wait_for_registered() { # wait_for_registered <canary_id> <container>
  local canary_id="$1" container="$2"
  poll 300 canary_check "$canary_id" '.status == "ok"' \
    || fail "canary $canary_id never reached ok within 5 minutes of enrolling -- still $(canary_field "$canary_id" '.status'), last run: $(runs_field "$canary_id" '.[0] // "none"')" "$container" "$E2E_BIRDCAGE"
}

# set_db_refresh_failing_since backdates canaries.db_refresh_failing_since
# to 25 hours ago, directly in the store -- ADR-0012 decision 10's
# db_stale is birdcage's own clock compared against that column, and this
# journey cannot wait out the real 24 hours to prove the comparison.
# Mirrors lifecycle.sh's own set_heartbeat_interval: "$E2E_STACK query"
# cannot be reused for a write on SQLite (its own comment says why -- it
# copies the file first, so a write through it never reaches the live
# database), so SQLite gets its own path, a one-off container with the
# data volume mounted read-write instead of stack.sh helper()'s
# hard-coded :ro; Postgres already writes live through "$E2E_STACK query".
set_db_refresh_failing_since() { # set_db_refresh_failing_since <canary_id>
  local canary_id="$1" ts
  ts="$(helper 'date -u -d "@$(( $(date +%s) - 90000 ))" +%Y-%m-%dT%H:%M:%S.000000000Z')" \
    || fail "could not compute a 25-hour-old timestamp" "$E2E_BIRDCAGE"
  if [ "$E2E_BACKEND" = postgres ] || [ -n "${E2E_DATABASE_URL:-}" ]; then
    "$E2E_STACK" query "update agents set db_refresh_failing_since = '$ts' where id = '$canary_id'" >/dev/null \
      || fail "backdating db_refresh_failing_since failed (postgres)" "$E2E_BIRDCAGE"
  else
    docker run --rm --volume "${E2E_PREFIX}-data:/data" "${E2E_PREFIX}-helper" \
      sh -c "sqlite3 /data/birdcage.db \"update agents set db_refresh_failing_since = '$ts' where id = '$canary_id'\"" >/dev/null \
      || fail "backdating db_refresh_failing_since failed (sqlite)" "$E2E_BIRDCAGE"
  fi
}

# ---------------------------------------------------------------------
step "leg 1 -- happy path: a full scan, masking proven rather than assumed"
# ---------------------------------------------------------------------
REF_COUNT="$(reference_count)"
[ "$REF_COUNT" -ge 1 ] 2>/dev/null || fail "the fixture's /opt/app manifest matched no CVE at all (reference scan found $REF_COUNT) -- fixture is not doing its job"
ok "reference scan of /opt/app alone found $REF_COUNT finding(s)"

enrol_scanner "e2e-scanner-leg1" "e2e-scanner" "scanner-leg1-enrol.txt"
run_scanner "${E2E_PREFIX}-scanner-leg1" "${E2E_PREFIX}-scanner-state-leg1" "$SCANNER_DB_VOL" "scanner-leg1-enrol.txt"
wait_for_scanner "e2e-scanner-leg1" "${E2E_PREFIX}-scanner-leg1"
LEG1_CANARY="$SCANNER_CANARY_ID"

# ADR-0012 decision 5/6: provisioning pends every kind now, and a scanner
# clears pending only on a passing ordered scan -- never on ordinary
# contact. "pending" is asserted through active_states and the open
# run's own trigger, not the top-level status: "silent" (no heartbeat
# yet) outranks "pending" in healthStateRank, so a canary checked in the
# gap between provisioning and its first heartbeat could legitimately
# read "silent" at the top even though it is, in fact, pending.
canary_check "$LEG1_CANARY" '(.active_states // []) | index("pending") != null' \
  && ok "canary is pending right after enrolling" \
  || fail "leg 1 canary's active_states does not include pending right after enrolling: $(canary_field "$LEG1_CANARY" '.')" "${E2E_PREFIX}-scanner-leg1"
canary_check "$LEG1_CANARY" '.run != null and .run.trigger == "proof"' \
  && ok "an open proof run is minted for the node" \
  || fail "leg 1 canary carries no open proof run: $(canary_field "$LEG1_CANARY" '.run')" "${E2E_PREFIX}-scanner-leg1"

step "leg 1 -- the proof run's stage advances, and the node registers once it passes"
wait_for_stage_progression "$LEG1_CANARY" "${E2E_PREFIX}-scanner-leg1"
wait_for_registered "$LEG1_CANARY" "${E2E_PREFIX}-scanner-leg1"
ok "canary registered (status ok) once its ordered scan passed"

step "leg 1 -- the newest run's snapshot carries a database refresh at or after the run was issued"
RUN_ISSUED="$(runs_field "$LEG1_CANARY" '.[0].issued_at')"
RUN_SNAPSHOT_ID="$(runs_field "$LEG1_CANARY" '.[0].snapshot_id')"
case "$RUN_SNAPSHOT_ID" in
  ""|null) fail "leg 1's newest run carries no snapshot_id: $(runs_field "$LEG1_CANARY" '.[0]')" "${E2E_PREFIX}-scanner-leg1" ;;
esac
# RUN_ISSUED is a timestamp birdcage itself just returned, never
# attacker-controlled input, so it is safe to fold straight into the jq
# program text the way WANT_MASKED_PATHS above already is.
# jq's fromdateiso8601 takes whole seconds only and both sides are Go
# RFC3339Nano in UTC, so each is cut to its first 19 characters first:
# flooring both keeps "at or after" true to the second.
scan_by_id_check "$RUN_SNAPSHOT_ID" \
  "(.db_refreshed_at != null) and ((.db_refreshed_at[0:19] + \"Z\" | fromdateiso8601) >= (\"$RUN_ISSUED\"[0:19] + \"Z\" | fromdateiso8601))" \
  && ok "run's snapshot ($RUN_SNAPSHOT_ID) carries db_refreshed_at at or after the run's issued_at ($RUN_ISSUED)" \
  || fail "run's snapshot $RUN_SNAPSHOT_ID's db_refreshed_at is not at/after the run's issued_at ($RUN_ISSUED): $(scan_by_id_field "$RUN_SNAPSHOT_ID" '.')" "${E2E_PREFIX}-scanner-leg1"

step "leg 1 -- happy path: a full scan, masking proven rather than assumed"
wait_for_scan_snapshot "$LEG1_CANARY" "${E2E_PREFIX}-scanner-leg1"

scan_check "$LEG1_CANARY" '.status == "ok"' \
  && ok "snapshot status is ok" \
  || fail "leg 1 snapshot is not ok: $(scan_field "$LEG1_CANARY" '.')" "${E2E_PREFIX}-scanner-leg1"
scan_check "$LEG1_CANARY" '.engine_name == "grype"' \
  && ok "engine.name is grype" \
  || fail "leg 1 snapshot's engine is not grype: $(scan_field "$LEG1_CANARY" '.')"
# The snapshot's canary is the enrolling token's: it was only found at
# all above by filtering GET /api/scans on canary_id == $LEG1_CANARY,
# so this is real evidence about what the server actually stored under
# that token, not a tautology of the query.
ok "the snapshot's canary is the enrolling token's ($LEG1_CANARY)"

scan_check "$LEG1_CANARY" ".finding_count == $REF_COUNT" \
  && ok "finding_count matches the /opt/app-only reference ($REF_COUNT): /home/user/app's masked copy contributed nothing" \
  || fail "leg 1 finding_count != $REF_COUNT (the /opt/app-only reference) -- the /home/user/app copy was not blind: $(scan_field "$LEG1_CANARY" '.')" "${E2E_PREFIX}-scanner-leg1"

scan_check "$LEG1_CANARY" '.masked_paths == '"$WANT_MASKED_PATHS" \
  && ok "masked_paths matches the full mask list" \
  || fail "leg 1 masked_paths does not match the full mask list: $(scan_field "$LEG1_CANARY" '.masked_paths')"

docker rm --force "${E2E_PREFIX}-scanner-leg1" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------
step "leg 2 -- one mask removed: the agent refuses to scan rather than trusting the edited command"
# ---------------------------------------------------------------------
enrol_scanner "e2e-scanner-leg2" "e2e-scanner" "scanner-leg2-enrol.txt"
run_scanner "${E2E_PREFIX}-scanner-leg2" "${E2E_PREFIX}-scanner-state-leg2" "$SCANNER_DB_VOL" "scanner-leg2-enrol.txt" '--tmpfs /host/home:ro'
wait_for_scanner "e2e-scanner-leg2" "${E2E_PREFIX}-scanner-leg2"
LEG2_CANARY="$SCANNER_CANARY_ID"
wait_for_scan_snapshot "$LEG2_CANARY" "${E2E_PREFIX}-scanner-leg2"

scan_check "$LEG2_CANARY" '.status == "failed"' \
  && ok "snapshot status is failed" \
  || fail "leg 2 snapshot is not failed: $(scan_field "$LEG2_CANARY" '.')" "${E2E_PREFIX}-scanner-leg2"
scan_check "$LEG2_CANARY" '((.reason // "") | contains("/host/home")) and ((.reason // "") | contains("not covered"))' \
  && ok "reason names the uncovered path: $(scan_field "$LEG2_CANARY" '.reason')" \
  || fail "leg 2 reason does not name /host/home as uncovered: $(scan_field "$LEG2_CANARY" '.reason')" "${E2E_PREFIX}-scanner-leg2"
scan_check "$LEG2_CANARY" '.finding_count == 0' \
  && ok "finding_count is 0" \
  || fail "leg 2 finding_count is not 0 (a failed scan must never carry findings): $(scan_field "$LEG2_CANARY" '.finding_count')"

# ADR-0012 decision 4: a failed snapshot answers the open proof run at
# once -- the run is failed, the node reads self-test failed, and it
# stays pending, never ok. The run may be answered by a later scan than
# the one wait_for_scan_snapshot saw (Nightjar's command poll is jittered
# up to 70s), so the Runs list is polled rather than read once.
step "leg 2 -- the failed scan fails the proof run: self-test failed, still pending, never ok"
poll 300 runs_check "$LEG2_CANARY" 'length > 0' \
  || fail "leg 2's proof run never completed within 5 minutes: $(canary_field "$LEG2_CANARY" '.run')" "${E2E_PREFIX}-scanner-leg2" "$E2E_BIRDCAGE"
runs_check "$LEG2_CANARY" '.[0].trigger == "proof" and .[0].verdict == "fail" and ((.[0].reason // "") | startswith("scan_failed")) and ((.[0].reason // "") | contains("/host/home"))' \
  && ok "the Runs list holds the failed proof run: $(runs_field "$LEG2_CANARY" '.[0].reason')" \
  || fail "leg 2's newest run is not a failed proof run naming /host/home: $(runs_field "$LEG2_CANARY" '.[0]')" "$E2E_BIRDCAGE"
canary_check "$LEG2_CANARY" '(.active_states // []) as $s | ($s | index("self_test_failed") != null) and ($s | index("pending") != null)' \
  && ok "canary reads self-test failed and is still pending" \
  || fail "leg 2 canary's active_states lack self_test_failed or pending: $(canary_field "$LEG2_CANARY" '.active_states')" "$E2E_BIRDCAGE"
canary_check "$LEG2_CANARY" '.status != "ok"' \
  && ok "canary is not ok" \
  || fail "leg 2 canary reads ok with a failed proof: $(canary_field "$LEG2_CANARY" '.')" "$E2E_BIRDCAGE"

docker rm --force "${E2E_PREFIX}-scanner-leg2" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------
step "leg 3 -- database unavailable: the scan fails closed rather than reporting a clean host"
# ---------------------------------------------------------------------
enrol_scanner "e2e-scanner-leg3" "e2e-scanner" "scanner-leg3-enrol.txt"
# Nightjar refreshes the database before every scan (ADR-0012 decision
# 10) and this network reaches the real mirror, so an empty database
# volume alone would simply be filled. GRYPE_DB_UPDATE_URL points the
# refresh at a closed port, so the scan really does meet no database.
run_scanner "${E2E_PREFIX}-scanner-leg3" "${E2E_PREFIX}-scanner-state-leg3" "$SCANNER_EMPTY_DB_VOL" "scanner-leg3-enrol.txt" "" "$MIRROR_UNREACHABLE"
wait_for_scanner "e2e-scanner-leg3" "${E2E_PREFIX}-scanner-leg3"
LEG3_CANARY="$SCANNER_CANARY_ID"
wait_for_scan_snapshot "$LEG3_CANARY" "${E2E_PREFIX}-scanner-leg3"

scan_check "$LEG3_CANARY" '.status == "failed"' \
  && ok "snapshot status is failed" \
  || fail "leg 3 snapshot is not failed: $(scan_field "$LEG3_CANARY" '.')" "${E2E_PREFIX}-scanner-leg3"
scan_check "$LEG3_CANARY" '(.reason // "") | contains("database")' \
  && ok "reason names the database: $(scan_field "$LEG3_CANARY" '.reason')" \
  || fail "leg 3 reason does not mention the database: $(scan_field "$LEG3_CANARY" '.reason')" "${E2E_PREFIX}-scanner-leg3"
scan_check "$LEG3_CANARY" '.finding_count == 0' \
  && ok "finding_count is 0" \
  || fail "leg 3 finding_count is not 0: $(scan_field "$LEG3_CANARY" '.finding_count')"

docker rm --force "${E2E_PREFIX}-scanner-leg3" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------
step "leg 4 -- mirror unreachable: the scan runs on the last good database and says so"
# ---------------------------------------------------------------------
# ADR-0012 decision 10: a failing refresh never withholds a scan under
# the five-day limit -- the snapshot is ok, carries the refresh error,
# and the heartbeat puts db_refresh on the read model at once. It does
# not pass a proof (db_refreshed_at is never after issued_at), so the
# node stays pending. db_stale needs 24 hours of failing by birdcage's
# own clock, which a journey cannot wait: the stored failing_since is
# moved back 25 hours once the heartbeat has set it.
enrol_scanner "e2e-scanner-leg4" "e2e-scanner" "scanner-leg4-enrol.txt"
run_scanner "${E2E_PREFIX}-scanner-leg4" "${E2E_PREFIX}-scanner-state-leg4" "$SCANNER_DB_VOL" "scanner-leg4-enrol.txt" "" "$MIRROR_UNREACHABLE"
wait_for_scanner "e2e-scanner-leg4" "${E2E_PREFIX}-scanner-leg4"
LEG4_CANARY="$SCANNER_CANARY_ID"
wait_for_scan_snapshot "$LEG4_CANARY" "${E2E_PREFIX}-scanner-leg4"

scan_check "$LEG4_CANARY" '.status == "ok" and ((.db_refresh_error // "") != "")' \
  && ok "snapshot is ok and carries the refresh error: $(scan_field "$LEG4_CANARY" '.db_refresh_error')" \
  || fail "leg 4 snapshot is not ok with a db_refresh_error: $(scan_field "$LEG4_CANARY" '.')" "${E2E_PREFIX}-scanner-leg4"
poll 120 canary_check "$LEG4_CANARY" '.db_refresh != null and (.db_refresh.last_error // "") != ""' \
  || fail "leg 4 canary never showed db_refresh on the read model: $(canary_field "$LEG4_CANARY" '.')" "${E2E_PREFIX}-scanner-leg4" "$E2E_BIRDCAGE"
ok "the heartbeat's db_refresh is on the read model: $(canary_field "$LEG4_CANARY" '.db_refresh.last_error')"
canary_check "$LEG4_CANARY" '(.active_states // []) | index("db_stale") == null' \
  && ok "not db_stale yet: the refresh has failed for minutes, not a day" \
  || fail "leg 4 canary reads db_stale before 24 hours of failing: $(canary_field "$LEG4_CANARY" '.')" "$E2E_BIRDCAGE"

step "leg 4 -- a day of failing refreshes by birdcage's clock reads db_stale, and history records it"
set_db_refresh_failing_since "$LEG4_CANARY"
poll 30 canary_check "$LEG4_CANARY" '(.active_states // []) | index("db_stale") != null' \
  || fail "leg 4 canary never read db_stale after failing_since moved back 25 hours: $(canary_field "$LEG4_CANARY" '.')" "$E2E_BIRDCAGE"
ok "canary reads db_stale"
# #56's period writer ticks every 30s; three ticks is the bound.
poll 90 helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/history?range=15m&canary=$LEG4_CANARY' \
  | jq -e '[.periods[] | select(.state == \"db_stale\")] | length > 0'" \
  || fail "no db_stale period in /api/history for leg 4's canary within 90s" "$E2E_BIRDCAGE"
ok "the db_stale period is on the canary's history"

docker rm --force "${E2E_PREFIX}-scanner-leg4" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------
# #108's identity leg is folded into leg 1 above: "the snapshot's canary is
# the token's" is the canary_id assertion right after leg 1's engine
# check. The other half of #108's own leg 4 -- a snapshot posted with a
# honeypot token is refused -- needs a kind check on the ingest path
# that issue #106 was to add; store.CanaryToken (internal/store/token.go)
# carries no Kind field and internal/ingest/scans.go's handleScan takes
# identity from the token alone with no kind comparison at all, so #106
# is not on this branch yet. Skipped, per the brief's own instruction,
# rather than asserting something the product does not do yet.
# ---------------------------------------------------------------------

finish
