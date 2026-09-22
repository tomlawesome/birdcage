#!/usr/bin/env bash
# scanner.sh -- issue #108 slice 1, commit 5: the live journey that
# proves Nightjar end to end -- enrolled by the real `birdcage canary
# enrol --kind scanner` command, run from its own printed `docker run`
# line exactly as enrol-and-hit.sh and smb.sh run theirs, scanning a
# fixture standing in for the operator's host filesystem with the real,
# freshly-fetched Grype and posting a real snapshot to POST
# /ingest/scans.
#
# Four legs, matching the "second opinion on the host mount" record on
# issue #108: masking blinds the scan rather than merely being present
# (leg 1); an edited command that drops one mask flag is refused rather
# than silently losing the covering (leg 2); a database that cannot be
# trusted fails the scan rather than reporting a clean host (leg 3); and
# the snapshot's identity is the enrolling token's (leg 4, folded into
# leg 1's own assertion -- see its own comment for why the second half
# of #108's leg 4 is skipped on this branch).
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/scanner-stack.sh up)"
#   scripts/e2e/scanner.sh
#   scripts/e2e/scanner-stack.sh down
#   scripts/e2e/stack.sh down
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${SCANNER_NIGHTJAR_IMAGE:-}" ] && [ -n "${SCANNER_FIXTURE_VOL:-}" ] && [ -n "${SCANNER_DB_VOL:-}" ] && [ -n "${SCANNER_EMPTY_DB_VOL:-}" ] || {
  echo "SCANNER_NIGHTJAR_IMAGE/SCANNER_FIXTURE_VOL/SCANNER_DB_VOL/SCANNER_EMPTY_DB_VOL unset -- run: eval \"\$(scripts/e2e/scanner-stack.sh up)\"" >&2
  exit 2
}

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

  command="$(helper "sed -n '/^docker run /,/[^\\\\]\$/p' /work/$workfile")" \
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
  local name="$1" container="$2" attempt status line
  for attempt in $(seq 1 60); do
    status="$(docker exec "$E2E_BIRDCAGE" /birdcage canary enrol --status 2>/dev/null || true)"
    line="$(printf '%s\n' "$status" | grep "name=$name[[:space:]]" | tail -1 || true)"
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

docker rm --force "${E2E_PREFIX}-scanner-leg2" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------
step "leg 3 -- database unavailable: the scan fails closed rather than reporting a clean host"
# ---------------------------------------------------------------------
enrol_scanner "e2e-scanner-leg3" "e2e-scanner" "scanner-leg3-enrol.txt"
run_scanner "${E2E_PREFIX}-scanner-leg3" "${E2E_PREFIX}-scanner-state-leg3" "$SCANNER_EMPTY_DB_VOL" "scanner-leg3-enrol.txt" "" "GRYPE_DB_AUTO_UPDATE=false"
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
# Leg 4 (identity) is folded into leg 1 above: "the snapshot's canary is
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
