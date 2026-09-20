#!/usr/bin/env bash
# smb.sh -- issue #78 journey 3: a real smbclient against a real smbd
# with the full_audit VFS module produces an smbd_audit line, OpenCanary
# parses it, and the marker in the file's name survives all the way into
# the alert birdcage stores.
#
# scripts/e2e/stack.sh up proved the back two-thirds of this chain
# already (2026-09-20): a correctly shaped smbd_audit line appended by
# hand makes OpenCanary emit an event with the path in
# logdata.FILENAME. What this file proves is the one link that was
# still unproved -- that Samba itself, driven by a real client, actually
# writes such a line. scripts/e2e/smb-stack.sh is the infrastructure
# this needs and no other journey does (a Samba container, and a second
# canary configured to watch its audit log); it is opt-in, started here
# rather than by `stack.sh up`.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/smb-stack.sh up)"
#   scripts/e2e/smb.sh
#   scripts/e2e/smb-stack.sh down
#   scripts/e2e/stack.sh down
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${SMB_SAMBA:-}" ] && [ -n "${SMB_SAMBA_IMAGE:-}" ] && [ -n "${SMB_CANARY:-}" ] && [ -n "${SMB_CANARY_ID:-}" ] || {
  echo "SMB_SAMBA/SMB_SAMBA_IMAGE/SMB_CANARY/SMB_CANARY_ID unset -- run: eval \"\$(scripts/e2e/smb-stack.sh up)\"" >&2
  exit 2
}

step "the smb canary appears in birdcage canary list"
list="$("$E2E_STACK" birdcage canary list)" || fail "birdcage canary list did not run"
case "$list" in
  *"canary=$SMB_CANARY_ID"*) ok "smb canary $SMB_CANARY_ID holds a token" ;;
  *) fail "smb canary $SMB_CANARY_ID is not in the list: $list" ;;
esac

# The marker is this run's own random hex, embedded in the filename a
# real smbclient writes -- not chosen by the code under test, so
# matching it back out of an alert is evidence about this run and no
# other.
MARKER="e2e-smb-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n').txt"

step "a real smbclient writes $MARKER to the Samba share"
docker run --rm --network "$E2E_NET" --entrypoint bash "$SMB_SAMBA_IMAGE" -c "
set -eu
echo e2e-smb-journey > /tmp/marker
smbclient //$SMB_SAMBA/share -N -c 'put /tmp/marker $MARKER'
" >/dev/null || fail "smbclient could not PUT $MARKER to //$SMB_SAMBA/share" "$SMB_SAMBA"
ok "wrote $MARKER over a real SMB session"

step "smbd's full_audit line reached OpenCanary and then birdcage"
# fromjson on .raw: /api/alerts stores OpenCanary's whole event as a raw
# JSON string (internal/store.Alert.Raw), so logdata.FILENAME is a field
# inside that string, not of the alert object itself.
poll 30 helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=smb' \
  | jq -e --arg m '$MARKER' '[.alerts[] | (.raw | fromjson | .logdata.FILENAME // \"\") | select(contains(\$m))] | length > 0'" \
  || fail "/api/alerts never held an smb event naming $MARKER after 30 attempts" "$SMB_CANARY" "$SMB_SAMBA" "$E2E_BIRDCAGE"

alert="$(helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/alerts?service=smb' \
  | jq -c --arg m '$MARKER' '[.alerts[] | select((.raw | fromjson | .logdata.FILENAME // \"\") | contains(\$m))][0] | {id, service, dest_port, filename: (.raw | fromjson | .logdata.FILENAME)}'")"
case "$alert" in
  *"$MARKER"*) ok "alert: $alert" ;;
  *) fail "could not re-read the smb alert naming $MARKER: $alert" "$E2E_BIRDCAGE" ;;
esac

finish
