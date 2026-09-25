#!/usr/bin/env bash
# mail.sh -- issue #80's live journey: birdcage's outbound mail
# (internal/mail) and its approval mailbox (internal/mailbox) against a
# real Postfix and a real Dovecot (build/e2e-mail), not the in-process
# fakes their unit tests use.
#
#   eval "$(scripts/e2e/stack.sh up)"
#   eval "$(scripts/e2e/mail-stack.sh up)"
#   scripts/e2e/mail.sh
#   scripts/e2e/mail-stack.sh down
#   scripts/e2e/stack.sh down
#
# What makes birdcage send mail at all: exactly one thing does -- a
# revoked credential presented while its successor is live (a
# token_conflict, docs/configuration.md "Outbound mail"). Each case below
# makes one for a canary of its own, with nothing but the operator's own
# CLI and one request: `agent add`, `agent mint`, `agent revoke`, `agent
# mint` again for the successor, then the revoked token presented to the
# ingest listener. One canary per case because the per-canary cooldown
# (an hour) would otherwise fold every case after the first into it.
#
# birdcage's mail configuration never changes during the run. The server
# does (mail-stack.sh mode): a real submission server that stops offering
# STARTTLS, starts rejecting the password, or shrinks its size limit is
# how each of these turns up in real life, and the client has to cope
# with it as configured.
#
# Named gap: DKIM. The approval reply this journey puts in the mailbox is
# unsigned, so it proves the IMAP read path -- TLS, SEARCH, the size check
# before download, BODY.PEEK[], \Seen only after the verdict is written --
# and that the verdict is a refusal. A signed reply verified end to end
# needs a resolver birdcage asks for the key (approval.Verify is handed
# net.LookupTXT, the system resolver), and this stack has no DNS server
# of its own to publish a test key in -- the next slice of #80.
set -eu

. "$(dirname "$0")/journey.sh"

[ -n "${MAIL_SERVER:-}" ] || {
  echo "MAIL_SERVER unset -- run: eval \"\$(scripts/e2e/mail-stack.sh up)\"" >&2
  exit 2
}

# imap runs one IMAP command against the test account's INBOX, as a
# client of our own (curl) on the stack's network, over TLS verified
# against the exported CA. The account comes from a netrc file, so the
# password is never on a command line.
imap() {
  helper "curl -sS --max-time 10 --cacert /work/mail-ca.pem --netrc-file /work/mail-netrc 'imaps://$MAIL_SERVER/INBOX' -X '$1'"
}

# search_nums prints the message numbers an IMAP SEARCH returned, one
# line, possibly empty.
search_nums() {
  imap "$1" | sed -n 's/^\* SEARCH *//p' | tr -d '\r'
}

# mail_log prints the server's log (Postfix and Dovecot both write to the
# container's output) -- only this mode's, since each mode is a fresh
# container.
mail_log() { docker logs "$MAIL_SERVER" 2>&1; }

# birdcage_sessions prints Postfix's one-line summary of every SMTP
# session birdcage itself opened in this mode: `disconnect from <name>...
# ehlo=1 starttls=1 auth=1 mail=1 ...`, a count per command the client
# actually sent. Postfix names the client by Docker's reverse DNS, which
# starts with the container name.
birdcage_sessions() { mail_log | grep "disconnect from $E2E_BIRDCAGE" || true; }

# present_revoked_credential makes a token_conflict for a canary of its
# own ($1). The revoked token is read out of the mint output inside the
# helper, so it never reaches this script's output or a CI log. The
# client certificate is the enrolled canary's, which only has to get the
# TLS handshake through: the token lookup, and the conflict check behind
# it, run before anything compares the certificate to the token.
present_revoked_credential() {
  local id="$1" response
  "$E2E_STACK" birdcage agent add "$id" "$id" e2e-mail 21 >/dev/null \
    || fail "birdcage agent add $id failed"
  "$E2E_STACK" birdcage agent mint "$id" | "$E2E_STACK" write-work "mint-$id.txt" \
    || fail "birdcage agent mint $id failed"
  helper "grep -q '^token (shown once' /work/mint-$id.txt" \
    || fail "birdcage agent mint $id printed no token"
  "$E2E_STACK" birdcage agent revoke "$id" >/dev/null \
    || fail "birdcage agent revoke $id failed"
  # The successor. Its token is not needed, only its existence: a revoked
  # token is a conflict only while a newer one is live.
  "$E2E_STACK" birdcage agent mint "$id" >/dev/null \
    || fail "birdcage agent mint $id (successor) failed"
  response="$(helper "curl -sS -w '\nhttp=%{http_code}' --cacert /work/birdcage-ca.pem \
    --cert /state/client.pem --key /state/client-key.pem \
    -H \"Authorization: Bearer \$(sed -n 's/^token (shown once, record it now): //p' /work/mint-$id.txt)\" \
    -X POST '$BIRDCAGE_INGEST_URL/ingest/events' -d '{\"events\":[]}'")" \
    || fail "the revoked token for $id could not be presented"
  case "$response" in
    *http=401*) ok "the revoked token for $id was refused (401), as it must be" ;;
    *) fail "the revoked token for $id was not refused with 401: $response" ;;
  esac
}

# outbox_row reads the one mail_outbox row for canary $1 into
# OUTBOX_ROW as attempts|sent-or-unsent|last_error, through stack.sh
# query so it reads the same on either engine. A poll() command:
# succeeds once birdcage has either sent the message or tried and
# failed at least once.
OUTBOX_ROW=""
outbox_row() {
  OUTBOX_ROW="$("$E2E_STACK" query "select attempts, case when sent_at is null then 'unsent' else 'sent' end, coalesce(last_error, '') from mail_outbox where agent_id = '$1'" 2>/dev/null)" || return 1
  case "$OUTBOX_ROW" in
    *'|sent|'*) return 0 ;;
    [1-9]*'|unsent|'*) return 0 ;;
  esac
  return 1
}

# api_mail prints GET /api/mail's body.
api_mail() {
  helper "curl -sS --cacert /tls/dashboard-ca.pem '$BIRDCAGE_URL/api/mail'"
}

# The whole-journey cap on one attempt: the history tick that notices the
# conflict and sends in the same pass runs every 30 seconds, so 75 is two
# ticks and some slack.
SEND_WAIT=75

# =====================================================================
step "two approval replies are delivered to the approval mailbox through the real server"
# Sent first, so birdcage's once-a-minute poll (it started with the
# restart in mail-stack.sh up) is already counting down while the send
# case below runs. Delivered through Postfix rather than written into
# the Maildir, so the message birdcage reads is one a server stored.
#
# The second is just over the reader's one-megabyte cap
# (internal/mailbox.MaxMessageSize), for the size check that has to
# happen before any of it is downloaded.
# Written with bare LF line ends; curl --crlf makes them CRLF on the wire.
helper "set -eu
now=\$(date -R)
printf 'From: $MAIL_ADDRESS\nTo: $MAIL_ADDRESS\nSubject: [birdcage e2e-ref-1] Re: approve\nDate: %s\nMessage-ID: <e2e-approval-small@e2e.invalid>\n\napproved\n' \"\$now\" > /tmp/small.eml
{ printf 'From: $MAIL_ADDRESS\nTo: $MAIL_ADDRESS\nSubject: [birdcage e2e-ref-2] Re: approve\nDate: %s\nMessage-ID: <e2e-approval-big@e2e.invalid>\n\n' \"\$now\"
  head -c 1100000 /dev/zero | tr '\\000' a | fold -w 76; echo; } > /tmp/big.eml
for m in small big; do
  curl -sS --crlf --ssl-reqd --cacert /work/mail-ca.pem --netrc-file /work/mail-netrc \
    'smtp://$MAIL_SERVER:587' --mail-from '$MAIL_ADDRESS' --mail-rcpt '$MAIL_ADDRESS' --upload-file /tmp/\$m.eml
done" || fail "the approval replies could not be delivered" "$MAIL_SERVER"
small_uid=""
for _ in $(seq 1 30); do
  small_uid="$(search_nums 'SEARCH HEADER Message-ID e2e-approval-small')"
  big_uid="$(search_nums 'SEARCH HEADER Message-ID e2e-approval-big')"
  [ -n "$small_uid" ] && [ -n "$big_uid" ] && break
  sleep 1
done
[ -n "$small_uid" ] && [ -n "$big_uid" ] \
  || fail "the two approval replies never appeared in the INBOX over IMAP" "$MAIL_SERVER"
ok "both are in the INBOX (messages $small_uid and $big_uid), unread"

# =====================================================================
step "(a) a token conflict is mailed through STARTTLS and AUTH, and arrives"
present_revoked_credential e2e-mail-sent
poll "$SEND_WAIT" outbox_row e2e-mail-sent \
  || fail "birdcage never tried to send the e2e-mail-sent alert within ${SEND_WAIT}s; outbox row: '$OUTBOX_ROW'" "$E2E_BIRDCAGE" "$MAIL_SERVER"
case "$OUTBOX_ROW" in
  *'|sent|'*) ok "mail_outbox records the alert as sent: $OUTBOX_ROW" ;;
  *) fail "the alert was not sent: $OUTBOX_ROW" "$E2E_BIRDCAGE" "$MAIL_SERVER" ;;
esac

sent_num=""
for _ in $(seq 1 15); do
  sent_num="$(search_nums 'SEARCH BODY e2e-mail-sent')"
  [ -n "$sent_num" ] && break
  sleep 1
done
[ -n "$sent_num" ] || fail "the alert never reached the INBOX over IMAP" "$MAIL_SERVER"
helper "curl -sS --max-time 10 --cacert /work/mail-ca.pem --netrc-file /work/mail-netrc 'imaps://$MAIL_SERVER/INBOX;MAILINDEX=${sent_num%% *}' > /work/alert.eml" \
  || fail "fetching the alert over IMAP failed" "$MAIL_SERVER"
helper "grep -q '^Subject: birdcage: an agent presented a revoked credential' /work/alert.eml" \
  || fail "the fetched alert does not carry birdcage's fixed subject: $(helper 'head -20 /work/alert.eml')"
helper "grep -q '^From: $MAIL_FROM' /work/alert.eml" \
  || fail "the fetched alert is not from $MAIL_FROM"
helper "grep -q 'Agent: e2e-mail-sent (id e2e-mail-sent)' /work/alert.eml" \
  || fail "the fetched alert does not name the canary that conflicted"
# The "with" clause is Postfix's own record, in the Received header it
# wrote, of how the message came in: the S is TLS and the A is an
# authenticated client (RFC 3848). Go's client asks for SMTPUTF8, so
# Postfix writes UTF8SMTPSA (RFC 6531) rather than ESMTPSA; either says
# the same two things.
helper "grep -Eq 'with (ESMTPSA|UTF8SMTPSA) ' /work/alert.eml" \
  || fail "the alert's Received header does not say ESMTPSA/UTF8SMTPSA -- it did not arrive over STARTTLS with AUTH: $(helper "grep -A2 '^Received' /work/alert.eml")"
ok "fetched over IMAPS: birdcage's subject, from $MAIL_FROM, naming e2e-mail-sent, received over TLS with AUTH"
docker exec "$MAIL_SERVER" grep -rlq 'id e2e-mail-sent' "/var/mail/$MAIL_USER/Maildir" \
  || fail "no file in the Maildir holds the alert" "$MAIL_SERVER"
ok "the Maildir on disk holds it"

api="$(api_mail)" || fail "GET /api/mail failed"
printf '%s\n' "$api" | "$E2E_STACK" write-work api-mail.json || fail "could not stash GET /api/mail"
helper "jq -e '.configured == true and .last_sent_at != null and .last_error == null and .pending == 0' /work/api-mail.json >/dev/null" \
  || fail "GET /api/mail does not report a configured, working, drained mailer: $api"
ok "GET /api/mail: $api"

# =====================================================================
step "(e) the approval mailbox reads the reply over IMAPS, records a verdict, and marks it read"
approval=""
approval_recorded() {
  approval="$("$E2E_STACK" query "select coalesce(verified_at, 'unverified'), coalesce(reject_reason, '') from approvals where message_id like '%e2e-approval-small%'" 2>/dev/null)" || return 1
  [ -n "$approval" ]
}
poll 90 approval_recorded \
  || fail "no approvals row for the small reply within 90s of it arriving -- birdcage never read it over IMAP" "$E2E_BIRDCAGE" "$MAIL_SERVER"
case "$approval" in
  unverified\|*DKIM*) ok "recorded, and refused for want of a DKIM signature: $approval" ;;
  *) fail "the approvals row is not the unsigned-reply refusal expected: $approval" ;;
esac
[ -n "$(search_nums 'SEARCH SEEN HEADER Message-ID e2e-approval-small')" ] \
  || fail "the small reply is still unread -- birdcage recorded it but did not mark it seen" "$E2E_BIRDCAGE"
ok "the small reply is marked \\Seen on the server"

# The oversize reply: marked read, never handed to the verifier, never
# recorded. It shares the poll with the small one, so by now it has been
# looked at.
[ -n "$(search_nums 'SEARCH SEEN HEADER Message-ID e2e-approval-big')" ] \
  || fail "the oversize reply is still unread -- the reader did not skip it" "$E2E_BIRDCAGE"
big_rows="$("$E2E_STACK" query "select count(*) from approvals where message_id like '%e2e-approval-big%'")" \
  || fail "could not count approvals rows for the oversize reply"
[ "$big_rows" = 0 ] || fail "the oversize reply was recorded ($big_rows row(s)) -- it should have been skipped before download"
"$E2E_STACK" logs 2>&1 | grep -q 'over the 1048576-byte limit; marking it read and skipping it' \
  || fail "birdcage did not log skipping the oversize reply"
ok "the oversize reply is marked \\Seen, unrecorded, and birdcage logged skipping it"

# =====================================================================
step "(b) against a server that does not offer STARTTLS, birdcage refuses to send"
"$MAIL_STACK" mode no-starttls
ehlo="$(helper "{ sleep 1; printf 'EHLO probe\r\n'; sleep 1; printf 'QUIT\r\n'; sleep 1; } | nc -w 5 $MAIL_SERVER 587")" \
  || fail "could not EHLO the no-starttls server" "$MAIL_SERVER"
case "$ehlo" in
  *STARTTLS*) fail "the no-starttls server still offers STARTTLS -- this case would prove nothing: $ehlo" "$MAIL_SERVER" ;;
  *'AUTH PLAIN'*) ok "precondition: the server offers AUTH PLAIN in the clear and no STARTTLS" ;;
  *) fail "the no-starttls server does not offer AUTH either -- the temptation this case needs is missing: $ehlo" "$MAIL_SERVER" ;;
esac
present_revoked_credential e2e-mail-cleartext
poll "$SEND_WAIT" outbox_row e2e-mail-cleartext \
  || fail "birdcage never tried to send the e2e-mail-cleartext alert within ${SEND_WAIT}s; outbox row: '$OUTBOX_ROW'" "$E2E_BIRDCAGE" "$MAIL_SERVER"
case "$OUTBOX_ROW" in
  *'|unsent|'*'does not offer STARTTLS; refusing to continue in the clear'*)
    ok "recorded as refused, not sent: $OUTBOX_ROW" ;;
  *) fail "the alert was not refused for want of STARTTLS: $OUTBOX_ROW" "$E2E_BIRDCAGE" "$MAIL_SERVER" ;;
esac
sessions="$(birdcage_sessions)"
[ -n "$sessions" ] || fail "Postfix logged no session from $E2E_BIRDCAGE" "$MAIL_SERVER"
case "$sessions" in
  *auth=*|*mail=*|*data=*) fail "birdcage sent AUTH, MAIL or DATA to a server without STARTTLS: $sessions" "$MAIL_SERVER" ;;
esac
ok "the server's own log shows birdcage said EHLO and nothing else: $sessions"
api="$(api_mail)" || fail "GET /api/mail failed"
case "$api" in
  *'"failing_since":"'*'does not offer STARTTLS'*) ok "GET /api/mail reports it: $api" ;;
  *) fail "GET /api/mail does not report the STARTTLS refusal: $api" ;;
esac

# =====================================================================
step "(c) against a server that rejects the credential, delivery fails and the credential stays out of the record"
"$MAIL_STACK" mode reject-auth
present_revoked_credential e2e-mail-badcred
poll "$SEND_WAIT" outbox_row e2e-mail-badcred \
  || fail "birdcage never tried to send the e2e-mail-badcred alert within ${SEND_WAIT}s; outbox row: '$OUTBOX_ROW'" "$E2E_BIRDCAGE" "$MAIL_SERVER"
case "$OUTBOX_ROW" in
  *'|unsent|'*'SMTP authentication as [redacted]: 535'*) ok "recorded as an authentication failure, username scrubbed: $OUTBOX_ROW" ;;
  *) fail "the alert did not fail at authentication as expected: $OUTBOX_ROW" "$E2E_BIRDCAGE" "$MAIL_SERVER" ;;
esac
# The password and the username never reach the outbox (read back by GET
# /api/mail and shown on the dashboard) or birdcage's log -- the scrub
# internal/mail's sender tests pin, here against a real server's real
# rejection text. The placeholder is read from the netrc inside the
# helper so this script never holds it either.
helper "set -eu; pw=\$(sed -n 's/.* password //p' /work/mail-netrc); [ -n \"\$pw\" ]" \
  || fail "could not read the test password back for the leak check"
"$E2E_STACK" query "select coalesce(last_error, '') from mail_outbox" | "$E2E_STACK" write-work outbox-errors.txt \
  || fail "could not read mail_outbox.last_error"
"$E2E_STACK" logs 2>&1 | "$E2E_STACK" write-work birdcage.log || fail "could not capture birdcage's log"
helper "set -eu; pw=\$(sed -n 's/.* password //p' /work/mail-netrc)
! grep -qF \"\$pw\" /work/outbox-errors.txt
! grep -qF \"\$pw\" /work/birdcage.log
! grep -qF '$MAIL_USER' /work/outbox-errors.txt" \
  || fail "the password or username appears in mail_outbox.last_error or birdcage's log"
ok "neither the password nor the username is in mail_outbox.last_error; the password is not in birdcage's log"
sessions="$(birdcage_sessions)"
case "$sessions" in
  *'auth=0/1'*) ;;
  *) fail "Postfix did not log a failed AUTH from birdcage: $sessions" "$MAIL_SERVER" ;;
esac
case "$sessions" in
  *mail=*) fail "birdcage went on to MAIL FROM after a failed AUTH: $sessions" "$MAIL_SERVER" ;;
esac
ok "the server's own log shows STARTTLS, a failed AUTH, and no MAIL FROM: $sessions"

# =====================================================================
step "(d) a message over the server's size limit is refused by the server and recorded"
"$MAIL_STACK" mode size-cap
present_revoked_credential e2e-mail-oversize
poll "$SEND_WAIT" outbox_row e2e-mail-oversize \
  || fail "birdcage never tried to send the e2e-mail-oversize alert within ${SEND_WAIT}s; outbox row: '$OUTBOX_ROW'" "$E2E_BIRDCAGE" "$MAIL_SERVER"
# Go's client does not declare a SIZE on MAIL FROM, so Postfix cannot
# refuse up front ("Message size exceeds fixed limit", which is what a
# client that declares one sees); it takes the bytes, then refuses the
# whole message at the end of DATA with "message file too big". Found by
# running this against the real server; internal/mail's unit tests have
# no size refusal at all.
case "$OUTBOX_ROW" in
  *'|unsent|'*'finish message: 552 '*'too big'*) ok "recorded as refused for size: $OUTBOX_ROW" ;;
  *) fail "the alert was not refused for size: $OUTBOX_ROW" "$E2E_BIRDCAGE" "$MAIL_SERVER" ;;
esac
sessions="$(birdcage_sessions)"
case "$sessions" in
  *'auth=1 mail=1 rcpt=1 data=0/1'*) ok "the server's own log shows AUTH, MAIL, RCPT accepted and DATA refused: $sessions" ;;
  *) fail "Postfix did not log birdcage's DATA being refused: $sessions" "$MAIL_SERVER" ;;
esac
if docker exec "$MAIL_SERVER" grep -rlq 'id e2e-mail-oversize' "/var/mail/$MAIL_USER/Maildir"; then
  fail "the oversize alert was delivered anyway" "$MAIL_SERVER"
fi
ok "nothing for e2e-mail-oversize reached the Maildir"

# =====================================================================
step "every failed alert is still owed, none dropped"
api="$(api_mail)" || fail "GET /api/mail failed"
printf '%s\n' "$api" | "$E2E_STACK" write-work api-mail.json || fail "could not stash GET /api/mail"
helper "jq -e '.pending == 3 and .failing_since != null' /work/api-mail.json >/dev/null" \
  || fail "GET /api/mail does not show the three failed alerts as still owed: $api"
ok "GET /api/mail: $api"

finish
