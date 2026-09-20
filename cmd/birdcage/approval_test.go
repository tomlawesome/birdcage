package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/logging"
	"github.com/tomlawesome/birdcage/internal/store"
)

// The one thing the boot inventory has to get right: it says where
// birdcage is reading approvals from, and it does not say the
// credential. The value below is a literal, obviously-fake placeholder.
func TestLoadMailboxConfigNeverLogsThePassword(t *testing.T) {
	const password = "not-a-real-password-ZZZZ"
	t.Setenv("BIRDCAGE_APPROVAL_IMAP_HOST", "imap.example.invalid")
	t.Setenv("BIRDCAGE_APPROVAL_IMAP_USERNAME", "birdcage@example.invalid")
	t.Setenv("BIRDCAGE_APPROVAL_IMAP_PASSWORD", password)

	out, _ := captureStdout(t, func() error {
		cfg, enabled := loadMailboxConfig(logging.New("approval"))
		if !enabled {
			t.Error("enabled = false for a complete configuration")
		}
		if cfg.Password != password {
			t.Error("the password did not reach the configuration")
		}
		if cfg.Host != "imap.example.invalid:993" {
			t.Errorf("Host = %q, want the default port filled in", cfg.Host)
		}
		return nil
	})

	if strings.Contains(out, password) {
		t.Error("the boot inventory printed the password")
	}
	for _, want := range []string{"imap.example.invalid:993", "implicit TLS", "INBOX", "BIRDCAGE_APPROVAL_IMAP_PASSWORD"} {
		if !strings.Contains(out, want) {
			t.Errorf("the boot inventory does not mention %q:\n%s", want, out)
		}
	}
}

func TestLoadMailboxConfigOffWhenNothingIsSet(t *testing.T) {
	for _, name := range []string{
		"BIRDCAGE_APPROVAL_IMAP_HOST", "BIRDCAGE_APPROVAL_IMAP_USERNAME",
		"BIRDCAGE_APPROVAL_IMAP_PASSWORD_FILE", "BIRDCAGE_APPROVAL_IMAP_PASSWORD",
		"BIRDCAGE_APPROVAL_IMAP_MAILBOX",
	} {
		t.Setenv(name, "")
	}
	out, _ := captureStdout(t, func() error {
		if _, enabled := loadMailboxConfig(logging.New("approval")); enabled {
			t.Error("enabled = true with nothing configured")
		}
		return nil
	})
	if !strings.Contains(out, "disabled") {
		t.Errorf("the boot line does not say the mailbox is off:\n%s", out)
	}
}

// writeEML puts a message in a temp file and returns its path.
func writeEML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "message.eml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

const unsignedReply = "From: Birdcage Admin <admin@example.net>\r\n" +
	"To: birdcage@example.net\r\n" +
	"Subject: Re: [birdcage u-2026-09-19-7f3a] upgrade mockingbird\r\n" +
	"Date: Fri, 19 Sep 2026 10:00:00 +0000\r\n" +
	"Message-ID: <reply-1@example.net>\r\n" +
	"\r\n" +
	"Yes, go ahead.\r\n"

// Without a pinned administrator address there is nothing to check
// against, and the command says which command to run rather than
// failing obscurely.
func TestApprovalCheckNeedsAPinnedAddress(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	path := writeEML(t, unsignedReply)

	_, err := captureStdout(t, func() error { return runApprovalCheck([]string{path}) })
	if err == nil {
		t.Fatal("runApprovalCheck succeeded with no administrator address set")
	}
	if !strings.Contains(err.Error(), "admin_approval_address") {
		t.Errorf("the error does not name the setting to fix: %v", err)
	}
}

// A message with no reference token is not an approval of anything, and
// the command says so before it goes anywhere near DNS.
func TestApprovalCheckReportsAMissingReference(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	pinAdminAddress(t)

	path := writeEML(t, strings.Replace(unsignedReply,
		"Subject: Re: [birdcage u-2026-09-19-7f3a] upgrade mockingbird",
		"Subject: Re: upgrade mockingbird", 1))

	out, err := captureStdout(t, func() error { return runApprovalCheck([]string{path}) })
	if err != nil {
		t.Fatalf("runApprovalCheck: %v", err)
	}
	if !strings.Contains(out, "carries no") {
		t.Errorf("the output does not say the reference is missing:\n%s", out)
	}
}

// The reported reason is the first rule the message broke, in plain
// words -- this one is unsigned, which is decided without any DNS
// lookup at all.
func TestApprovalCheckExplainsWhyAMessageFails(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	pinAdminAddress(t)

	path := writeEML(t, unsignedReply)
	out, err := captureStdout(t, func() error { return runApprovalCheck([]string{path}) })
	if err != nil {
		t.Fatalf("runApprovalCheck: %v", err)
	}
	for _, want := range []string{"admin@example.net", "u-2026-09-19-7f3a", "No. The first thing that failed", "no DKIM signature"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not mention %q:\n%s", want, out)
		}
	}
}

func TestApprovalCheckRefusesAnOversizedFile(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	pinAdminAddress(t)

	path := writeEML(t, unsignedReply+strings.Repeat("x", 1<<20))
	if _, err := captureStdout(t, func() error { return runApprovalCheck([]string{path}) }); err == nil {
		t.Fatal("runApprovalCheck accepted a file over the 1 MiB limit")
	}
}

func TestApprovalCheckUsage(t *testing.T) {
	if err := runApprovalCheck(nil); err == nil {
		t.Error("runApprovalCheck accepted no arguments")
	}
	if err := runApprovalCheck([]string{"a", "b"}); err == nil {
		t.Error("runApprovalCheck accepted two arguments")
	}
}

// approvalReply builds a raw .eml-shaped message with a Date close
// enough to time.Now() to pass approvalHandler's one-hour
// approvalMaxAge (unlike this file's unsignedReply constant, which is
// dated for runApprovalCheck's much wider thirty-day checkMaxAge and
// would otherwise be rejected here for being stale rather than for
// whatever the test is actually trying to prove).
func approvalReply(from, subject, messageID string) []byte {
	date := time.Now().UTC().Format(time.RFC1123Z)
	return []byte("From: " + from + "\r\n" +
		"To: birdcage@example.net\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + date + "\r\n" +
		"Message-ID: " + messageID + "\r\n" +
		"\r\n" +
		"Yes, go ahead.\r\n")
}

// approvalReplyNoMessageID is the same shape with no Message-ID header
// at all, for TestApprovalHandlerIgnoresMessageWithNoMessageID.
func approvalReplyNoMessageID(from, subject string) []byte {
	date := time.Now().UTC().Format(time.RFC1123Z)
	return []byte("From: " + from + "\r\n" +
		"To: birdcage@example.net\r\n" +
		"Subject: " + subject + "\r\n" +
		"Date: " + date + "\r\n" +
		"\r\n" +
		"Yes, go ahead.\r\n")
}

// setAdminApprovalAddress is pinAdminAddress with a caller-chosen
// address, for tests that need the pinned address to differ from (or
// match) a specific message's From.
func setAdminApprovalAddress(t *testing.T, address string) {
	t.Helper()
	if _, err := captureStdout(t, func() error {
		return runSettingsSet([]string{string(store.SettingAdminApprovalAddress), address})
	}); err != nil {
		t.Fatalf("set %s: %v", store.SettingAdminApprovalAddress, err)
	}
}

// TestApprovalHandlerRejectsWrongAddress is approvalHandler's first
// job: a reply from anyone but the pinned administrator is rejected,
// not merely ignored -- it is written to the approvals table as a
// rejection, verified() false, with a reason naming the address that
// was actually seen. The From/pinned-address check runs before any
// DKIM lookup (internal/agent/approval.Verify checks From right after
// parsing), so this needs no signature and no network access to prove.
func TestApprovalHandlerRejectsWrongAddress(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	setAdminApprovalAddress(t, "right-admin@example.net")

	handler := approvalHandler(database, logging.New("approval-test"))
	raw := approvalReply("Someone Else <attacker@evil.example.net>",
		"Re: [birdcage u-wrong-addr] upgrade mockingbird", "<wrong-addr-1@example.net>")

	if err := handler(context.Background(), raw); err != nil {
		t.Fatalf("approvalHandler returned an error for a message that should be recorded as rejected, not error out: %v", err)
	}

	rec, err := store.ApprovalByReference(context.Background(), database, "u-wrong-addr")
	if err != nil {
		t.Fatalf("store.ApprovalByReference: %v", err)
	}
	if rec == nil {
		t.Fatal("no approval row was recorded for the wrong-address message")
	}
	if rec.Verified() {
		t.Fatal("a message from the wrong address was recorded as verified")
	}
	if rec.RejectReason == nil || !strings.Contains(*rec.RejectReason, "attacker@evil.example.net") {
		t.Errorf("RejectReason = %v, want it to name the address the message actually came from", rec.RejectReason)
	}
}

// TestApprovalHandlerRejectsAndRecordsAnUnsignedMessageFromTheRightAddress
// covers the other half of "rejected, and the outcome is recorded":
// the From address matches the pinned administrator, but the message
// carries no DKIM signature at all, so it is rejected for that reason
// instead -- and still ends up as a row, not silently dropped.
func TestApprovalHandlerRejectsAndRecordsAnUnsignedMessageFromTheRightAddress(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	setAdminApprovalAddress(t, "admin@example.net")

	handler := approvalHandler(database, logging.New("approval-test"))
	raw := approvalReply("Birdcage Admin <admin@example.net>",
		"Re: [birdcage u-unsigned] upgrade mockingbird", "<unsigned-1@example.net>")

	if err := handler(context.Background(), raw); err != nil {
		t.Fatalf("approvalHandler returned an error for a message that should be recorded as rejected, not error out: %v", err)
	}

	rec, err := store.ApprovalByReference(context.Background(), database, "u-unsigned")
	if err != nil {
		t.Fatalf("store.ApprovalByReference: %v", err)
	}
	if rec == nil {
		t.Fatal("no approval row was recorded for the unsigned message")
	}
	if rec.Verified() {
		t.Fatal("an unsigned message was recorded as verified")
	}
	if rec.RejectReason == nil || !strings.Contains(*rec.RejectReason, "DKIM signature") {
		t.Errorf("RejectReason = %v, want it to mention the missing DKIM signature", rec.RejectReason)
	}
	// A rejected message keeps the raw From header as it arrived
	// (record.FromAddress is only overwritten with the parsed address
	// on the verified path) -- still enough to show which header the
	// rejection was actually about.
	if rec.FromAddress != "Birdcage Admin <admin@example.net>" {
		t.Errorf("FromAddress = %q, want the raw From header the message carried", rec.FromAddress)
	}
}

// TestApprovalHandlerIgnoresMessageWithNoMessageID is the safety branch
// approvalHandler's own comment describes: a message with no
// Message-ID has nothing to key a replay check on, so it is logged and
// dropped rather than stored under an empty key that a second, unrelated
// message with no Message-ID of its own would collide with.
func TestApprovalHandlerIgnoresMessageWithNoMessageID(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	setAdminApprovalAddress(t, "admin@example.net")

	handler := approvalHandler(database, logging.New("approval-test"))
	raw := approvalReplyNoMessageID("Birdcage Admin <admin@example.net>",
		"Re: [birdcage u-no-msgid] upgrade mockingbird")

	if err := handler(context.Background(), raw); err != nil {
		t.Fatalf("approvalHandler returned an error for a message with no Message-ID, want it silently ignored: %v", err)
	}

	rec, err := store.ApprovalByReference(context.Background(), database, "u-no-msgid")
	if err != nil {
		t.Fatalf("store.ApprovalByReference: %v", err)
	}
	if rec != nil {
		t.Fatalf("a message with no Message-ID was recorded anyway: %+v", rec)
	}
}

// TestApprovalHandlerReturnsAnErrorWhenRecordingFails is approvalHandler's
// third outcome: a message that cannot be stored (here, because the
// approvals table itself is gone) must return an error, so the mailbox
// poll leaves it unread and owes it again next time -- rather than
// silently treating a storage failure as "nothing to do".
func TestApprovalHandlerReturnsAnErrorWhenRecordingFails(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	setAdminApprovalAddress(t, "admin@example.net")
	if _, err := database.Exec(`DROP TABLE approvals`); err != nil {
		t.Fatalf("drop approvals table: %v", err)
	}
	defer closeCanaryDB(database)

	handler := approvalHandler(database, logging.New("approval-test"))
	raw := approvalReply("Birdcage Admin <admin@example.net>",
		"Re: [birdcage u-store-fail] upgrade mockingbird", "<store-fail-1@example.net>")

	if err := handler(context.Background(), raw); err == nil {
		t.Fatal("approvalHandler succeeded despite the approvals table being gone, want an error")
	}
}

// The "accepted" outcome -- a message whose DKIM signature actually
// verifies -- is deliberately not covered here. approvalHandler wires
// approval.Verify to net.LookupTXT directly (not an injectable
// resolver, unlike internal/agent/approval's own tests, which stub
// DNS), the same deliberate choice runApprovalCheck's doc comment
// explains: "the whole point ... is to try a real provider's signature
// against the key it actually published." Producing a real, valid DKIM
// signature needs a private key whose public half is published in real
// DNS for a domain this project controls, which does not exist as a
// test fixture and should not be faked. internal/agent/approval's own
// test suite (TestVerifyAcceptsRSASignedApproval etc.) already proves
// Verify's accept path against stubbed DNS; what is untested is only
// the wiring from approvalHandler to a real net.LookupTXT, which cannot
// be exercised without a real signed message from a real domain.

func pinAdminAddress(t *testing.T) {
	t.Helper()
	if _, err := captureStdout(t, func() error {
		return runSettingsSet([]string{"admin_approval_address", "admin@example.net"})
	}); err != nil {
		t.Fatalf("set admin_approval_address: %v", err)
	}
}

// The header helpers read a message that may already have failed to
// parse, so what they do with folding and with the header/body boundary
// is worth pinning: a "Subject:" line in the body must never be read as
// the subject.
func TestHeaderHelpers(t *testing.T) {
	raw := []byte("From: Admin <admin@example.net>\r\n" +
		"Subject: Re: [birdcage u-1]\r\n" +
		" upgrade mockingbird\r\n" +
		"Message-ID: <abc@example.net>\r\n" +
		"\r\n" +
		"Subject: not this one\r\n")

	if got, want := subjectOf(raw), "Re: [birdcage u-1] upgrade mockingbird"; got != want {
		t.Errorf("subjectOf = %q, want the folded line joined: %q", got, want)
	}
	if got, want := fromOf(raw), "Admin <admin@example.net>"; got != want {
		t.Errorf("fromOf = %q, want %q", got, want)
	}
	if got, want := messageIDOf(raw), "<abc@example.net>"; got != want {
		t.Errorf("messageIDOf = %q, want %q", got, want)
	}
	if got := firstHeader(raw, "date"); got != "" {
		t.Errorf("firstHeader for an absent header = %q, want empty", got)
	}
	// Bare LF, as a file saved by hand may well have.
	lf := []byte("subject: hello\n\nbody\n")
	if got := subjectOf(lf); got != "hello" {
		t.Errorf("subjectOf on a bare-LF message = %q, want %q", got, "hello")
	}
}
