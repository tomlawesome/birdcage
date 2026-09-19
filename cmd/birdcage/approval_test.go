package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/logging"
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
