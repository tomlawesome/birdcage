package main

import (
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/logging"
)

// TestLoadMailConfigNeverLogsThePassword is the one thing this wrapper
// exists to get right: it prints an inventory line so an operator can
// see where mail is going, and that line must not carry the credential.
// The value below is a literal, obviously-fake placeholder.
func TestLoadMailConfigNeverLogsThePassword(t *testing.T) {
	const password = "not-a-real-password-ZZZZ"
	t.Setenv("BIRDCAGE_MAIL_HOST", "smtp.example.invalid:465")
	t.Setenv("BIRDCAGE_MAIL_USERNAME", "birdcage@example.invalid")
	t.Setenv("BIRDCAGE_MAIL_PASSWORD", password)
	t.Setenv("BIRDCAGE_MAIL_FROM", "birdcage@example.invalid")
	t.Setenv("BIRDCAGE_MAIL_TO", "admin@example.invalid")

	out, _ := captureStdout(t, func() error {
		cfg, enabled := loadMailConfig(logging.New("mail"))
		if !enabled {
			t.Error("enabled = false for a complete configuration")
		}
		if cfg.Password != password {
			t.Error("the password did not reach the configuration")
		}
		return nil
	})

	if strings.Contains(out, password) {
		t.Errorf("the boot inventory printed the password")
	}
	for _, want := range []string{"smtp.example.invalid:465", "implicit TLS", "admin@example.invalid", "BIRDCAGE_MAIL_PASSWORD"} {
		if !strings.Contains(out, want) {
			t.Errorf("the boot inventory does not mention %q:\n%s", want, out)
		}
	}
}

func TestLoadMailConfigOffWhenNothingIsSet(t *testing.T) {
	for _, name := range []string{
		"BIRDCAGE_MAIL_HOST", "BIRDCAGE_MAIL_STARTTLS", "BIRDCAGE_MAIL_USERNAME",
		"BIRDCAGE_MAIL_PASSWORD_FILE", "BIRDCAGE_MAIL_PASSWORD", "BIRDCAGE_MAIL_FROM", "BIRDCAGE_MAIL_TO",
	} {
		t.Setenv(name, "")
	}
	out, _ := captureStdout(t, func() error {
		if _, enabled := loadMailConfig(logging.New("mail")); enabled {
			t.Error("enabled = true with no mail variables set")
		}
		return nil
	})
	if !strings.Contains(out, "outbound mail disabled") {
		t.Errorf("no line saying mail is off:\n%s", out)
	}
}
