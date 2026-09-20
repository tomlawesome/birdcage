package main

import (
	"strings"
	"testing"
)

// TestRedactDatabaseURL is SECURITY.md's "never logged" rule for
// credentials, proved for the one function that stands between a
// DATABASE_URL and the log line main.go prints it to (main.go's own
// envDatabaseURL config-inventory line, around line 426).
//
// Every case asserts the secret's *absence* from the result, not just
// equality with one expected string: an equality check against a fixed
// "postgres://REDACTED@..." string would still pass if someone changed
// the redaction to some other value that happened to leak the password
// a different way (e.g. moving it into the query string).
func TestRedactDatabaseURL(t *testing.T) {
	const (
		user     = "alice"
		password = "s3cret-do-not-log-ZZZZ"
	)

	cases := []struct {
		name string
		raw  string
	}{
		{"user and password", "postgres://" + user + ":" + password + "@db.example.net:5432/birdcage?sslmode=disable"},
		{"user, no password", "postgres://" + user + "@db.example.net:5432/birdcage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := redactDatabaseURL(c.raw)
			if got == c.raw {
				t.Fatalf("redactDatabaseURL(%q) = %q, unchanged -- userinfo was not stripped", c.raw, got)
			}
			for _, secret := range []string{password, user} {
				if strings.Contains(got, secret) {
					t.Errorf("redactDatabaseURL(%q) = %q, still contains %q", c.raw, got, secret)
				}
			}
			if !strings.Contains(got, "REDACTED") {
				t.Errorf("redactDatabaseURL(%q) = %q, want it to say REDACTED somewhere", c.raw, got)
			}
			// The host and path are not secret and are what an operator
			// needs to confirm which database this is -- they must
			// survive redaction.
			if !strings.Contains(got, "db.example.net") || !strings.Contains(got, "birdcage") {
				t.Errorf("redactDatabaseURL(%q) = %q, lost non-secret routing information", c.raw, got)
			}
		})
	}

	t.Run("no userinfo at all", func(t *testing.T) {
		const raw = "postgres://db.example.net:5432/birdcage"
		if got := redactDatabaseURL(raw); got != raw {
			t.Errorf("redactDatabaseURL(%q) = %q, want it unchanged (nothing to redact)", raw, got)
		}
	})

	t.Run("bare sqlite path passes through unchanged", func(t *testing.T) {
		for _, raw := range []string{"birdcage.db", "/var/lib/birdcage/birdcage.db"} {
			if got := redactDatabaseURL(raw); got != raw {
				t.Errorf("redactDatabaseURL(%q) = %q, want a bare path unchanged", raw, got)
			}
		}
	})

	t.Run("unparseable value becomes the fixed placeholder", func(t *testing.T) {
		// url.Parse rejects an unterminated IPv6 host literal.
		const raw = "postgres://" + user + ":" + password + "@[::1"
		got := redactDatabaseURL(raw)
		if got != "(unparseable)" {
			t.Errorf("redactDatabaseURL(%q) = %q, want the fixed placeholder %q", raw, got, "(unparseable)")
		}
		if strings.Contains(got, password) {
			t.Errorf("redactDatabaseURL(%q) = %q, leaked the password even though it did not parse", raw, got)
		}
	})
}
