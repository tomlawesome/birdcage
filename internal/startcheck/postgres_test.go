package startcheck

import (
	"errors"
	"strings"
	"testing"
)

func TestPostgresRequiresVerifyFullAcceptsVerifyFull(t *testing.T) {
	err := PostgresRequiresVerifyFull("postgres://u:p@host:5432/db?sslmode=verify-full")
	if err != nil {
		t.Fatalf("sslmode=verify-full: got %v, want nil", err)
	}
}

// TestPostgresRequiresVerifyFullRefusesEveryWeakerMode is issue #84's core
// requirement: verify-full is the only accepted mode, and each of pgx's
// other four sslmodes -- including verify-ca, which does encrypt, just
// without checking the hostname -- is refused the same way, naming
// sslmode=verify-full as the fix.
func TestPostgresRequiresVerifyFullRefusesEveryWeakerMode(t *testing.T) {
	modes := []string{"disable", "allow", "prefer", "require", "verify-ca"}
	for _, mode := range modes {
		url := "postgres://u:p@host:5432/db?sslmode=" + mode
		err := PostgresRequiresVerifyFull(url)
		if !errors.Is(err, ErrPostgresRequiresVerifyFull) {
			t.Errorf("sslmode=%s: got %v, want ErrPostgresRequiresVerifyFull", mode, err)
			continue
		}
		if !strings.Contains(err.Error(), "sslmode=verify-full") {
			t.Errorf("sslmode=%s: error %q does not name the fix (sslmode=verify-full)", mode, err.Error())
		}
	}
}

// TestPostgresRequiresVerifyFullRefusesNoSslmode covers a URL with no
// sslmode at all: pgx defaults an absent sslmode to "prefer" (see
// pgconn/config.go's configTLS), which still falls back to plaintext, so
// omitting the setting entirely must refuse exactly like writing
// sslmode=prefer would.
func TestPostgresRequiresVerifyFullRefusesNoSslmode(t *testing.T) {
	err := PostgresRequiresVerifyFull("postgres://u:p@host:5432/db")
	if !errors.Is(err, ErrPostgresRequiresVerifyFull) {
		t.Fatalf("no sslmode: got %v, want ErrPostgresRequiresVerifyFull", err)
	}
}

// TestPostgresRequiresVerifyFullRefusesAMalformedURL covers a postgres://
// URL pgconn cannot parse at all -- refused with its own message rather
// than the sslmode one (there's no sslmode to have gotten wrong), and
// without embedding pgx's own parse error, which can still carry the DSN
// -- and the password in it -- despite pgx's best-effort redaction.
func TestPostgresRequiresVerifyFullRefusesAMalformedURL(t *testing.T) {
	cases := []string{
		"postgres://u:p@host:not-a-port/db",
		"postgres://[::1",
	}
	for _, url := range cases {
		err := PostgresRequiresVerifyFull(url)
		if err == nil {
			t.Errorf("%q: got nil, want a refusal", url)
			continue
		}
		if !errors.Is(err, errPostgresURLInvalid) {
			t.Errorf("%q: got %v, want errPostgresURLInvalid", url, err)
		}
	}
}

// TestPostgresRequiresVerifyFullAcceptsNonPostgresURLs covers every form
// internal/db.Open treats as SQLite, per issue #84's scope: TLS is a
// Postgres-transport property, so none of these are this check's concern.
func TestPostgresRequiresVerifyFullAcceptsNonPostgresURLs(t *testing.T) {
	cases := []string{
		"",
		"sqlite:/tmp/does-not-need-to-exist.db",
		"/var/lib/birdcage/birdcage.db",
		"birdcage.db",
	}
	for _, url := range cases {
		if err := PostgresRequiresVerifyFull(url); err != nil {
			t.Errorf("%q: got %v, want nil (not a postgres URL)", url, err)
		}
	}
}
