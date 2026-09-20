package startcheck

import (
	"crypto/tls"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// ErrPostgresRequiresVerifyFull is returned by PostgresRequiresVerifyFull
// for a DATABASE_URL that could connect to Postgres without authenticating
// the server. Issue #84: that database holds every canary's bearer-token
// hash, the CA, enrolment sessions and the whole alert history, so a link
// to it that could run in the clear -- or encrypt without checking who it
// is actually talking to -- is a plain read of the product's secrets by
// anything on the path, or by an attacker impersonating the server.
//
// Of pgx's five sslmodes, only "verify-full" authenticates the server: it
// is the only one that both requires TLS and checks the certificate
// against the hostname. "require" and "verify-ca" encrypt but do not check
// the hostname, so any certificate trusted by the root store (or, for
// "require" with no root configured, any certificate at all) is accepted
// from whoever answers on the wire. "prefer" and "allow" fall back to
// plaintext outright if the server declines TLS. Birdcage requires
// "verify-full" specifically and refuses the other four unconditionally --
// this is a fixed policy, not something a deployment can opt down from
// with a documented reason.
//
// This mirrors mikroview's internal/persist.requireTLS, which solved the
// same problem first for a sibling project's Postgres backend, except
// mikroview accepts "require" and "verify-ca" too as a deliberately looser
// default for its own database. Birdcage's holds bearer-token hashes and a
// CA, so issue #84 pins the requirement at "verify-full" alone.
var ErrPostgresRequiresVerifyFull = errors.New(
	"startcheck: DATABASE_URL must set sslmode=verify-full -- it is the only Postgres " +
		"sslmode that authenticates the server (checks the certificate against the " +
		"hostname); sslmode=require and verify-ca encrypt without that check, and " +
		"disable/allow/prefer can fall back to an unencrypted connection. This database " +
		"holds canary bearer-token hashes, the CA, enrolment sessions and the whole " +
		"alert history, so nothing weaker is accepted.",
)

// errPostgresURLInvalid is returned instead of wrapping pgconn's own parse
// error, which can still carry the connection string -- and the password
// inside it -- even though pgx redacts recognizable passwords in it on a
// best-effort basis (see pgconn.ParseConfigError). Nothing from the
// underlying error reaches this message or, from there, a log line.
var errPostgresURLInvalid = errors.New(
	"startcheck: DATABASE_URL is not a valid postgres connection string",
)

// PostgresRequiresVerifyFull refuses a databaseURL that could ever connect
// to Postgres without authenticating the server, per issue #84 (see
// ErrPostgresRequiresVerifyFull for the reasoning). Called from
// cmd/birdcage before db.Open, alongside issue #70's other start-up
// refusals in this package: db.Open's sql.Open does no network I/O, so
// without this check the same misconfiguration would otherwise only
// surface on the first query, deep inside pgx, rather than failing here
// before any listener binds.
//
// A databaseURL that does not select the Postgres engine (unset, a bare
// path, or "sqlite:PATH" -- see internal/db.Open, whose dispatch this
// mirrors) is not this check's concern and always passes: TLS is a
// property of the Postgres transport, not something SQLite has.
//
// This inspects what pgx will actually *do* with databaseURL, via
// pgconn.ParseConfig, rather than pattern-matching "sslmode=" in the URL
// text -- the same choice mikroview's requireTLS makes, and for the same
// reason: the mode can also arrive via a PGSSLMODE environment variable or
// a service file pgconn resolves for itself, neither of which is visible
// by reading the URL alone.
func PostgresRequiresVerifyFull(databaseURL string) error {
	if !isPostgresURL(databaseURL) {
		return nil
	}

	cfg, err := pgconn.ParseConfig(databaseURL)
	if err != nil {
		return errPostgresURLInvalid
	}

	if !authenticatesServer(cfg.TLSConfig) {
		return ErrPostgresRequiresVerifyFull
	}
	// Fallbacks are additional (host, TLS config) pairs pgx will also try
	// -- populated for multiple hosts in one URL, and for "prefer"/"allow"
	// mode's plaintext alternative (already caught above via cfg.TLSConfig,
	// since that's always the first candidate pgx tries; checked again
	// here defensively rather than assumed to always be redundant).
	for _, fb := range cfg.Fallbacks {
		if !authenticatesServer(fb.TLSConfig) {
			return ErrPostgresRequiresVerifyFull
		}
	}
	return nil
}

// authenticatesServer reports whether tlsCfg is what pgx builds for
// sslmode=verify-full specifically: present, and verifying the full
// certificate chain against the hostname (InsecureSkipVerify false).
// Every other sslmode either leaves tlsCfg nil (disable, and allow's first
// attempt) or sets InsecureSkipVerify true (allow's fallback, prefer,
// require, verify-ca) -- measured against pgx v5's pgconn/config.go
// configTLS, not assumed.
func authenticatesServer(tlsCfg *tls.Config) bool {
	return tlsCfg != nil && !tlsCfg.InsecureSkipVerify
}

// isPostgresURL reports whether databaseURL selects the Postgres engine --
// the same two schemes internal/db.Open dispatches on. Duplicated here
// rather than imported from internal/db so this package, which
// cmd/birdcage calls before opening anything, doesn't have to pull in
// db's own driver dependencies (modernc.org/sqlite) just to ask this
// question.
func isPostgresURL(databaseURL string) bool {
	return strings.HasPrefix(databaseURL, "postgres://") || strings.HasPrefix(databaseURL, "postgresql://")
}
