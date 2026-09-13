// Package dbtest gives internal/db's and internal/store's own tests a
// way to run against every database engine birdcage supports, per issue
// #7: SQLite always, and Postgres too when a real instance is available
// via BIRDCAGE_TEST_DATABASE_URL.
package dbtest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// EnvPostgresURL is the environment variable that, when set to a
// Postgres DATABASE_URL, adds a Postgres target to Targets. Unset (the
// default on a machine without a Postgres instance handy), only SQLite
// runs.
const EnvPostgresURL = "BIRDCAGE_TEST_DATABASE_URL"

// Target is one database engine a test runs against.
type Target struct {
	Name string
	DB   *db.DB
}

// Targets returns the database engines the calling test should run
// against: always a fresh, migrated SQLite temp-file database, and
// additionally a freshly created, migrated Postgres database (against
// BIRDCAGE_TEST_DATABASE_URL, whose own database name is treated as the
// admin connection this creates a throwaway database alongside, one per
// call -- see openPostgres) when that variable is set. When it is
// unset, logs one line saying Postgres was skipped.
//
// A fresh Postgres *database*, not merely truncated tables in a shared
// one, is what each call gets: go test runs different packages'
// tests concurrently by default, and internal/db's own tests and
// internal/store's both open Postgres targets against the same
// BIRDCAGE_TEST_DATABASE_URL, so anything less than full isolation lets
// one package's rows or truncation land mid-test in another's (observed
// directly: a table this function's caller had just populated came back
// with one row instead of ten, right after a concurrent package's
// dbtest.Targets call truncated it).
//
// Callers loop over the result with t.Run so a Postgres-only failure
// doesn't hide behind (or get masked by) the SQLite result:
//
//	for _, tgt := range dbtest.Targets(t) {
//	    t.Run(tgt.Name, func(t *testing.T) { ... use tgt.DB ... })
//	}
func Targets(t *testing.T) []Target {
	t.Helper()
	targets := []Target{{Name: "sqlite", DB: openSQLite(t)}}

	adminURL := os.Getenv(EnvPostgresURL)
	if adminURL == "" {
		t.Log("dbtest: BIRDCAGE_TEST_DATABASE_URL not set, skipping Postgres")
		return targets
	}
	targets = append(targets, Target{Name: "postgres", DB: openPostgres(t, adminURL)})
	return targets
}

func openSQLite(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "birdcage-test.db"))
	if err != nil {
		t.Fatalf("dbtest: open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("dbtest: close sqlite: %v", err)
		}
	})
	if err := db.Migrate(context.Background(), database); err != nil {
		t.Fatalf("dbtest: migrate sqlite: %v", err)
	}
	return database
}

// openPostgres connects to adminURL (whatever database
// BIRDCAGE_TEST_DATABASE_URL names -- typically the server's default
// "postgres" database), creates a throwaway database with a unique
// name, connects to that instead, applies migrations, and registers a
// cleanup that drops it. Each call is therefore fully isolated from
// every other test or package using the same admin URL, rather than
// sharing one set of tables that concurrent test binaries could
// truncate out from under each other.
func openPostgres(t *testing.T, adminURL string) *db.DB {
	t.Helper()
	ctx := context.Background()

	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Fatalf("dbtest: open postgres admin connection: %v", err)
	}
	// One Cleanup, not two: admin must stay open for the drop below,
	// which only t.Cleanup (not a plain defer, which would run and close
	// it before the test itself finishes) can order correctly -- and
	// registering "drop" and "close" as separate Cleanups would run
	// them last-registered-first, closing admin before the drop.
	closeAdmin := true
	defer func() {
		if closeAdmin {
			_ = admin.Close() // t.Fatalf already fired; nothing left to report
		}
	}()

	name := fmt.Sprintf("birdcage_test_%d_%d", os.Getpid(), time.Now().UnixNano())
	// CREATE/DROP DATABASE can't run inside a transaction block; a bare
	// Exec on *sql.DB is autocommit, so this is fine as-is.
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		t.Fatalf("dbtest: create database %s: %v", name, err)
	}
	closeAdmin = false // ownership moves to the Cleanup below
	t.Cleanup(func() {
		defer func() {
			if err := admin.Close(); err != nil {
				t.Errorf("dbtest: close admin connection: %v", err)
			}
		}()
		// -- FORCE (Postgres 13+) drops even if something is still
		// connected, so a test's own leftover connections (closed by an
		// earlier t.Cleanup, but the server can lag) never leave the
		// throwaway database stranded.
		if _, err := admin.ExecContext(context.Background(),
			`DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`); err != nil {
			t.Errorf("dbtest: drop database %s: %v", name, err)
		}
	})

	dbURL, err := withDatabaseName(adminURL, name)
	if err != nil {
		t.Fatalf("dbtest: build URL for database %s: %v", name, err)
	}

	database, err := db.Open(dbURL)
	if err != nil {
		t.Fatalf("dbtest: open postgres database %s: %v", name, err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("dbtest: close postgres: %v", err)
		}
	})
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("dbtest: migrate postgres database %s: %v", name, err)
	}
	return database
}

// withDatabaseName returns rawURL with its path (the database name)
// replaced by name.
func withDatabaseName(rawURL, name string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	return u.String(), nil
}

// quoteIdent double-quotes a Postgres identifier for use in DDL where a
// bound parameter isn't allowed (CREATE/DROP DATABASE takes no
// placeholders). name is always this package's own generated
// "birdcage_test_<pid>_<nanotime>" -- never external input -- so the
// only thing quoting needs to defend against is a literal `"` in that
// name, which doubling handles per standard SQL identifier escaping.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
