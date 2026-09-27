// Package dbtest gives internal/db's and internal/store's own tests a
// way to run against every database engine birdcage supports, per issue
// #7: SQLite always, and Postgres too when a real instance is available
// via BIRDCAGE_TEST_DATABASE_URL.
package dbtest

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
// Every call gets its own database, isolated from every other test:
// each engine below clones a template that is migrated once per test
// binary (issue #138) rather than running every migration again per
// call -- SQLite by copying a template file, Postgres with
// CREATE DATABASE ... TEMPLATE, which Postgres itself implements as a
// file-level copy rather than a migration replay. A fresh Postgres
// *database*, not merely truncated tables in a shared one, is what each
// call gets: go test runs different packages' tests concurrently by
// default, and internal/db's own tests and internal/store's both open
// Postgres targets against the same BIRDCAGE_TEST_DATABASE_URL, so
// anything less than full isolation lets one package's rows or
// truncation land mid-test in another's (observed directly: a table
// this function's caller had just populated came back with one row
// instead of ten, right after a concurrent package's dbtest.Targets
// call truncated it).
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

// sqliteTemplateOnce, sqliteTemplatePath and sqliteTemplateErr hold the
// SQLite template file migrated once per test binary process -- see
// sqliteTemplate.
var (
	sqliteTemplateOnce sync.Once
	sqliteTemplatePath string
	sqliteTemplateErr  error
)

// sqliteTemplate returns the path of a fully migrated SQLite database
// file, migrating it into existence on the first call and reusing that
// same file for every later call in this process. openSQLite clones it
// per test instead of migrating from scratch each time, which is what
// made internal/store's suite slow (issue #138): with ~25 migrations
// and 183 call sites in that package alone, migrating twice per call
// (SQLite and Postgres) dominated the package's runtime.
//
// The file is deliberately never removed by a t.Cleanup: a test's
// Cleanup runs when that test finishes, but later tests in the same
// binary still need to clone this file, and there is no hook that fires
// once per binary without adding a TestMain to every package that
// imports dbtest. It is one small SQLite file, named by this process's
// pid so concurrent packages' test binaries never collide, and CI's
// runner discards the whole filesystem at the end of the job.
func sqliteTemplate(t *testing.T) string {
	t.Helper()
	sqliteTemplateOnce.Do(func() {
		path := filepath.Join(os.TempDir(), fmt.Sprintf("birdcage-dbtest-template-%d.db", os.Getpid()))
		database, err := db.Open(path)
		if err != nil {
			sqliteTemplateErr = fmt.Errorf("open sqlite template: %w", err)
			return
		}
		defer func() { _ = database.Close() }()
		if err := db.Migrate(context.Background(), database); err != nil {
			sqliteTemplateErr = fmt.Errorf("migrate sqlite template: %w", err)
			return
		}
		sqliteTemplatePath = path
	})
	if sqliteTemplateErr != nil {
		t.Fatalf("dbtest: %v", sqliteTemplateErr)
	}
	return sqliteTemplatePath
}

func openSQLite(t *testing.T) *db.DB {
	t.Helper()
	template := sqliteTemplate(t)

	path := filepath.Join(t.TempDir(), "birdcage-test.db")
	if err := copyFile(template, path); err != nil {
		t.Fatalf("dbtest: clone sqlite template: %v", err)
	}

	database, err := db.Open(path)
	if err != nil {
		t.Fatalf("dbtest: open sqlite: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("dbtest: close sqlite: %v", err)
		}
	})
	return database
}

// copyFile copies src to dst, overwriting dst if it already exists.
// db.Open's SQLite driver uses the default rollback-journal mode (see
// internal/db's openSQLite), which leaves no -wal/-shm sidecar file
// once a connection has cleanly closed, so a plain byte-for-byte copy
// of the template's single file is a complete, independent clone.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// pgTemplateOnce, pgTemplateName and pgTemplateErr hold the name of the
// Postgres template database migrated once per test binary process --
// see pgTemplate. The template mirrors sqliteTemplate's tradeoff: it is
// never dropped by a t.Cleanup, for the same reason (no hook fires once
// per binary), and for the same reason it is harmless -- CI's Postgres
// service container is discarded with the job, and a database left
// behind against a persistent local Postgres is one throwaway database
// per test-binary run, named by pid.
var (
	pgTemplateOnce sync.Once
	pgTemplateName string
	pgTemplateErr  error
)

// pgTemplate returns the name of a fully migrated Postgres database,
// creating and migrating it on the first call in this process and
// reusing that same database (as a CREATE DATABASE ... TEMPLATE source,
// never written to again) for every later call. openPostgres clones it
// per test with CREATE DATABASE ... TEMPLATE, which Postgres itself
// implements as a file-level copy of the template's data directory
// entries rather than a migration replay -- see sqliteTemplate's doc
// comment for why this matters (issue #138).
func pgTemplate(t *testing.T, adminURL string) string {
	t.Helper()
	pgTemplateOnce.Do(func() {
		ctx := context.Background()

		admin, err := sql.Open("pgx", adminURL)
		if err != nil {
			pgTemplateErr = fmt.Errorf("open postgres admin connection: %w", err)
			return
		}
		defer func() { _ = admin.Close() }()

		name := fmt.Sprintf("birdcage_test_template_%d", os.Getpid())
		if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+quoteIdent(name)); err != nil {
			pgTemplateErr = fmt.Errorf("create template database %s: %w", name, err)
			return
		}

		dbURL, err := withDatabaseName(adminURL, name)
		if err != nil {
			pgTemplateErr = fmt.Errorf("build URL for template database %s: %w", name, err)
			return
		}
		database, err := db.Open(dbURL)
		if err != nil {
			pgTemplateErr = fmt.Errorf("open template database %s: %w", name, err)
			return
		}
		migrateErr := db.Migrate(ctx, database)
		closeErr := database.Close()
		switch {
		case migrateErr != nil:
			pgTemplateErr = fmt.Errorf("migrate template database %s: %w", name, migrateErr)
			return
		case closeErr != nil:
			// CREATE DATABASE ... TEMPLATE refuses while any session is
			// connected to the template, so this connection must be
			// fully closed -- not merely idle in a pool -- before the
			// first clone below can succeed.
			pgTemplateErr = fmt.Errorf("close template database %s: %w", name, closeErr)
			return
		}
		pgTemplateName = name
	})
	if pgTemplateErr != nil {
		t.Fatalf("dbtest: %v", pgTemplateErr)
	}
	return pgTemplateName
}

// openPostgres connects to adminURL (whatever database
// BIRDCAGE_TEST_DATABASE_URL names -- typically the server's default
// "postgres" database), creates a throwaway database with a unique
// name as a clone of the migrated template (see pgTemplate), connects
// to that instead, and registers a cleanup that drops it. Each call is
// therefore fully isolated from every other test or package using the
// same admin URL, rather than sharing one set of tables that concurrent
// test binaries could truncate out from under each other.
func openPostgres(t *testing.T, adminURL string) *db.DB {
	t.Helper()
	ctx := context.Background()
	template := pgTemplate(t, adminURL)

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
	if _, err := admin.ExecContext(ctx,
		`CREATE DATABASE `+quoteIdent(name)+` TEMPLATE `+quoteIdent(template)); err != nil {
		t.Fatalf("dbtest: create database %s from template %s: %v", name, template, err)
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
	// database is already migrated: it was cloned from pgTemplate above,
	// not created fresh, so there is nothing left to apply here.
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
// placeholders). Every name this package builds is its own generated
// "birdcage_test_..." string -- never external input -- so the only
// thing quoting needs to defend against is a literal `"` in that name,
// which doubling handles per standard SQL identifier escaping.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
