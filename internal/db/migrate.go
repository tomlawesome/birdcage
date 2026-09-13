package db

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"time"
)

//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrationFiles embed.FS

const createSchemaMigrations = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
)`

// migrationsDir returns the embedded subdirectory Migrate reads
// migration files from for engine.
func migrationsDir(engine Engine) string {
	if engine == Postgres {
		return "migrations/postgres"
	}
	return "migrations/sqlite"
}

// MigrationNames returns the sorted list of migration filenames the
// given engine's directory contains. Migrate uses it to know what to
// apply; TestMigrationDirectoriesMatch (migrate_test.go) uses it to
// assert the two engines' sets of names are identical -- a migration
// that exists on only one engine is a defect per issue #7.
func MigrationNames(engine Engine) ([]string, error) {
	entries, err := migrationFiles.ReadDir(migrationsDir(engine))
	if err != nil {
		return nil, fmt.Errorf("list migrations for %s: %w", engine, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// migrationLockKey is an arbitrary, fixed pg_advisory_lock key
// identifying "a birdcage process is running migrations". It has no
// meaning beyond being stable across processes and versions.
const migrationLockKey = 875301442

// Migrate applies every embedded migration for database.Engine, in
// filename order. Applied migrations are recorded in schema_migrations
// and skipped on subsequent calls, so Migrate is safe to run on every
// process start -- including two birdcage processes (or, as happens in
// this package's own test suite, two test binaries) starting against
// the same Postgres database at once: SQLite only ever sees one
// process per file, but Postgres does not, and concurrent CREATE
// TABLE/FUNCTION statements from separate connections can otherwise
// race on Postgres' own catalog (observed directly: "duplicate key
// value violates unique constraint pg_type_typname_nsp_index" when two
// Migrate calls ran at once against a shared instance). A Postgres
// session-level advisory lock, held for this call's whole duration on
// one dedicated connection, serializes them; SQLite needs no such
// guard.
func Migrate(ctx context.Context, database *DB) error {
	if database.Engine == Postgres {
		unlock, err := lockPostgresMigrations(ctx, database)
		if err != nil {
			return err
		}
		defer unlock()
	}

	names, err := MigrationNames(database.Engine)
	if err != nil {
		return err
	}

	if _, err := database.ExecContext(ctx, createSchemaMigrations); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, name := range names {
		applied, err := migrationApplied(ctx, database, name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		if err := applyMigration(ctx, database, name); err != nil {
			return err
		}
	}
	return nil
}

// lockPostgresMigrations acquires migrationLockKey as a session-level
// advisory lock on a connection dedicated to holding it, and returns a
// function that releases it and returns the connection to the pool.
// Session-level advisory locks are tied to the connection that took
// them, not to database/sql's *DB, so the lock and unlock calls must
// share the one *sql.Conn pinned here rather than going through the
// normal pooled Exec path.
func lockPostgresMigrations(ctx context.Context, database *DB) (unlock func(), err error) {
	conn, err := database.DB.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection for migration lock: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("acquire migration lock: %w", err)
	}
	return func() {
		// Best-effort: an unlock failure here still releases the lock
		// when the session ends, i.e. when Close below drops this
		// connection.
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockKey)
		_ = conn.Close()
	}, nil
}

func migrationApplied(ctx context.Context, database *DB, version string) (bool, error) {
	var n int
	err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`,
		version).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("check migration %s: %w", version, err)
	}
	return n > 0, nil
}

func applyMigration(ctx context.Context, database *DB, name string) error {
	content, err := migrationFiles.ReadFile(migrationsDir(database.Engine) + "/" + name)
	if err != nil {
		return fmt.Errorf("read migration %s: %w", name, err)
	}

	tx, err := database.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx, string(content)); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("apply migration %s: %w", name, err)
	}
	appliedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx,
		database.rebind(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`),
		name, appliedAt); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}
	return nil
}
