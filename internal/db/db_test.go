package db_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
)

// TestEngineString covers both arms of Engine.String(): the Postgres
// case and the default (SQLite) case migrate.go's log lines and this
// package's own error-wrapping (%s on an Engine) both rely on.
func TestEngineString(t *testing.T) {
	if got := db.Postgres.String(); got != "postgres" {
		t.Errorf("Postgres.String() = %q, want %q", got, "postgres")
	}
	if got := db.SQLite.String(); got != "sqlite" {
		t.Errorf("SQLite.String() = %q, want %q", got, "sqlite")
	}
}

// TestRebindLiteralQuotes proves Rebind's literal-aware scan empirically:
// a "?" inside a single-quoted string literal must NOT be renumbered as
// a placeholder, only a "?" outside one may. None of birdcage's own SQL
// currently puts a literal "?" inside a string (per db.go's comment),
// but the scan claims to handle it anyway, so that claim gets a test.
func TestRebindLiteralQuotes(t *testing.T) {
	got := db.Rebind(`SELECT * FROM t WHERE note = 'is this a ?' AND id = ? AND tag = 'it''s here?' AND n = ?`)
	want := `SELECT * FROM t WHERE note = 'is this a ?' AND id = $1 AND tag = 'it''s here?' AND n = $2`
	if got != want {
		t.Errorf("Rebind() =\n  %q\nwant\n  %q", got, want)
	}
}

// TestRebindNoQuotes covers the plain case with no string literals at
// all, renumbering every "?" in order of appearance.
func TestRebindNoQuotes(t *testing.T) {
	got := db.Rebind(`INSERT INTO t (a, b, c) VALUES (?, ?, ?)`)
	want := `INSERT INTO t (a, b, c) VALUES ($1, $2, $3)`
	if got != want {
		t.Errorf("Rebind() = %q, want %q", got, want)
	}
}

// TestOpenSQLiteSchemePrefix covers Open's "sqlite:" branch explicitly
// -- distinct from the default (no recognized scheme) branch that a bare
// path already exercises elsewhere -- and proves the opened database is
// actually usable.
func TestOpenSQLiteSchemePrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "explicit-scheme.db")
	database, err := db.Open("sqlite:" + path)
	if err != nil {
		t.Fatalf("Open(sqlite:...): %v", err)
	}
	defer func() { _ = database.Close() }()

	if database.Engine != db.SQLite {
		t.Fatalf("Engine = %v, want SQLite", database.Engine)
	}
	if err := db.Migrate(context.Background(), database); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if n == 0 {
		t.Error("schema_migrations empty after Migrate on an sqlite:-prefixed path")
	}
}

// TestBeginCommitsAndRollsBack exercises DB.Begin and every Tx method
// (ExecContext, QueryRowContext, QueryContext and, on Postgres, the "?"
// rebind they share with *DB) on both engines, proving both real
// outcomes a transaction can have: a committed write is visible
// afterwards, and a rolled-back write is refused -- never persisted.
func TestBeginCommitsAndRollsBack(t *testing.T) {
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			database := tgt.DB
			ctx := context.Background()

			// Committed path.
			tx, err := database.Begin(ctx)
			if err != nil {
				t.Fatalf("Begin: %v", err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO alerts (instance_id, source_ip, dest_port, service, raw, received_at) VALUES (?, ?, ?, ?, ?, ?)`,
				"node-commit", "203.0.113.20", 22, "ssh", "raw-commit", "2026-01-01T00:00:00Z"); err != nil {
				t.Fatalf("tx.ExecContext insert: %v", err)
			}
			var committedID int64
			if err := tx.QueryRowContext(ctx,
				`SELECT id FROM alerts WHERE instance_id = ?`, "node-commit").Scan(&committedID); err != nil {
				t.Fatalf("tx.QueryRowContext: %v", err)
			}
			rows, err := tx.QueryContext(ctx, `SELECT id FROM alerts WHERE instance_id = ?`, "node-commit")
			if err != nil {
				t.Fatalf("tx.QueryContext: %v", err)
			}
			var seen int
			for rows.Next() {
				seen++
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("iterate tx.QueryContext rows: %v", err)
			}
			_ = rows.Close()
			if seen != 1 {
				t.Fatalf("tx.QueryContext saw %d rows in-flight, want 1", seen)
			}
			if err := tx.Commit(); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			var n int
			if err := database.QueryRow(`SELECT COUNT(*) FROM alerts WHERE id = ?`, committedID).Scan(&n); err != nil {
				t.Fatalf("post-commit query: %v", err)
			}
			if n != 1 {
				t.Errorf("committed row count = %d, want 1", n)
			}

			// Rolled-back path: a refusal to persist, proved by absence
			// afterwards rather than merely by Rollback returning nil.
			tx2, err := database.Begin(ctx)
			if err != nil {
				t.Fatalf("Begin (rollback case): %v", err)
			}
			if _, err := tx2.ExecContext(ctx,
				`INSERT INTO alerts (instance_id, source_ip, dest_port, service, raw, received_at) VALUES (?, ?, ?, ?, ?, ?)`,
				"node-rollback", "203.0.113.21", 23, "telnet", "raw-rollback", "2026-01-01T00:00:01Z"); err != nil {
				t.Fatalf("tx2.ExecContext insert: %v", err)
			}
			if err := tx2.Rollback(); err != nil {
				t.Fatalf("Rollback: %v", err)
			}
			var n2 int
			if err := database.QueryRow(`SELECT COUNT(*) FROM alerts WHERE instance_id = ?`, "node-rollback").Scan(&n2); err != nil {
				t.Fatalf("post-rollback query: %v", err)
			}
			if n2 != 0 {
				t.Errorf("rolled-back row count = %d, want 0 (rollback must not persist the write)", n2)
			}
		})
	}
}
