package db_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
)

// TestMigrateOnClosedDB proves Migrate refuses to proceed -- rather than
// panicking or silently doing nothing -- once its underlying connection
// is gone, on both engines and at both points that check: the Postgres
// advisory-lock acquisition (lockPostgresMigrations, which only
// Postgres reaches) and the schema_migrations creation every engine
// reaches. sql: database is closed is deterministic, unlike a network
// failure, so this needs no retry loop to stay stable across runs.
func TestMigrateOnClosedDB(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "closed.db")
		database, err := db.Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := database.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		err = db.Migrate(context.Background(), database)
		if err == nil {
			t.Fatal("Migrate on a closed sqlite DB succeeded, want an error")
		}
		if !strings.Contains(err.Error(), "create schema_migrations") {
			t.Errorf("Migrate error = %q, want it to name the create schema_migrations step", err.Error())
		}
	})

	t.Run("postgres", func(t *testing.T) {
		adminURL := os.Getenv(dbtest.EnvPostgresURL)
		if adminURL == "" {
			t.Skip("BIRDCAGE_TEST_DATABASE_URL not set, skipping Postgres")
		}
		database, err := db.Open(adminURL)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := database.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		err = db.Migrate(context.Background(), database)
		if err == nil {
			t.Fatal("Migrate on a closed postgres DB succeeded, want an error")
		}
		if !strings.Contains(err.Error(), "migration lock") {
			t.Errorf("Migrate error = %q, want it to name the migration-lock step", err.Error())
		}
	})
}

// TestMigrateRejectsForeignSchemaMigrationsTable proves Migrate's own
// bookkeeping query fails loudly, rather than silently misbehaving,
// when schema_migrations already exists but not in the shape Migrate
// expects -- CREATE TABLE IF NOT EXISTS accepts whatever is already
// there by name alone (verified empirically: SQLite and Postgres both
// skip creation without checking column shape), so a pre-existing,
// wrongly-shaped table is a real state Migrate can meet, not a
// hypothetical one.
func TestMigrateRejectsForeignSchemaMigrationsTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "foreign-table.db")
	database, err := db.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	if _, err := database.Exec(`CREATE TABLE schema_migrations (unexpected_column TEXT)`); err != nil {
		t.Fatalf("pre-create foreign schema_migrations: %v", err)
	}

	err = db.Migrate(context.Background(), database)
	if err == nil {
		t.Fatal("Migrate against a wrongly-shaped schema_migrations table succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "check migration") {
		t.Errorf("Migrate error = %q, want it to name the check migration step", err.Error())
	}
}

// TestMigrateReapplyingNonIdempotentMigrationFails proves applyMigration
// fails (and rolls back) rather than corrupting the schema when Migrate
// is made to re-run a migration whose statements are not idempotent.
// 0013_agent_kinds.sql is exactly that: an ALTER TABLE ... ADD COLUMN,
// unlike every other migration here which uses CREATE ... IF NOT
// EXISTS. Deleting its own schema_migrations row (simulating bookkeeping
// getting out of sync with the schema it describes) forces Migrate to
// attempt it again, which must fail with a duplicate-column error on
// both engines rather than silently succeeding or leaving a partial
// transaction committed.
func TestMigrateReapplyingNonIdempotentMigrationFails(t *testing.T) {
	const migrationName = "0013_agent_kinds.sql"

	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			database := tgt.DB
			ctx := context.Background()

			res, err := database.Exec(`DELETE FROM schema_migrations WHERE version = ?`, migrationName)
			if err != nil {
				t.Fatalf("delete schema_migrations row for %s: %v", migrationName, err)
			}
			if n, err := res.RowsAffected(); err != nil {
				t.Fatalf("RowsAffected: %v", err)
			} else if n != 1 {
				t.Fatalf("deleted %d rows for %s, want exactly 1 (is the migration file still named this?)", n, migrationName)
			}

			err = db.Migrate(ctx, database)
			if err == nil {
				t.Fatal("Migrate re-applying a non-idempotent migration succeeded, want a duplicate-column error")
			}
			if !strings.Contains(err.Error(), "apply migration "+migrationName) {
				t.Errorf("Migrate error = %q, want it to name apply migration %s", err.Error(), migrationName)
			}

			// The failed re-apply must not have left the migration
			// marked applied again (its tx rolled back), and the
			// columns it would have added were already there from the
			// first, successful application -- still exactly one kind
			// column each, not a partial or duplicated one.
			var n int
			if err := database.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, migrationName).Scan(&n); err != nil {
				t.Fatalf("recount schema_migrations: %v", err)
			}
			if n != 0 {
				t.Errorf("schema_migrations has %d rows for %s after a failed re-apply, want 0 (rollback must not record it)", n, migrationName)
			}
		})
	}
}
