package db_test

import (
	"context"
	"testing"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
)

// TestMigrationDirectoriesMatch asserts migrations/sqlite and
// migrations/postgres carry exactly the same set of migration
// filenames -- per issue #7, a migration that exists on only one engine
// is a defect, not an oversight to catch later.
func TestMigrationDirectoriesMatch(t *testing.T) {
	sqliteNames, err := db.MigrationNames(db.SQLite)
	if err != nil {
		t.Fatalf("MigrationNames(SQLite): %v", err)
	}
	postgresNames, err := db.MigrationNames(db.Postgres)
	if err != nil {
		t.Fatalf("MigrationNames(Postgres): %v", err)
	}
	if len(sqliteNames) == 0 {
		t.Fatal("sqlite migrations directory is empty")
	}
	if len(sqliteNames) != len(postgresNames) {
		t.Fatalf("sqlite has %d migrations %v, postgres has %d %v", len(sqliteNames), sqliteNames, len(postgresNames), postgresNames)
	}
	for i := range sqliteNames {
		if sqliteNames[i] != postgresNames[i] {
			t.Fatalf("migration name mismatch at index %d: sqlite=%q postgres=%q (sqlite=%v, postgres=%v)",
				i, sqliteNames[i], postgresNames[i], sqliteNames, postgresNames)
		}
	}
}

func TestMigrateIdempotent(t *testing.T) {
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			database := tgt.DB
			ctx := context.Background()

			// dbtest.Targets already ran Migrate once; run it twice more
			// here to prove idempotency on top of that.
			if err := db.Migrate(ctx, database); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			if err := db.Migrate(ctx, database); err != nil {
				t.Fatalf("Migrate again: %v", err)
			}

			names, err := db.MigrationNames(database.Engine)
			if err != nil {
				t.Fatalf("MigrationNames: %v", err)
			}

			var count int
			if err := database.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
				t.Fatalf("count schema_migrations: %v", err)
			}
			if count != len(names) {
				t.Fatalf("schema_migrations has %d rows, want %d (exactly the applied migrations: %v)", count, len(names), names)
			}

			assertTableHasColumns(t, database, "alerts",
				"id,instance_id,source_ip,dest_port,service,raw,received_at,event_id")
			assertRowInsertable(t, database, "alerts", "audit_log", "canary_tokens")
			assertAuditLogAppendOnly(t, database)
		})
	}
}

// assertTableHasColumns checks a table's column set/order, using each
// engine's own schema-introspection mechanism: SQLite has no
// information_schema (verified empirically -- it errors "no such
// table"), so this branches rather than assuming standard SQL coverage
// extends that far.
func assertTableHasColumns(t *testing.T, database *db.DB, table, want string) {
	t.Helper()
	query := `SELECT column_name FROM information_schema.columns WHERE table_name = ? ORDER BY ordinal_position`
	if database.Engine == db.SQLite {
		query = `SELECT name FROM pragma_table_info(?)`
	}
	rows, err := database.Query(query, table)
	if err != nil {
		t.Fatalf("query columns for %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns: %v", err)
	}

	gotJoined := joinComma(got)
	if gotJoined != want {
		t.Errorf("%s columns = %q, want %q", table, gotJoined, want)
	}
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

// assertRowInsertable proves each named table actually exists and
// accepts a trivial row-count query -- the portable half of "the
// migration created this table" that doesn't depend on either engine's
// own schema-catalog dialect.
func assertRowInsertable(t *testing.T, database *db.DB, tables ...string) {
	t.Helper()
	for _, table := range tables {
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Errorf("table %s: %v", table, err)
		}
	}
}

// assertAuditLogAppendOnly proves the append-only trigger guard exists
// on both engines by exercising it directly (SQLite's RAISE(ABORT)
// triggers vs. Postgres' trigger function -- see
// migrations/sqlite/0002_audit_log.sql and
// migrations/postgres/0002_audit_log.sql), rather than asserting on
// either engine's own trigger catalog.
func assertAuditLogAppendOnly(t *testing.T, database *db.DB) {
	t.Helper()
	var id int64
	err := database.QueryRow(
		`INSERT INTO audit_log (action, target, reason, triggered_by, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id`,
		"a", "t", "r", "tb", "2026-01-01T00:00:00Z").Scan(&id)
	if err != nil {
		t.Fatalf("insert audit_log row: %v", err)
	}
	if _, err := database.Exec(`UPDATE audit_log SET reason = ? WHERE id = ?`, "tampered", id); err == nil {
		t.Error("UPDATE audit_log succeeded, want the append-only guard to abort it")
	}
	if _, err := database.Exec(`DELETE FROM audit_log WHERE id = ?`, id); err == nil {
		t.Error("DELETE audit_log succeeded, want the append-only guard to abort it")
	}
}

// TestExecMultiStatement verifies empirically that a single Exec call
// runs every ;-separated statement in the string, on both engines
// (Migrate relies on this to apply each migration file in one call, per
// the issue's "verify rather than assume" requirement).
func TestExecMultiStatement(t *testing.T) {
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			database := tgt.DB
			_, err := database.Exec(`CREATE TABLE multistmt_t1 (id INTEGER PRIMARY KEY);
CREATE TABLE multistmt_t2 (id INTEGER PRIMARY KEY);
CREATE INDEX idx_multistmt_t2_id ON multistmt_t2(id);`)
			if err != nil {
				t.Fatalf("multi-statement Exec failed: %v", err)
			}

			for _, table := range []string{"multistmt_t1", "multistmt_t2"} {
				var n int
				if err := database.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
					t.Errorf("table %s missing after multi-statement Exec: %v", table, err)
				}
			}
		})
	}
}

// TestEventIDUniqueIndexAllowsMultipleNulls verifies empirically, on
// both engines, the claim migrations/*/0004_canary_tokens.sql's comment
// relies on: idx_alerts_event_id is a plain (not partial) unique index,
// and a plain unique index's own SQL semantics -- every NULL distinct
// from every other NULL -- already let any number of NULL event_id rows
// coexist, with no WHERE clause needed. Two rows with event_id set to
// the same value must still be rejected, so this also proves the index
// is doing real dedup work, not merely absent.
func TestEventIDUniqueIndexAllowsMultipleNulls(t *testing.T) {
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			database := tgt.DB
			insert := `INSERT INTO alerts (instance_id, source_ip, dest_port, service, raw, received_at, event_id)
				VALUES (?, ?, ?, ?, ?, ?, ?)`

			if _, err := database.Exec(insert, "node-1", "203.0.113.9", 22, "ssh", "raw-1", "2026-01-01T00:00:00Z", nil); err != nil {
				t.Fatalf("insert first NULL event_id row: %v", err)
			}
			if _, err := database.Exec(insert, "node-2", "203.0.113.10", 23, "telnet", "raw-2", "2026-01-01T00:00:01Z", nil); err != nil {
				t.Fatalf("insert second NULL event_id row: %v", err)
			}

			if _, err := database.Exec(insert, "node-1", "203.0.113.9", 80, "http", "raw-3", "2026-01-01T00:00:02Z", "dup-event"); err != nil {
				t.Fatalf("insert first non-NULL event_id row: %v", err)
			}
			if _, err := database.Exec(insert, "node-1", "203.0.113.9", 80, "http", "raw-4", "2026-01-01T00:00:03Z", "dup-event"); err == nil {
				t.Error("second insert with duplicate non-NULL event_id succeeded, want a unique-index violation")
			}
		})
	}
}
