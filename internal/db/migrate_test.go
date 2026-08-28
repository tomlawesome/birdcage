package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func openTempDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "birdcage-test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func TestMigrateIdempotent(t *testing.T) {
	database := openTempDB(t)
	ctx := context.Background()

	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != 1 {
		t.Fatalf("schema_migrations has %d rows, want 1 (exactly one applied migration)", count)
	}

	var version string
	if err := database.QueryRow(`SELECT version FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != "0001_init.sql" {
		t.Fatalf("version = %q, want %q", version, "0001_init.sql")
	}

	for _, name := range []string{"idx_alerts_instance_id", "idx_alerts_source_ip", "idx_alerts_service", "idx_alerts_received_at"} {
		var n int
		if err := database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&n); err != nil {
			t.Fatalf("check index %s: %v", name, err)
		}
		if n != 1 {
			t.Errorf("index %s present %d times, want 1", name, n)
		}
	}

	var columns string
	if err := database.QueryRow(`SELECT GROUP_CONCAT(name, ',') FROM pragma_table_info('alerts')`).Scan(&columns); err != nil {
		t.Fatalf("pragma_table_info: %v", err)
	}
	want := "id,instance_id,source_ip,dest_port,service,raw,received_at"
	if columns != want {
		t.Errorf("alerts columns = %q, want %q", columns, want)
	}
}

// TestExecMultiStatement verifies empirically that a single Exec call runs
// every ;-separated statement in the string (Migrate relies on this to
// apply each migration file in one call, per the issue's "verify rather
// than assume" requirement).
func TestExecMultiStatement(t *testing.T) {
	database := openTempDB(t)

	_, err := database.Exec(`CREATE TABLE t1 (id INTEGER PRIMARY KEY);
CREATE TABLE t2 (id INTEGER PRIMARY KEY);
CREATE INDEX idx_t2_id ON t2(id);`)
	if err != nil {
		t.Fatalf("multi-statement Exec failed: %v", err)
	}

	var objects int
	err = database.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table', 'index') AND name IN ('t1', 't2', 'idx_t2_id')`).Scan(&objects)
	if err != nil {
		t.Fatalf("count objects: %v", err)
	}
	if objects != 3 {
		t.Fatalf("found %d of 3 expected objects after multi-statement Exec", objects)
	}
}
