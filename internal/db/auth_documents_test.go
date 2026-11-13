package db_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
)

// TestMigration0029IsListedOnBothEngines: migration 0029 exists on both
// engines (issue #8, ADR-0016 decision 2). The sibling parity test
// TestMigrationDirectoriesMatch then keeps the two directories equal.
func TestMigration0029IsListedOnBothEngines(t *testing.T) {
	for _, engine := range []db.Engine{db.SQLite, db.Postgres} {
		names, err := db.MigrationNames(engine)
		if err != nil {
			t.Fatalf("MigrationNames(%s): %v", engine, err)
		}
		found := false
		for _, n := range names {
			if strings.HasPrefix(n, "0029") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s migrations %v have no 0029 migration", engine, names)
		}
	}
}

// TestAuthDocumentsTableHasItsColumns: migration 0029 creates auth_documents
// with name, payload, version and updated_at, on every engine under test.
func TestAuthDocumentsTableHasItsColumns(t *testing.T) {
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			assertTableHasColumns(t, tgt.DB, "auth_documents", "name,payload,version,updated_at")
		})
	}
}

// TestAuthDocumentsRowsRoundTripAndNameIsUnique: a row keeps its payload
// bytes exactly (including non-text bytes), and name is the primary key, so
// a second row with the same name is refused.
func TestAuthDocumentsRowsRoundTripAndNameIsUnique(t *testing.T) {
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			database := tgt.DB
			payload := []byte{0x00, 0x01, 0xfe, 0xff, 'o', 'k'}
			insert := `INSERT INTO auth_documents (name, payload, version, updated_at) VALUES (?, ?, ?, ?)`

			if _, err := database.Exec(insert, "accounts", payload, 1, "2026-10-10T00:00:00Z"); err != nil {
				t.Fatalf("insert auth_documents row: %v", err)
			}

			var got []byte
			var version int64
			if err := database.QueryRow(`SELECT payload, version FROM auth_documents WHERE name = ?`, "accounts").Scan(&got, &version); err != nil {
				t.Fatalf("read auth_documents row: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("payload = %v, want %v", got, payload)
			}
			if version != 1 {
				t.Errorf("version = %d, want 1", version)
			}

			if _, err := database.Exec(insert, "accounts", payload, 1, "2026-10-10T00:00:01Z"); err == nil {
				t.Error("inserting a second auth_documents row named accounts succeeded, want name to be the primary key")
			}
			if _, err := database.Exec(insert, "tokens", payload, 1, "2026-10-10T00:00:02Z"); err != nil {
				t.Errorf("inserting a differently named auth_documents row: %v", err)
			}
		})
	}
}
