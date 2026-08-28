package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	bdb "github.com/tomlawesome/birdcage/internal/db"
)

func openMigratedDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := bdb.Open(filepath.Join(t.TempDir(), "birdcage-test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := bdb.Migrate(context.Background(), database); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return database
}

func validEntry() Entry {
	return Entry{
		Action:      "block_source",
		Target:      "203.0.113.7",
		Reason:      "port scan reported by OpenCanary",
		TriggeredBy: "ingest/open-canary",
		CreatedAt:   time.Date(2026, 8, 28, 12, 30, 45, 0, time.UTC),
	}
}

func scanRow(t *testing.T, database *sql.DB, id int64) (action, target, reason, triggeredBy, createdAt string) {
	t.Helper()
	err := database.QueryRow(
		`SELECT action, target, reason, triggered_by, created_at FROM audit_log WHERE id = ?`, id,
	).Scan(&action, &target, &reason, &triggeredBy, &createdAt)
	if err != nil {
		t.Fatalf("select audit_log row %d: %v", id, err)
	}
	return action, target, reason, triggeredBy, createdAt
}

func rowCount(t *testing.T, database *sql.DB) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatalf("count audit_log: %v", err)
	}
	return n
}

// TestAppendInsertsEntry is the happy path: Append inserts exactly one row
// with exactly the values passed in, and returns the positive id of that
// row.
func TestAppendInsertsEntry(t *testing.T) {
	database := openMigratedDB(t)
	ctx := context.Background()

	entry := validEntry()
	id, err := Append(ctx, database, entry)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if id <= 0 {
		t.Fatalf("Append returned id %d, want positive", id)
	}

	if n := rowCount(t, database); n != 1 {
		t.Fatalf("audit_log has %d rows after one Append, want 1", n)
	}

	action, target, reason, triggeredBy, createdAt := scanRow(t, database, id)
	if action != entry.Action {
		t.Errorf("action = %q, want %q", action, entry.Action)
	}
	if target != entry.Target {
		t.Errorf("target = %q, want %q", target, entry.Target)
	}
	if reason != entry.Reason {
		t.Errorf("reason = %q, want %q", reason, entry.Reason)
	}
	if triggeredBy != entry.TriggeredBy {
		t.Errorf("triggered_by = %q, want %q", triggeredBy, entry.TriggeredBy)
	}
	if want := entry.CreatedAt.UTC().Format(time.RFC3339); createdAt != want {
		t.Errorf("created_at = %q, want %q", createdAt, want)
	}
}

// TestAppendStoresCreatedAtAsUTC proves the RFC 3339 UTC requirement: a
// non-UTC input instant must come back as the same instant in UTC, not as
// the input location's rendering.
func TestAppendStoresCreatedAtAsUTC(t *testing.T) {
	database := openMigratedDB(t)

	loc := time.FixedZone("UTC+02:00", 2*3600)
	entry := validEntry()
	entry.CreatedAt = time.Date(2026, 8, 28, 14, 30, 45, 0, loc) // 12:30:45 UTC

	id, err := Append(context.Background(), database, entry)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	_, _, _, _, createdAt := scanRow(t, database, id)
	want := entry.CreatedAt.UTC().Format(time.RFC3339)
	if createdAt != want {
		t.Fatalf("created_at = %q, want UTC %q", createdAt, want)
	}
}

// TestAppendRejectsBlankFields covers validation: each required field,
// empty or whitespace-only, must be rejected with an error and must not
// insert a row. A zero CreatedAt must also be rejected (Append must not
// silently default the timestamp).
func TestAppendRejectsBlankFields(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Entry)
	}{
		{"action empty", func(e *Entry) { e.Action = "" }},
		{"action whitespace only", func(e *Entry) { e.Action = " \t " }},
		{"target empty", func(e *Entry) { e.Target = "" }},
		{"target whitespace only", func(e *Entry) { e.Target = "   " }},
		{"reason empty", func(e *Entry) { e.Reason = "" }},
		{"reason whitespace only", func(e *Entry) { e.Reason = "\n" }},
		{"triggered_by empty", func(e *Entry) { e.TriggeredBy = "" }},
		{"triggered_by whitespace only", func(e *Entry) { e.TriggeredBy = "  \t " }},
		{"created_at zero", func(e *Entry) { e.CreatedAt = time.Time{} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database := openMigratedDB(t)
			entry := validEntry()
			tc.mutate(&entry)

			_, err := Append(context.Background(), database, entry)
			if err == nil {
				t.Fatalf("Append accepted %+v, want error", entry)
			}
			if n := rowCount(t, database); n != 0 {
				t.Fatalf("audit_log has %d rows after failed Append, want 0", n)
			}
		})
	}
}

// TestAuditLogIsAppendOnly is the append-only invariant test required by
// CONTRIBUTING.md: it bypasses the audit package entirely and issues raw
// UPDATE and DELETE statements against the database. Both must fail at the
// database level (schema triggers), and the row written by Append must
// survive unchanged.
func TestAuditLogIsAppendOnly(t *testing.T) {
	database := openMigratedDB(t)
	ctx := context.Background()

	entry := validEntry()
	id, err := Append(ctx, database, entry)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	originalAction, originalTarget, originalReason, originalTriggeredBy, originalCreatedAt := scanRow(t, database, id)

	if _, err := database.ExecContext(ctx,
		`UPDATE audit_log SET reason = ? WHERE id = ?`, "tampered", id); err == nil {
		t.Fatalf("raw UPDATE on audit_log succeeded, want the schema trigger to abort it")
	}
	if _, err := database.ExecContext(ctx,
		`DELETE FROM audit_log WHERE id = ?`, id); err == nil {
		t.Fatalf("raw DELETE on audit_log succeeded, want the schema trigger to abort it")
	}

	action, target, reason, triggeredBy, createdAt := scanRow(t, database, id)
	if action != originalAction || target != originalTarget ||
		reason != originalReason || triggeredBy != originalTriggeredBy ||
		createdAt != originalCreatedAt {
		t.Errorf("row changed after blocked UPDATE/DELETE: got (%q, %q, %q, %q, %q), want (%q, %q, %q, %q, %q)",
			action, target, reason, triggeredBy, createdAt,
			originalAction, originalTarget, originalReason, originalTriggeredBy, originalCreatedAt)
	}
	if n := rowCount(t, database); n != 1 {
		t.Fatalf("audit_log has %d rows after blocked UPDATE/DELETE, want 1", n)
	}
}
