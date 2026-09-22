package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// TestOldBinaryInsertBackfillsHoneypotCanary is the #105 delivery plan's
// named reversibility proof for canaries: a binary built before migration
// 0013_agent_kinds.sql lists every column except kind in its INSERT --
// exactly what InsertCanary itself did before this change -- and that
// must still succeed against the migrated schema, with kind read back as
// "honeypot" from the column's own DEFAULT. A rolled-back binary talking
// to an already-migrated database is exactly this shape.
func TestOldBinaryInsertBackfillsHoneypotCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		enrolledAt := time.Now().UTC().Format(receivedAtLayout)
		if _, err := database.ExecContext(ctx, `
			INSERT INTO canaries (id, name, lane, ports, heartbeat_interval_s, enrolled_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			"old-binary-canary", "old", "lan", "22", 60, enrolledAt); err != nil {
			t.Fatalf("insert canary without kind column: %v", err)
		}

		var kind string
		row := database.QueryRow(`SELECT kind FROM canaries WHERE id = ?`, "old-binary-canary")
		if err := row.Scan(&kind); err != nil {
			t.Fatalf("scan kind: %v", err)
		}
		if kind != string(agentkind.Honeypot) {
			t.Errorf("kind = %q, want the migration's default %q", kind, agentkind.Honeypot)
		}
	})
}

// TestOldBinaryInsertBackfillsHoneypotEnrolmentSession is
// TestOldBinaryInsertBackfillsHoneypotCanary's counterpart for
// enrolment_sessions.
func TestOldBinaryInsertBackfillsHoneypotEnrolmentSession(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		createdAt := time.Now().UTC()
		deadline := createdAt.Add(5 * time.Minute)
		if _, err := database.ExecContext(ctx, `
			INSERT INTO enrolment_sessions (id, token_hash, canary_name, lane, created_at, first_contact_deadline, state)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"old-binary-session", "deadbeef", "old", "lan",
			createdAt.Format(receivedAtLayout), deadline.Format(receivedAtLayout), string(EnrolmentStateMinted)); err != nil {
			t.Fatalf("insert enrolment session without kind column: %v", err)
		}

		var kind string
		row := database.QueryRow(`SELECT kind FROM enrolment_sessions WHERE id = ?`, "old-binary-session")
		if err := row.Scan(&kind); err != nil {
			t.Fatalf("scan kind: %v", err)
		}
		if kind != string(agentkind.Honeypot) {
			t.Errorf("kind = %q, want the migration's default %q", kind, agentkind.Honeypot)
		}
	})
}
