package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// TestAnyCanariesEnrolled runs issue #149's startup signal on every
// engine: an empty agents table reads as a fresh install, one row as
// state that depends on the CA. Postgres returns EXISTS as a boolean,
// not SQLite's 0/1, so the query must read on both.
func TestAnyCanariesEnrolled(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		got, err := AnyCanariesEnrolled(ctx, database)
		if err != nil {
			t.Fatalf("empty table: %v", err)
		}
		if got {
			t.Fatalf("empty table: got enrolled, want none")
		}

		enrolledAt := time.Now().UTC().Format(receivedAtLayout)
		if _, err := database.ExecContext(ctx, `
			INSERT INTO agents (id, name, lane, ports, heartbeat_interval_s, enrolled_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			"enrolled-canary", "c", "lan", "22", 60, enrolledAt); err != nil {
			t.Fatalf("insert canary: %v", err)
		}
		got, err = AnyCanariesEnrolled(ctx, database)
		if err != nil {
			t.Fatalf("one canary: %v", err)
		}
		if !got {
			t.Fatalf("one canary: got none, want enrolled")
		}
	})
}
