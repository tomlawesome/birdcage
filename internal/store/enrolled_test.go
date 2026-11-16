package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// TestAnyClientCertsIssued is #213's PS2-S1: the CA-continuity signal is a
// client_certs row (CA-signed state), not an agents row.
func TestAnyClientCertsIssued(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		got, err := AnyClientCertsIssued(ctx, database)
		if err != nil {
			t.Fatalf("empty table: %v", err)
		}
		if got {
			t.Fatalf("empty table: got issued, want none")
		}

		enrolledAt := time.Now().UTC().Format(receivedAtLayout)
		if _, err := database.ExecContext(ctx, `
			INSERT INTO agents (id, name, lane, ports, heartbeat_interval_s, enrolled_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			"enrolled-canary", "c", "lan", "22", 60, enrolledAt); err != nil {
			t.Fatalf("insert canary: %v", err)
		}
		got, err = AnyClientCertsIssued(ctx, database)
		if err != nil {
			t.Fatalf("agent row only: %v", err)
		}
		if got {
			t.Fatalf("agent row only: got issued, want none")
		}

		now := time.Now().UTC()
		insertCertRow(t, database, "enrolled-canary", "fp-any-issued", now, now.Add(time.Hour), nil)
		got, err = AnyClientCertsIssued(ctx, database)
		if err != nil {
			t.Fatalf("one cert: %v", err)
		}
		if !got {
			t.Fatalf("one cert: got none, want issued")
		}
	})
}
