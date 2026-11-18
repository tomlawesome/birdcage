package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// Issue #164: agents, findings and audit rows make a database "not new";
// settings alone do not.
func TestReadDatabaseHistory(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		now := time.Now().UTC()
		if err := SetSetting(ctx, database, SettingAdminApprovalAddress, "admin@example.net", now); err != nil {
			t.Fatalf("SetSetting: %v", err)
		}
		h, err := ReadDatabaseHistory(ctx, database)
		if err != nil || h.InUse() {
			t.Fatalf("fresh database with a setting: history %+v err %v, want not in use", h, err)
		}
		if err := InsertCanary(ctx, database, Canary{ID: "c-164", Name: "c-164", Lane: "lan", Kind: agentkind.Honeypot,
			HeartbeatIntervalS: DefaultHeartbeatIntervalS, EnrolledAt: now}); err != nil {
			t.Fatalf("InsertCanary: %v", err)
		}
		h, err = ReadDatabaseHistory(ctx, database)
		if err != nil || !h.InUse() || h.Agents != 1 {
			t.Fatalf("after one agent: history %+v err %v, want one agent, in use", h, err)
		}
	})
}
