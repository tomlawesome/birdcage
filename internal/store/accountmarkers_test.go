package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
)

// Issue #164 (note 63923): only the accounts_initialised marker or a
// user.register audit row say an account has existed; agents, settings
// and other audit rows do not. The reset acknowledgement is recorded once
// and spent.
func TestAccountHistorySignals(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		now := time.Now().UTC()
		read := func() AccountHistory {
			t.Helper()
			h, err := ReadAccountHistory(ctx, database)
			if err != nil {
				t.Fatalf("ReadAccountHistory: %v", err)
			}
			return h
		}
		appendAudit := func(action string) {
			t.Helper()
			if _, err := audit.Append(ctx, database, audit.Entry{Action: action, Target: "t", Reason: "r", TriggeredBy: "x", CreatedAt: now}); err != nil {
				t.Fatalf("audit.Append(%s): %v", action, err)
			}
		}

		if err := SetSetting(ctx, database, SettingAdminApprovalAddress, "admin@example.net", now); err != nil {
			t.Fatalf("SetSetting: %v", err)
		}
		if err := InsertCanary(ctx, database, Canary{ID: "c-164", Name: "c-164", Lane: "lan", Kind: agentkind.Honeypot,
			HeartbeatIntervalS: DefaultHeartbeatIntervalS, EnrolledAt: now}); err != nil {
			t.Fatalf("InsertCanary: %v", err)
		}
		appendAudit("user.login_failed")
		if h := read(); h.InUse() {
			t.Fatalf("ordinary fresh-install rows: history %+v, want not in use", h)
		}

		for i := 0; i < 2; i++ {
			if err := MarkAccountsInitialised(ctx, database, now); err != nil {
				t.Fatalf("MarkAccountsInitialised: %v", err)
			}
		}
		if h := read(); !h.InUse() || !h.Initialised || h.Registrations != 0 {
			t.Errorf("marker alone: history %+v, want in use through the marker alone", h)
		}
		// audit_log is append-only, so the audit-row-alone case removes the
		// marker instead.
		if _, err := database.Exec(`DELETE FROM settings WHERE key = ?`, markerAccountsInitialised); err != nil {
			t.Fatalf("remove marker: %v", err)
		}
		appendAudit("user.register")
		if h := read(); !h.InUse() || h.Initialised || h.Registrations != 1 {
			t.Errorf("after a user.register row: history %+v, want in use through the audit row alone", h)
		}
		if keys := SettingKeys(); len(keys) > 0 {
			for _, k := range keys {
				if k == markerAccountsInitialised || k == markerAccountsReset {
					t.Errorf("marker %q is listed as an operator setting", k)
				}
			}
		}

		if acked, err := AccountsResetAcknowledged(ctx, database); err != nil || acked {
			t.Fatalf("acknowledged before a reset = %v, %v", acked, err)
		}
		if err := RecordAccountsReset(ctx, database, now); err != nil {
			t.Fatalf("RecordAccountsReset: %v", err)
		}
		if acked, err := AccountsResetAcknowledged(ctx, database); err != nil || !acked {
			t.Fatalf("acknowledged after a reset = %v, %v, want true", acked, err)
		}
		if err := SpendAccountsReset(ctx, database); err != nil {
			t.Fatalf("SpendAccountsReset: %v", err)
		}
		if acked, err := AccountsResetAcknowledged(ctx, database); err != nil || acked {
			t.Errorf("acknowledged after spending = %v, %v, want false", acked, err)
		}
	})
}
