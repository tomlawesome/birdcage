package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
)

// insertCertRow writes a client_certs row with chosen validity, for the
// time-driven health tests (a signed certificate's validity comes from
// the wall clock, which these tests do not use).
func insertCertRow(t *testing.T, database *db.DB, canaryID, fp string, notBefore, notAfter time.Time, firstUsed *time.Time) {
	t.Helper()
	var used any
	if firstUsed != nil {
		used = firstUsed.UTC().Format(receivedAtLayout)
	}
	if _, err := database.Exec(`INSERT INTO client_certs (agent_id, serial, fingerprint_sha256, not_before, not_after, first_used_at)
		VALUES (?, ?, ?, ?, ?, ?)`, canaryID, "01", fp,
		notBefore.UTC().Format(receivedAtLayout), notAfter.UTC().Format(receivedAtLayout), used); err != nil {
		t.Fatalf("insert client_certs row: %v", err)
	}
}

// TestCertificateSignalBoundaries is renewal_stalled's clock (ADR-0012
// B2, #72): nothing before half-life plus the margin, renewal_stalled
// from there until expiry, then expired (not_delivering). A seven-day
// certificate's margin is fifteen minutes; a twenty-minute one's is a
// tenth of its life.
func TestCertificateSignalBoundaries(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		nb := mustParse(t, "2026-01-01T00:00:00Z")
		used := nb.Add(time.Minute)
		insertCertRow(t, database, "week", "fp-week", nb, nb.Add(7*24*time.Hour), &used)
		insertCertRow(t, database, "short", "fp-short", nb, nb.Add(20*time.Minute), &used)

		half := nb.Add(84 * time.Hour)
		cases := []struct {
			canary          string
			at              time.Time
			stalled, expire bool
		}{
			{"week", half, false, false},
			{"week", half.Add(15*time.Minute - time.Second), false, false},
			{"week", half.Add(15 * time.Minute), true, false},
			{"week", nb.Add(7*24*time.Hour - time.Second), true, false},
			{"week", nb.Add(7 * 24 * time.Hour), false, true},
			{"short", nb.Add(10*time.Minute + 2*time.Minute - time.Second), false, false},
			{"short", nb.Add(12 * time.Minute), true, false},
			{"short", nb.Add(20 * time.Minute), false, true},
			{"none", half, false, false},
		}
		for _, tc := range cases {
			sig, err := certificateSignal(ctx, database, tc.canary, tc.at)
			if err != nil {
				t.Fatalf("certificateSignal: %v", err)
			}
			if sig.renewalStalled != tc.stalled || sig.expired != tc.expire {
				t.Errorf("%s at %s: stalled=%v expired=%v, want %v %v", tc.canary, tc.at, sig.renewalStalled, sig.expired, tc.stalled, tc.expire)
			}
		}
	})
}

// TestCertificateSignalFollowsTheCertificateInUse: a successor issued
// but never used does not stop the clock; once used it does.
func TestCertificateSignalFollowsTheCertificateInUse(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		nb := mustParse(t, "2026-01-01T00:00:00Z")
		used := nb.Add(time.Minute)
		insertCertRow(t, database, "c", "fp-old", nb, nb.Add(7*24*time.Hour), &used)
		renewedAt := nb.Add(100 * time.Hour)
		insertCertRow(t, database, "c", "fp-new", renewedAt, renewedAt.Add(7*24*time.Hour), nil)

		at := nb.Add(101 * time.Hour)
		sig, err := certificateSignal(ctx, database, "c", at)
		if err != nil {
			t.Fatalf("certificateSignal: %v", err)
		}
		if !sig.renewalStalled {
			t.Error("unused successor stopped the renewal_stalled clock")
		}

		newCert, err := LookupClientCertByFingerprint(ctx, database, "fp-new")
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if _, _, err := RecordClientCertFirstUse(ctx, database, newCert, at); err != nil {
			t.Fatalf("RecordClientCertFirstUse: %v", err)
		}
		if sig, _ = certificateSignal(ctx, database, "c", at); sig.renewalStalled || sig.expired {
			t.Errorf("after the successor's first use: %+v, want no signal", sig)
		}
	})
}

// TestApplyCredentialHealthRanks: each new state sits beside its twin
// in healthStateRank, and certificate expiry turns on not_delivering.
func TestApplyCredentialHealthRanks(t *testing.T) {
	now := mustParse(t, "2026-01-01T00:00:00Z")
	recent := now.Add(-30 * time.Second).Format(receivedAtLayout)
	pair := `["10.0.0.1","10.0.0.2"]`

	c := Canary{Status: "silent"}
	conflictSince := now.Add(-time.Minute)
	applyHealthState(&c, false, nil, true, false, 60, &conflictSince, false, true, now)
	c.dualUse = dualUseColumns{addrs: &pair, addrsAt: &recent}
	if err := applyCredentialHealth(&c, certSignal{renewalStalled: true, renewalStalledForS: 5}, now); err != nil {
		t.Fatalf("applyCredentialHealth: %v", err)
	}
	want := "token_conflict,credential_conflict,silent,rotation_stalled,renewal_stalled,pending"
	if got := strings.Join(c.ActiveStates, ","); got != want {
		t.Errorf("ActiveStates = %s, want %s", got, want)
	}
	if c.Status != "token_conflict" {
		t.Errorf("Status = %q, want token_conflict", c.Status)
	}

	// credential_conflict alone outranks silent.
	c = Canary{Status: "silent"}
	applyHealthState(&c, false, nil, false, false, 0, nil, false, false, now)
	c.dualUse = dualUseColumns{addrs: &pair, addrsAt: &recent}
	if err := applyCredentialHealth(&c, certSignal{}, now); err != nil {
		t.Fatalf("applyCredentialHealth: %v", err)
	}
	if c.Status != "credential_conflict" {
		t.Errorf("Status = %q, want credential_conflict over silent", c.Status)
	}

	// Expiry: not_delivering, once, and it outranks renewal-stalled's tier.
	c = Canary{Status: "ok"}
	applyHealthState(&c, false, nil, false, false, 0, nil, false, false, now)
	if err := applyCredentialHealth(&c, certSignal{expired: true}, now); err != nil {
		t.Fatalf("applyCredentialHealth: %v", err)
	}
	if c.Status != "not_delivering" || !c.NotDelivering || !c.CertificateExpired {
		t.Errorf("expired: Status=%q NotDelivering=%v CertificateExpired=%v", c.Status, c.NotDelivering, c.CertificateExpired)
	}
	c = Canary{Status: "ok"}
	applyHealthState(&c, true, nil, false, false, 0, nil, false, false, now)
	if err := applyCredentialHealth(&c, certSignal{expired: true}, now); err != nil {
		t.Fatalf("applyCredentialHealth: %v", err)
	}
	if strings.Join(c.ActiveStates, ",") != "not_delivering" {
		t.Errorf("ActiveStates = %v, want not_delivering once", c.ActiveStates)
	}

	// Nothing to add leaves an ok canary ok.
	c = Canary{Status: "ok"}
	applyHealthState(&c, false, nil, false, false, 0, nil, false, false, now)
	stale := now.Add(-credentialConflictWindow).Format(receivedAtLayout)
	c.dualUse = dualUseColumns{addrs: &pair, addrsAt: &stale}
	if err := applyCredentialHealth(&c, certSignal{}, now); err != nil {
		t.Fatalf("applyCredentialHealth: %v", err)
	}
	if c.Status != "ok" || c.CredentialConflict != nil {
		t.Errorf("stale pair: Status=%q detail=%+v, want ok and none", c.Status, c.CredentialConflict)
	}
}

// TestListCanariesCredentialStatesAndJSON drives the states through
// ListCanaries (what #56's recorder and both dashboard routes read) and
// pins the JSON the dashboard consumes.
func TestListCanariesCredentialStatesAndJSON(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		now := mustParse(t, "2026-01-01T00:00:00Z")
		for _, id := range []string{"dual", "certconflict", "stalled"} {
			if err := InsertCanary(ctx, database, Canary{ID: id, Name: id, Lane: "lan", Kind: agentkind.Honeypot, HeartbeatIntervalS: 60, EnrolledAt: now}); err != nil {
				t.Fatalf("InsertCanary: %v", err)
			}
			if err := RecordCanaryCommonHeartbeat(ctx, database, id, now, ""); err != nil {
				t.Fatalf("heartbeat: %v", err)
			}
		}

		if err := RecordCredentialDualUse(ctx, database, "dual", DualUseAddresses, "10.0.0.1", "10.0.0.2", now); err != nil {
			t.Fatalf("RecordCredentialDualUse: %v", err)
		}
		if err := RecordCredentialDualUse(ctx, database, "dual", DualUseVersions, "1.0.0", "0.9.9", now); err != nil {
			t.Fatalf("RecordCredentialDualUse: %v", err)
		}
		if err := RecordCredentialDualUse(ctx, database, "nobody", DualUseAddresses, "a", "b", now); err != ErrCanaryNotFound {
			t.Errorf("unknown canary err = %v, want ErrCanaryNotFound", err)
		}
		if _, err := audit.Append(ctx, database, audit.Entry{Action: "ingest.cert_conflict", Target: "certconflict", Reason: "r", TriggeredBy: "certconflict", CreatedAt: now}); err != nil {
			t.Fatalf("audit.Append: %v", err)
		}
		nb := now.Add(-100 * time.Hour)
		insertCertRow(t, database, "stalled", "fp-stalled", nb, nb.Add(7*24*time.Hour), &nb)

		canaries, err := ListCanaries(ctx, database, now.Add(10*time.Second), time.Hour)
		if err != nil {
			t.Fatalf("ListCanaries: %v", err)
		}
		byID := map[string]Canary{}
		for _, c := range canaries {
			byID[c.ID] = c
		}

		if got := byID["certconflict"].Status; got != string(StateTokenConflict) {
			t.Errorf("cert_conflict canary Status = %q, want token_conflict", got)
		}
		if got := byID["stalled"].Status; got != string(StateRenewalStalled) {
			t.Errorf("stalled canary Status = %q, want renewal_stalled", got)
		}

		raw, err := json.Marshal(byID["dual"])
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got := string(decoded["status"]); got != `"credential_conflict"` {
			t.Errorf("status = %s, want \"credential_conflict\"", got)
		}
		want := `{"addresses":["10.0.0.1","10.0.0.2"],"versions":["1.0.0","0.9.9"]}`
		if got := string(decoded["credential_conflict"]); got != want {
			t.Errorf("credential_conflict = %s, want %s", got, want)
		}
		for _, hidden := range []string{"dualUse", "credential_dual_use_addrs"} {
			if _, ok := decoded[hidden]; ok {
				t.Errorf("raw column %s leaked into JSON", hidden)
			}
		}

		// Absent, not null, while the state does not hold.
		later, err := ListCanaries(ctx, database, now.Add(credentialConflictWindow), time.Hour)
		if err != nil {
			t.Fatalf("ListCanaries: %v", err)
		}
		for _, c := range later {
			if c.ID != "dual" {
				continue
			}
			raw, _ := json.Marshal(c)
			if strings.Contains(string(raw), "credential_conflict") {
				t.Errorf("after the window the JSON still mentions credential_conflict: %s", raw)
			}
		}
	})
}
