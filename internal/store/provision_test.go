package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// fakeIssue returns a fixed, obviously-fake cert/key pair -- Provision
// never inspects their contents, only that issue succeeded, so a real
// internal/ca.CA is unnecessary for these store-level tests (the real
// thing is exercised by internal/ingest's mTLS tests instead).
func fakeIssue(_ string) (certPEM, keyPEM []byte, err error) {
	return []byte("fake-cert-pem"), []byte("fake-key-pem"), nil
}

// contactedFixture mints and first-contacts a session, returning the raw
// enrolment secret Provision consumes and the session it belongs to.
func contactedFixture(t *testing.T, database *db.DB, mintedAt time.Time) (secret string, session EnrolmentSession) {
	t.Helper()
	ctx := context.Background()
	raw, _, err := MintEnrolmentSession(ctx, database, "provisioned-canary", "front-door", mintedAt)
	if err != nil {
		t.Fatalf("MintEnrolmentSession: %v", err)
	}
	secret, session, outcome, err := FirstContact(ctx, database, HashToken(raw), mintedAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("FirstContact: %v", err)
	}
	if outcome != Contacted {
		t.Fatalf("FirstContact outcome = %v, want Contacted", outcome)
	}
	return secret, session
}

// TestProvisionHappyPath is the success path: a contacted session,
// presented within its window, becomes a live canary -- a canaries row
// (name/lane carried from the session, ports the Mockingbird fixed set,
// the default heartbeat interval), an active canary_tokens row, and the
// enrolment_sessions row left in state "provisioned" with its secret
// shredded.
func TestProvisionHappyPath(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		secret, session := contactedFixture(t, database, mintedAt)

		provisionAt := mintedAt.Add(2 * time.Minute)
		result, outcome, err := Provision(context.Background(), database, HashToken(secret), provisionAt, fakeIssue)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if outcome != Provisioned {
			t.Fatalf("outcome = %v, want Provisioned", outcome)
		}
		if result.CanaryID == "" {
			t.Fatal("CanaryID is empty")
		}
		if result.CanaryToken == "" {
			t.Fatal("CanaryToken is empty")
		}
		if result.ClientCertPEM != "fake-cert-pem" || result.ClientKeyPEM != "fake-key-pem" {
			t.Errorf("ClientCertPEM/ClientKeyPEM = %q/%q, want the values fakeIssue returned", result.ClientCertPEM, result.ClientKeyPEM)
		}
		if result.HeartbeatIntervalS != DefaultHeartbeatIntervalS {
			t.Errorf("HeartbeatIntervalS = %d, want %d", result.HeartbeatIntervalS, DefaultHeartbeatIntervalS)
		}

		// The canary row exists, built from the session's name/lane and
		// the fixed Mockingbird port set.
		var name, lane, ports string
		row := database.QueryRow(`SELECT name, lane, ports FROM canaries WHERE id = ?`, result.CanaryID)
		if err := row.Scan(&name, &lane, &ports); err != nil {
			t.Fatalf("scan canaries row: %v", err)
		}
		if name != session.Name || lane != session.Lane {
			t.Errorf("canaries name/lane = %q/%q, want %q/%q", name, lane, session.Name, session.Lane)
		}
		if ports != mockingbirdPorts {
			t.Errorf("canaries ports = %q, want %q", ports, mockingbirdPorts)
		}

		// The token is active and resolves to the new canary.
		tok, err := LookupCanaryTokenByHash(context.Background(), database, HashToken(result.CanaryToken))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash: %v", err)
		}
		if tok.CanaryID != result.CanaryID {
			t.Errorf("token CanaryID = %q, want %q", tok.CanaryID, result.CanaryID)
		}

		// The session is provisioned and its secret is shredded.
		var state string
		var canaryID, secretHash *string
		row = database.QueryRow(`SELECT state, canary_id, enrolment_secret_hash FROM enrolment_sessions WHERE id = ?`, session.ID)
		if err := row.Scan(&state, &canaryID, &secretHash); err != nil {
			t.Fatalf("scan enrolment_sessions row: %v", err)
		}
		if state != string(EnrolmentStateProvisioned) {
			t.Errorf("state = %q, want %q", state, EnrolmentStateProvisioned)
		}
		if canaryID == nil || *canaryID != result.CanaryID {
			t.Errorf("canary_id = %v, want %q", canaryID, result.CanaryID)
		}
		if secretHash != nil {
			t.Errorf("enrolment_secret_hash = %v, want NULL after provisioning", *secretHash)
		}
	})
}

// TestProvisionReplayIsUnknownSecret is design note decision 2's point:
// once provisioned, a session's enrolment_secret_hash is shredded, so a
// second Provision call with the same secret looks exactly like an
// unknown secret -- not a distinct "already provisioned" outcome.
func TestProvisionReplayIsUnknownSecret(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		secret, _ := contactedFixture(t, database, mintedAt)

		provisionAt := mintedAt.Add(2 * time.Minute)
		_, firstOutcome, err := Provision(context.Background(), database, HashToken(secret), provisionAt, fakeIssue)
		if err != nil {
			t.Fatalf("first Provision: %v", err)
		}
		if firstOutcome != Provisioned {
			t.Fatalf("first outcome = %v, want Provisioned", firstOutcome)
		}

		result, secondOutcome, err := Provision(context.Background(), database, HashToken(secret), provisionAt.Add(time.Minute), fakeIssue)
		if err != nil {
			t.Fatalf("second Provision: %v", err)
		}
		if secondOutcome != UnknownSecret {
			t.Fatalf("second outcome = %v, want UnknownSecret", secondOutcome)
		}
		if result != (ProvisionResult{}) {
			t.Errorf("second result = %+v, want zero value on UnknownSecret", result)
		}
	})
}

// TestProvisionUnknownSecret covers a secret that was never minted at
// all -- the other leg of UnknownSecret, alongside the replay case
// above.
func TestProvisionUnknownSecret(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		result, outcome, err := Provision(context.Background(), database, HashToken("never-minted"), mustParse(t, "2026-01-01T00:00:00Z"), fakeIssue)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if outcome != UnknownSecret {
			t.Fatalf("outcome = %v, want UnknownSecret", outcome)
		}
		if result != (ProvisionResult{}) {
			t.Errorf("result = %+v, want zero value on UnknownSecret", result)
		}
	})
}

// TestProvisionAfterWindowExpires is the required "secret after window"
// case: a contacted session presented at or after its window_deadline is
// refused as WindowExpired and moved to state "expired" -- no canary,
// token or certificate is ever created for it.
func TestProvisionAfterWindowExpires(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		secret, session := contactedFixture(t, database, mintedAt)

		result, outcome, err := Provision(context.Background(), database, HashToken(secret), *session.WindowDeadline, fakeIssue)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if outcome != WindowExpired {
			t.Fatalf("outcome = %v, want WindowExpired", outcome)
		}
		if result != (ProvisionResult{}) {
			t.Errorf("result = %+v, want zero value on WindowExpired", result)
		}

		var state string
		row := database.QueryRow(`SELECT state FROM enrolment_sessions WHERE id = ?`, session.ID)
		if err := row.Scan(&state); err != nil {
			t.Fatalf("scan state: %v", err)
		}
		if state != string(EnrolmentStateExpired) {
			t.Errorf("state = %q, want %q", state, EnrolmentStateExpired)
		}

		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM canaries`).Scan(&count); err != nil {
			t.Fatalf("count canaries: %v", err)
		}
		if count != 0 {
			t.Errorf("canaries has %d rows, want 0: a window-expired provision attempt must create no canary", count)
		}
	})
}

// TestProvisionIssueFailureRollsBackEverything proves the transaction
// boundary the design calls for: a CA failure must leave no canary row,
// no token, and the session still contacted (and its secret intact) --
// not a half-provisioned canary with no certificate to match.
func TestProvisionIssueFailureRollsBackEverything(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		secret, session := contactedFixture(t, database, mintedAt)

		failingIssue := func(string) ([]byte, []byte, error) {
			return nil, nil, errors.New("ca: boom")
		}

		_, _, err := Provision(context.Background(), database, HashToken(secret), mintedAt.Add(2*time.Minute), failingIssue)
		if err == nil {
			t.Fatal("Provision with a failing issue func returned no error")
		}

		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM canaries`).Scan(&count); err != nil {
			t.Fatalf("count canaries: %v", err)
		}
		if count != 0 {
			t.Errorf("canaries has %d rows, want 0: issue failure must roll back the whole transaction", count)
		}

		var state string
		var secretHash *string
		row := database.QueryRow(`SELECT state, enrolment_secret_hash FROM enrolment_sessions WHERE id = ?`, session.ID)
		if err := row.Scan(&state, &secretHash); err != nil {
			t.Fatalf("scan enrolment_sessions row: %v", err)
		}
		if state != string(EnrolmentStateContacted) {
			t.Errorf("state = %q, want %q (unchanged)", state, EnrolmentStateContacted)
		}
		if secretHash == nil {
			t.Error("enrolment_secret_hash is NULL; issue failure must not shred it")
		}
	})
}
