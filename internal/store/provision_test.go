package store

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// fakeIssue signs a real certificate for canaryID over a fresh key,
// with a test CA built here from crypto/x509 (testSigningCA, in
// clientcert_test.go): Provision now records the certificate's serial,
// fingerprint and validity, so a placeholder PEM no longer suffices.
// The key is thrown away -- these store-level tests never present it;
// internal/ingest's mTLS tests do.
func fakeIssue(canaryID string, kind agentkind.Kind) ([]byte, *x509.Certificate, error) {
	return testSigningCA().sign(canaryID, kind, time.Hour)
}

// contactedFixture mints and first-contacts a session, returning the raw
// enrolment secret Provision consumes and the session it belongs to.
func contactedFixture(t *testing.T, database *db.DB, mintedAt time.Time) (secret string, session EnrolmentSession) {
	t.Helper()
	ctx := context.Background()
	raw, _, err := MintEnrolmentSession(ctx, database, "provisioned-canary", "front-door", agentkind.Honeypot, mintedAt)
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
		if !strings.HasPrefix(result.ClientCertPEM, "-----BEGIN CERTIFICATE-----") {
			t.Errorf("ClientCertPEM = %q, want the certificate fakeIssue signed", result.ClientCertPEM)
		}
		if result.HeartbeatIntervalS != DefaultHeartbeatIntervalS {
			t.Errorf("HeartbeatIntervalS = %d, want %d", result.HeartbeatIntervalS, DefaultHeartbeatIntervalS)
		}

		// The canary row exists, built from the session's name/lane/kind
		// and its kind's provisioning profile -- the single source for
		// the port list now that there is no second mirror constant to
		// compare against (issue #105).
		honeypotProfile, ok := agentkind.Lookup(agentkind.Honeypot)
		if !ok {
			t.Fatal("agentkind.Lookup(Honeypot) ok = false")
		}
		var name, lane, kind, ports string
		row := database.QueryRow(`SELECT name, lane, kind, ports FROM canaries WHERE id = ?`, result.CanaryID)
		if err := row.Scan(&name, &lane, &kind, &ports); err != nil {
			t.Fatalf("scan canaries row: %v", err)
		}
		if name != session.Name || lane != session.Lane {
			t.Errorf("canaries name/lane = %q/%q, want %q/%q", name, lane, session.Name, session.Lane)
		}
		if kind != string(agentkind.Honeypot) {
			t.Errorf("canaries kind = %q, want %q", kind, agentkind.Honeypot)
		}
		if ports != honeypotProfile.Ports {
			t.Errorf("canaries ports = %q, want %q", ports, honeypotProfile.Ports)
		}

		// The token is active and resolves to the new canary.
		tok, err := LookupCanaryTokenByHash(context.Background(), database, HashToken(result.CanaryToken))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash: %v", err)
		}
		if tok.CanaryID != result.CanaryID {
			t.Errorf("token CanaryID = %q, want %q", tok.CanaryID, result.CanaryID)
		}

		// Issue #130 B2/B3: the certificate is recorded, live and unused,
		// and the token is bound to exactly its fingerprint.
		block, _ := pem.Decode([]byte(result.ClientCertPEM))
		if block == nil {
			t.Fatal("ClientCertPEM does not decode")
		}
		certs, err := ListClientCertsForCanary(context.Background(), database, result.CanaryID)
		if err != nil {
			t.Fatalf("ListClientCertsForCanary: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("client_certs rows = %d, want 1", len(certs))
		}
		if certs[0].Fingerprint != CertFingerprint(block.Bytes) {
			t.Errorf("recorded fingerprint = %s, want the issued certificate's", certs[0].Fingerprint)
		}
		if !certs[0].Live() || certs[0].FirstUsedAt != nil {
			t.Errorf("recorded certificate = %+v, want live and unused", certs[0])
		}
		if tok.CertFingerprint != certs[0].Fingerprint {
			t.Errorf("token bound to %q, want %q", tok.CertFingerprint, certs[0].Fingerprint)
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

// TestProvisionScannerAcceptsEmptyPorts is #108's own instruction (the
// "Scanner agent, slice 1" plan, section 6): "confirm store.Provision
// accepts an empty port list; if it does not, make it do so rather than
// inventing a fake port." Nightjar listens on nothing (ADR-0010 decision
// 3), so agentkind.Scanner's Profile.Ports is "" -- this proves that
// value reaches the canaries row unchanged rather than tripping a schema
// constraint or a code path that assumes a non-empty port list.
func TestProvisionScannerAcceptsEmptyPorts(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		ctx := context.Background()
		raw, _, err := MintEnrolmentSession(ctx, database, "provisioned-scanner", "front-door", agentkind.Scanner, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession: %v", err)
		}
		secret, _, contactOutcome, err := FirstContact(ctx, database, HashToken(raw), mintedAt.Add(time.Minute))
		if err != nil {
			t.Fatalf("FirstContact: %v", err)
		}
		if contactOutcome != Contacted {
			t.Fatalf("FirstContact outcome = %v, want Contacted", contactOutcome)
		}

		provisionAt := mintedAt.Add(2 * time.Minute)
		result, provisionOutcome, err := Provision(ctx, database, HashToken(secret), provisionAt, fakeIssue)
		if err != nil {
			t.Fatalf("Provision: %v", err)
		}
		if provisionOutcome != Provisioned {
			t.Fatalf("outcome = %v, want Provisioned", provisionOutcome)
		}

		var (
			kind, ports  string
			registeredAt *string
		)
		row := database.QueryRow(`SELECT kind, ports, registered_at FROM canaries WHERE id = ?`, result.CanaryID)
		if err := row.Scan(&kind, &ports, &registeredAt); err != nil {
			t.Fatalf("scan canaries row: %v", err)
		}
		if kind != string(agentkind.Scanner) {
			t.Errorf("canaries kind = %q, want %q", kind, agentkind.Scanner)
		}
		if ports != "" {
			t.Errorf("canaries ports = %q, want empty", ports)
		}
		// Issue #116 (ADR-0012 decision 5): a scanner is pending until
		// its first ordered scan passes, like a honeypot's self-test.
		if registeredAt != nil {
			t.Errorf("registered_at = %q for a provisioned scanner; want NULL (pending until its proof passes)", *registeredAt)
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

// TestProvisionUnregisteredKindFailsLoudly is the #105 delivery plan's
// named "provision fails loudly on a session row carrying an
// unregistered kind" test: a session in state "contacted" whose kind
// column names nothing agentkind.Lookup knows -- written directly with
// SQL, since MintEnrolmentSession itself refuses to mint one -- must
// make Provision fail with an error, not silently fall back to
// Honeypot's profile or any other kind's.
func TestProvisionUnregisteredKindFailsLoudly(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		contactedAt := mintedAt.Add(time.Minute)
		windowDeadline := contactedAt.Add(30 * time.Minute)
		secretRaw := "unregistered-kind-secret"

		if _, err := database.ExecContext(ctx, `
			INSERT INTO enrolment_sessions (id, token_hash, canary_name, lane, kind, created_at, first_contact_deadline, burned_at, enrolment_secret_hash, window_deadline, state)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"unregistered-kind-session", "irrelevant-token-hash", "canary-a", "lane-a", "seagull",
			mintedAt.Format(receivedAtLayout), contactedAt.Format(receivedAtLayout), contactedAt.Format(receivedAtLayout),
			HashToken(secretRaw), windowDeadline.Format(receivedAtLayout), string(EnrolmentStateContacted)); err != nil {
			t.Fatalf("insert enrolment session with unregistered kind: %v", err)
		}

		result, _, err := Provision(ctx, database, HashToken(secretRaw), contactedAt.Add(time.Minute), fakeIssue)
		if err == nil {
			t.Fatal("Provision with an unregistered kind returned no error")
		}
		if result != (ProvisionResult{}) {
			t.Errorf("result = %+v, want zero value on failure", result)
		}

		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM canaries`).Scan(&count); err != nil {
			t.Fatalf("count canaries: %v", err)
		}
		if count != 0 {
			t.Errorf("canaries has %d rows, want 0: an unregistered kind must create no canary, not fall back to any registered one's profile", count)
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

		failingIssue := func(string, agentkind.Kind) ([]byte, *x509.Certificate, error) {
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
