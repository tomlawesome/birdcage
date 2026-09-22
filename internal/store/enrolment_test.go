package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// TestMintEnrolmentSessionReturnsRawOnceAndStoresOnlyHash mirrors
// TestMintCanaryTokenReturnsRawOnceAndStoresOnlyHash: the raw deploy
// token is returned once, and only its SHA-256 hash ever lands in the
// row.
func TestMintEnrolmentSessionReturnsRawOnceAndStoresOnlyHash(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, session, err := MintEnrolmentSession(context.Background(), database, "canary-a", "lane-a", agentkind.Honeypot, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession: %v", err)
		}
		if raw == "" {
			t.Fatal("MintEnrolmentSession returned an empty raw token")
		}
		if session.ID == "" {
			t.Fatal("MintEnrolmentSession returned an empty session id")
		}
		if session.Name != "canary-a" || session.Lane != "lane-a" {
			t.Errorf("Name/Lane = %q/%q, want %q/%q", session.Name, session.Lane, "canary-a", "lane-a")
		}
		if session.State != EnrolmentStateMinted {
			t.Errorf("State = %q, want %q", session.State, EnrolmentStateMinted)
		}
		if !session.CreatedAt.Equal(mintedAt) {
			t.Errorf("CreatedAt = %v, want %v", session.CreatedAt, mintedAt)
		}
		wantDeadline := mintedAt.Add(enrolmentFirstContactWindow)
		if !session.FirstContactDeadline.Equal(wantDeadline) {
			t.Errorf("FirstContactDeadline = %v, want %v", session.FirstContactDeadline, wantDeadline)
		}

		var storedHash string
		row := database.QueryRow(`SELECT token_hash FROM enrolment_sessions WHERE id = ?`, session.ID)
		if err := row.Scan(&storedHash); err != nil {
			t.Fatalf("scan token_hash: %v", err)
		}
		if storedHash == raw {
			t.Fatal("enrolment_sessions.token_hash equals the raw token; the raw value must never be stored")
		}
		if storedHash != HashToken(raw) {
			t.Errorf("stored token_hash = %q, want HashToken(raw) = %q", storedHash, HashToken(raw))
		}
	})
}

// TestFirstContactUnknownToken is the "unknown" leg of design note
// decision 1's "unknown/expired/burned all get the same" refusal set: a
// hash matching no row at all.
func TestFirstContactUnknownToken(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		secret, session, outcome, err := FirstContact(context.Background(), database, HashToken("never-minted"), mustParse(t, "2026-01-01T00:00:00Z"))
		if err != nil {
			t.Fatalf("FirstContact: %v", err)
		}
		if outcome != Unknown {
			t.Fatalf("outcome = %v, want Unknown", outcome)
		}
		if secret != "" {
			t.Errorf("secret = %q, want empty on Unknown", secret)
		}
		if session != (EnrolmentSession{}) {
			t.Errorf("session = %+v, want zero value on Unknown", session)
		}
	})
}

// TestFirstContactSucceedsAndBurnsSession is the success path: a fresh
// session, first-contacted before its deadline, mints a secret exactly
// once, burns the row (design note decision 1) and returns a
// window_deadline 30 minutes out.
func TestFirstContactSucceedsAndBurnsSession(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, minted, err := MintEnrolmentSession(context.Background(), database, "canary-a", "lane-a", agentkind.Honeypot, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession: %v", err)
		}

		contactAt := mintedAt.Add(1 * time.Minute)
		secret, session, outcome, err := FirstContact(context.Background(), database, HashToken(raw), contactAt)
		if err != nil {
			t.Fatalf("FirstContact: %v", err)
		}
		if outcome != Contacted {
			t.Fatalf("outcome = %v, want Contacted", outcome)
		}
		if secret == "" {
			t.Fatal("FirstContact returned an empty enrolment secret on success")
		}
		if session.ID != minted.ID {
			t.Errorf("session.ID = %q, want %q", session.ID, minted.ID)
		}
		if session.State != EnrolmentStateContacted {
			t.Errorf("State = %q, want %q", session.State, EnrolmentStateContacted)
		}
		if session.BurnedAt == nil || !session.BurnedAt.Equal(contactAt) {
			t.Errorf("BurnedAt = %v, want %v", session.BurnedAt, contactAt)
		}
		wantWindow := contactAt.Add(enrolmentContactWindow)
		if session.WindowDeadline == nil || !session.WindowDeadline.Equal(wantWindow) {
			t.Errorf("WindowDeadline = %v, want %v", session.WindowDeadline, wantWindow)
		}

		// The raw secret never appears in the row -- only its hash.
		var storedSecretHash *string
		row := database.QueryRow(`SELECT enrolment_secret_hash FROM enrolment_sessions WHERE id = ?`, minted.ID)
		if err := row.Scan(&storedSecretHash); err != nil {
			t.Fatalf("scan enrolment_secret_hash: %v", err)
		}
		if storedSecretHash == nil {
			t.Fatal("enrolment_secret_hash is NULL after a successful first contact")
		}
		if *storedSecretHash == secret {
			t.Fatal("enrolment_secret_hash equals the raw secret; the raw value must never be stored")
		}
		if *storedSecretHash != HashToken(secret) {
			t.Errorf("stored enrolment_secret_hash = %q, want HashToken(secret) = %q", *storedSecretHash, HashToken(secret))
		}
	})
}

// TestFirstContactSecondCallReturnsReused is one of the three tests the
// task explicitly requires: a burned session refuses a second contact,
// uniformly with Unknown/Expired, per design note decision 1.
func TestFirstContactSecondCallReturnsReused(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, minted, err := MintEnrolmentSession(context.Background(), database, "canary-a", "lane-a", agentkind.Honeypot, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession: %v", err)
		}
		hash := HashToken(raw)

		firstSecret, _, firstOutcome, err := FirstContact(context.Background(), database, hash, mintedAt.Add(1*time.Minute))
		if err != nil {
			t.Fatalf("first FirstContact: %v", err)
		}
		if firstOutcome != Contacted {
			t.Fatalf("first outcome = %v, want Contacted", firstOutcome)
		}

		secondSecret, session, secondOutcome, err := FirstContact(context.Background(), database, hash, mintedAt.Add(2*time.Minute))
		if err != nil {
			t.Fatalf("second FirstContact: %v", err)
		}
		if secondOutcome != Reused {
			t.Fatalf("second outcome = %v, want Reused", secondOutcome)
		}
		if secondSecret != "" {
			t.Errorf("second secret = %q, want empty on Reused", secondSecret)
		}
		if secondSecret == firstSecret {
			t.Error("second call returned the same secret as the first; a burned session must never re-issue one")
		}
		if session.ID != minted.ID {
			t.Errorf("session.ID = %q, want %q", session.ID, minted.ID)
		}
	})
}

// TestFirstContactAfterDeadlineReturnsExpired is the second required
// test: a session never contacted, presented after its
// first_contact_deadline, is refused as Expired and its state moves to
// "expired".
func TestFirstContactAfterDeadlineReturnsExpired(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, minted, err := MintEnrolmentSession(context.Background(), database, "canary-a", "lane-a", agentkind.Honeypot, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession: %v", err)
		}
		hash := HashToken(raw)

		pastDeadline := minted.FirstContactDeadline.Add(1 * time.Second)
		secret, session, outcome, err := FirstContact(context.Background(), database, hash, pastDeadline)
		if err != nil {
			t.Fatalf("FirstContact: %v", err)
		}
		if outcome != Expired {
			t.Fatalf("outcome = %v, want Expired", outcome)
		}
		if secret != "" {
			t.Errorf("secret = %q, want empty on Expired", secret)
		}
		if session.State != EnrolmentStateExpired {
			t.Errorf("State = %q, want %q", session.State, EnrolmentStateExpired)
		}
		if session.BurnedAt != nil {
			t.Errorf("BurnedAt = %v, want nil: an expired session was never contacted", session.BurnedAt)
		}

		// A later attempt (still past the deadline) stays Expired, not
		// Unknown or Reused -- the row was never burned.
		secondSecret, _, secondOutcome, err := FirstContact(context.Background(), database, hash, pastDeadline.Add(time.Minute))
		if err != nil {
			t.Fatalf("second FirstContact: %v", err)
		}
		if secondOutcome != Expired {
			t.Fatalf("second outcome = %v, want Expired", secondOutcome)
		}
		if secondSecret != "" {
			t.Errorf("second secret = %q, want empty on Expired", secondSecret)
		}
	})
}

// TestFirstContactContactedSessionNeverReusableAfterItsWindow is the
// third required test: once a session has been successfully contacted,
// it refuses every later attempt as Reused even after its own
// window_deadline has passed -- burned_at, not the provisioning window,
// is what FirstContact checks first.
func TestFirstContactContactedSessionNeverReusableAfterItsWindow(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, _, err := MintEnrolmentSession(context.Background(), database, "canary-a", "lane-a", agentkind.Honeypot, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession: %v", err)
		}
		hash := HashToken(raw)

		contactAt := mintedAt.Add(1 * time.Minute)
		_, session, outcome, err := FirstContact(context.Background(), database, hash, contactAt)
		if err != nil {
			t.Fatalf("first FirstContact: %v", err)
		}
		if outcome != Contacted {
			t.Fatalf("first outcome = %v, want Contacted", outcome)
		}

		longAfterWindow := session.WindowDeadline.Add(24 * time.Hour)
		secret, _, laterOutcome, err := FirstContact(context.Background(), database, hash, longAfterWindow)
		if err != nil {
			t.Fatalf("later FirstContact: %v", err)
		}
		if laterOutcome != Reused {
			t.Fatalf("later outcome = %v, want Reused", laterOutcome)
		}
		if secret != "" {
			t.Errorf("secret = %q, want empty on Reused", secret)
		}
	})
}

// TestListEnrolmentSessionsNeverSelectsHashes proves ListEnrolmentSessions'
// query has no hash column to leak: EnrolmentSession itself carries
// neither token_hash nor enrolment_secret_hash, so this is really a
// compile-time guarantee, but the row count and ordering are worth
// covering too.
func TestListEnrolmentSessionsOrderedByCreatedAt(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		_, first, err := MintEnrolmentSession(ctx, database, "canary-first", "lane-a", agentkind.Honeypot, mustParse(t, "2026-01-01T00:00:00Z"))
		if err != nil {
			t.Fatalf("MintEnrolmentSession first: %v", err)
		}
		_, second, err := MintEnrolmentSession(ctx, database, "canary-second", "lane-a", agentkind.Honeypot, mustParse(t, "2026-01-02T00:00:00Z"))
		if err != nil {
			t.Fatalf("MintEnrolmentSession second: %v", err)
		}

		sessions, err := ListEnrolmentSessions(ctx, database)
		if err != nil {
			t.Fatalf("ListEnrolmentSessions: %v", err)
		}
		if len(sessions) != 2 {
			t.Fatalf("len(sessions) = %d, want 2", len(sessions))
		}
		if sessions[0].ID != first.ID || sessions[1].ID != second.ID {
			t.Errorf("sessions = [%s, %s], want [%s, %s] (oldest first)",
				sessions[0].ID, sessions[1].ID, first.ID, second.ID)
		}
	})
}
