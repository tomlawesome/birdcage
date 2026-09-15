package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

func TestMintCanaryTokenReturnsRawOnceAndStoresOnlyHash(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, token, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken: %v", err)
		}
		if raw == "" {
			t.Fatal("MintCanaryToken returned an empty raw token")
		}
		if token.ID == "" || token.CanaryID != "canary-a" {
			t.Fatalf("MintCanaryToken token = %+v, want a non-empty ID and CanaryID canary-a", token)
		}
		if !token.CreatedAt.Equal(mintedAt) {
			t.Errorf("CreatedAt = %v, want %v", token.CreatedAt, mintedAt)
		}

		// The raw value is never stored: only its hash resolves.
		var storedRaw string
		row := database.QueryRow(`SELECT token_hash FROM canary_tokens WHERE id = ?`, token.ID)
		if err := row.Scan(&storedRaw); err != nil {
			t.Fatalf("scan token_hash: %v", err)
		}
		if storedRaw == raw {
			t.Fatal("canary_tokens.token_hash equals the raw token; the raw value must never be stored")
		}
		if storedRaw != HashToken(raw) {
			t.Errorf("stored token_hash = %q, want HashToken(raw) = %q", storedRaw, HashToken(raw))
		}

		found, err := LookupCanaryTokenByHash(context.Background(), database, HashToken(raw))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash: %v", err)
		}
		if found.ID != token.ID {
			t.Errorf("LookupCanaryTokenByHash id = %q, want %q", found.ID, token.ID)
		}
	})
}

func TestLookupCanaryTokenByHashUnknownHash(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		_, err := LookupCanaryTokenByHash(context.Background(), database, HashToken("never-minted"))
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("LookupCanaryTokenByHash(unknown) = %v, want ErrTokenNotFound", err)
		}
	})
}

// TestRevokedCanaryTokenNeverResolves is one of #32 slice 1's three
// required tests: a token minted, then revoked through
// RevokeCanaryToken, must never resolve by hash again.
func TestRevokedCanaryTokenNeverResolves(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, token, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken: %v", err)
		}

		if _, err := LookupCanaryTokenByHash(context.Background(), database, HashToken(raw)); err != nil {
			t.Fatalf("LookupCanaryTokenByHash before revoke: %v", err)
		}

		revokedAt := mustParse(t, "2026-01-02T00:00:00Z")
		if err := RevokeCanaryToken(context.Background(), database, token.ID, revokedAt); err != nil {
			t.Fatalf("RevokeCanaryToken: %v", err)
		}

		_, err = LookupCanaryTokenByHash(context.Background(), database, HashToken(raw))
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("LookupCanaryTokenByHash after revoke = %v, want ErrTokenNotFound", err)
		}
	})
}

// TestLookupByHashNeverReturnsRevokedRow is #32 slice 1's second
// required test, distinct from TestRevokedCanaryTokenNeverResolves: it
// sets revoked_at directly with SQL (bypassing RevokeCanaryToken
// entirely) to prove LookupCanaryTokenByHash's own query filters
// revoked rows out -- not merely that RevokeCanaryToken happens to also
// hide them some other way -- and that a second, still-active token
// stays resolvable throughout.
func TestLookupByHashNeverReturnsRevokedRow(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		revokedRaw, revokedTok, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken (to be revoked): %v", err)
		}
		activeRaw, activeTok, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken (stays active): %v", err)
		}

		if _, err := database.Exec(`UPDATE canary_tokens SET revoked_at = ? WHERE id = ?`,
			"2026-01-02T00:00:00Z", revokedTok.ID); err != nil {
			t.Fatalf("mark revoked directly: %v", err)
		}

		if _, err := LookupCanaryTokenByHash(context.Background(), database, HashToken(revokedRaw)); !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("LookupCanaryTokenByHash(revoked hash) = %v, want ErrTokenNotFound", err)
		}
		found, err := LookupCanaryTokenByHash(context.Background(), database, HashToken(activeRaw))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash(active hash): %v", err)
		}
		if found.ID != activeTok.ID {
			t.Errorf("LookupCanaryTokenByHash(active hash) id = %q, want %q", found.ID, activeTok.ID)
		}
	})
}

func TestRecordCanaryTokenUseUpdatesLastUsedAt(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, token, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken: %v", err)
		}

		found, err := LookupCanaryTokenByHash(context.Background(), database, HashToken(raw))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash: %v", err)
		}
		if found.LastUsedAt != nil {
			t.Fatalf("LastUsedAt = %v before any use, want nil", found.LastUsedAt)
		}

		usedAt := mustParse(t, "2026-01-01T01:00:00Z")
		if err := RecordCanaryTokenUse(context.Background(), database, token.ID, usedAt); err != nil {
			t.Fatalf("RecordCanaryTokenUse: %v", err)
		}

		found, err = LookupCanaryTokenByHash(context.Background(), database, HashToken(raw))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash after use: %v", err)
		}
		if found.LastUsedAt == nil || !found.LastUsedAt.Equal(usedAt) {
			t.Errorf("LastUsedAt = %v, want %v", found.LastUsedAt, usedAt)
		}
	})
}

// TestRevokeCanaryTokenTwiceKeepsFirstTimestamp: revoking again must not
// move the moment the token stopped working, which is what the audit
// trail (#32 item 10) reports.
func TestRevokeCanaryTokenTwiceKeepsFirstTimestamp(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, token, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken: %v", err)
		}

		first := mustParse(t, "2026-01-02T00:00:00Z")
		if err := RevokeCanaryToken(context.Background(), database, token.ID, first); err != nil {
			t.Fatalf("RevokeCanaryToken (first): %v", err)
		}
		later := mustParse(t, "2026-01-09T00:00:00Z")
		if err := RevokeCanaryToken(context.Background(), database, token.ID, later); err != nil {
			t.Fatalf("RevokeCanaryToken (second) = %v, want nil", err)
		}

		var revokedAt string
		if err := database.QueryRow(`SELECT revoked_at FROM canary_tokens WHERE id = ?`,
			token.ID).Scan(&revokedAt); err != nil {
			t.Fatalf("read revoked_at: %v", err)
		}
		got, err := time.Parse(receivedAtLayout, revokedAt)
		if err != nil {
			t.Fatalf("parse revoked_at %q: %v", revokedAt, err)
		}
		if !got.Equal(first) {
			t.Fatalf("revoked_at = %s, want the first revocation %s", got, first)
		}

		if _, err := LookupCanaryTokenByHash(context.Background(), database, HashToken(raw)); !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("LookupCanaryTokenByHash after two revokes = %v, want ErrTokenNotFound", err)
		}
	})
}

func TestRevokeCanaryTokenUnknownID(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := RevokeCanaryToken(context.Background(), database, "no-such-token", mustParse(t, "2026-01-01T00:00:00Z"))
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("RevokeCanaryToken(unknown id) = %v, want ErrTokenNotFound", err)
		}
	})
}

// TestInsertAlertIfNewDuplicateEventIDIsNoOp is #32 slice 1's third
// required test: the same event id delivered twice stores one row, and
// the second call reports it did not store rather than erroring.
// TestLookupCanaryTokenByHashAnyStatusFindsRevokedRow is #32 slice 5's
// separate internal lookup: unlike LookupCanaryTokenByHash, it must
// resolve a revoked token's row rather than reporting ErrTokenNotFound,
// while still reporting ErrTokenNotFound for a hash that was never
// minted at all.
func TestLookupCanaryTokenByHashAnyStatusFindsRevokedRow(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		raw, token, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken: %v", err)
		}
		revokedAt := mustParse(t, "2026-01-02T00:00:00Z")
		if err := RevokeCanaryToken(context.Background(), database, token.ID, revokedAt); err != nil {
			t.Fatalf("RevokeCanaryToken: %v", err)
		}

		found, err := LookupCanaryTokenByHashAnyStatus(context.Background(), database, HashToken(raw))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHashAnyStatus(revoked): %v", err)
		}
		if found.ID != token.ID || found.RevokedAt == nil || !found.RevokedAt.Equal(revokedAt) {
			t.Errorf("LookupCanaryTokenByHashAnyStatus(revoked) = %+v, want ID %q and RevokedAt %v", found, token.ID, revokedAt)
		}

		_, err = LookupCanaryTokenByHashAnyStatus(context.Background(), database, HashToken("never-minted"))
		if !errors.Is(err, ErrTokenNotFound) {
			t.Fatalf("LookupCanaryTokenByHashAnyStatus(never minted) = %v, want ErrTokenNotFound", err)
		}
	})
}

// TestCanaryHasActiveTokenReflectsRevocations proves CanaryHasActiveToken
// tracks live rows exactly: true while at least one token is
// unrevoked, false once every token for that canary is revoked, and
// unaffected by another canary's tokens.
func TestCanaryHasActiveTokenReflectsRevocations(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		_, tokA, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken(canary-a): %v", err)
		}
		if _, _, err := MintCanaryToken(context.Background(), database, "canary-b", mintedAt); err != nil {
			t.Fatalf("MintCanaryToken(canary-b): %v", err)
		}

		active, err := CanaryHasActiveToken(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("CanaryHasActiveToken(canary-a): %v", err)
		}
		if !active {
			t.Fatal("CanaryHasActiveToken(canary-a) = false, want true before any revocation")
		}

		if err := RevokeCanaryToken(context.Background(), database, tokA.ID, mustParse(t, "2026-01-02T00:00:00Z")); err != nil {
			t.Fatalf("RevokeCanaryToken: %v", err)
		}

		active, err = CanaryHasActiveToken(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("CanaryHasActiveToken(canary-a) after revoke: %v", err)
		}
		if active {
			t.Fatal("CanaryHasActiveToken(canary-a) = true, want false once its only token is revoked")
		}

		active, err = CanaryHasActiveToken(context.Background(), database, "canary-b")
		if err != nil {
			t.Fatalf("CanaryHasActiveToken(canary-b): %v", err)
		}
		if !active {
			t.Fatal("CanaryHasActiveToken(canary-b) = false, want true (unaffected by canary-a's revocation)")
		}
	})
}

// TestRevokeOtherCanaryTokensRevokesEveryOtherLiveToken is #32 slice 5's
// core rotation primitive: every non-revoked token for the canary except
// keepID is revoked, an already-revoked row is left with its original
// timestamp, and another canary's tokens are never touched.
func TestRevokeOtherCanaryTokensRevokesEveryOtherLiveToken(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		_, keep, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken(keep): %v", err)
		}
		_, older1, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken(older1): %v", err)
		}
		_, older2, err := MintCanaryToken(context.Background(), database, "canary-a", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken(older2): %v", err)
		}
		alreadyRevokedAt := mustParse(t, "2026-01-01T12:00:00Z")
		if err := RevokeCanaryToken(context.Background(), database, older2.ID, alreadyRevokedAt); err != nil {
			t.Fatalf("RevokeCanaryToken(older2): %v", err)
		}
		_, otherCanary, err := MintCanaryToken(context.Background(), database, "canary-b", mintedAt)
		if err != nil {
			t.Fatalf("MintCanaryToken(canary-b): %v", err)
		}

		at := mustParse(t, "2026-01-02T00:00:00Z")
		n, err := RevokeOtherCanaryTokens(context.Background(), database, "canary-a", keep.ID, at)
		if err != nil {
			t.Fatalf("RevokeOtherCanaryTokens: %v", err)
		}
		if n != 1 {
			t.Errorf("RevokeOtherCanaryTokens revoked %d rows, want 1 (only older1, older2 was already revoked)", n)
		}

		var revokedAt *string
		row := database.QueryRow(`SELECT revoked_at FROM canary_tokens WHERE id = ?`, keep.ID)
		if err := row.Scan(&revokedAt); err != nil {
			t.Fatalf("scan keep.revoked_at: %v", err)
		}
		if revokedAt != nil {
			t.Errorf("keep token revoked_at = %v, want nil (never revoked)", *revokedAt)
		}

		row = database.QueryRow(`SELECT revoked_at FROM canary_tokens WHERE id = ?`, older1.ID)
		if err := row.Scan(&revokedAt); err != nil {
			t.Fatalf("scan older1.revoked_at: %v", err)
		}
		if revokedAt == nil {
			t.Fatal("older1 was not revoked")
		}

		row = database.QueryRow(`SELECT revoked_at FROM canary_tokens WHERE id = ?`, older2.ID)
		if err := row.Scan(&revokedAt); err != nil {
			t.Fatalf("scan older2.revoked_at: %v", err)
		}
		got, err := time.Parse(receivedAtLayout, *revokedAt)
		if err != nil {
			t.Fatalf("parse older2.revoked_at %q: %v", *revokedAt, err)
		}
		if !got.Equal(alreadyRevokedAt) {
			t.Errorf("older2 revoked_at = %s, want unchanged original %s", got, alreadyRevokedAt)
		}

		row = database.QueryRow(`SELECT revoked_at FROM canary_tokens WHERE id = ?`, otherCanary.ID)
		if err := row.Scan(&revokedAt); err != nil {
			t.Fatalf("scan otherCanary.revoked_at: %v", err)
		}
		if revokedAt != nil {
			t.Errorf("canary-b's token revoked_at = %v, want nil (a different canary must never be touched)", *revokedAt)
		}
	})
}

func TestInsertAlertIfNewDuplicateEventIDIsNoOp(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		a := AlertInsert{
			InstanceID: "canary-a", SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh",
			Raw: "raw-1", ReceivedAt: mustParse(t, "2026-01-01T00:00:00Z"), EventID: "event-1",
		}

		stored, err := InsertAlertIfNew(context.Background(), database, a)
		if err != nil {
			t.Fatalf("InsertAlertIfNew (first): %v", err)
		}
		if !stored {
			t.Fatal("InsertAlertIfNew (first) reported stored=false, want true")
		}

		dup := a
		dup.Raw = "raw-2" // a differing payload must still be ignored: the id is what matters
		stored, err = InsertAlertIfNew(context.Background(), database, dup)
		if err != nil {
			t.Fatalf("InsertAlertIfNew (duplicate): %v", err)
		}
		if stored {
			t.Fatal("InsertAlertIfNew (duplicate) reported stored=true, want false (no-op)")
		}

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{InstanceID: "canary-a"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) != 1 {
			t.Fatalf("got %d alerts for duplicate event id, want exactly 1: %+v", len(alerts), alerts)
		}
		if alerts[0].Raw != "raw-1" {
			t.Errorf("stored alert Raw = %q, want %q (the first delivery, not the duplicate)", alerts[0].Raw, "raw-1")
		}
	})
}

// TestInsertAlertIfNewDedupIsPerCanary: dedup is scoped to one canary,
// so a canary cannot suppress another canary's alert by storing its
// event id first (#32 research, 2026-09-15).
func TestInsertAlertIfNewDedupIsPerCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		at := mustParse(t, "2026-01-01T00:00:00Z")
		shared := "a1b2c3"
		first := AlertInsert{
			InstanceID: "canary-a", SourceIP: "203.0.113.9", DestPort: 22,
			Service: "ssh", Raw: "raw-a", ReceivedAt: at, EventID: shared,
		}
		stored, err := InsertAlertIfNew(context.Background(), database, first)
		if err != nil || !stored {
			t.Fatalf("InsertAlertIfNew(canary-a) = %v, %v; want true, nil", stored, err)
		}

		second := first
		second.InstanceID = "canary-b"
		second.Raw = "raw-b"
		stored, err = InsertAlertIfNew(context.Background(), database, second)
		if err != nil {
			t.Fatalf("InsertAlertIfNew(canary-b): %v", err)
		}
		if !stored {
			t.Fatal("canary-b's alert was suppressed by canary-a's event id; dedup must be per canary")
		}

		stored, err = InsertAlertIfNew(context.Background(), database, first)
		if err != nil {
			t.Fatalf("InsertAlertIfNew(canary-a, repeat): %v", err)
		}
		if stored {
			t.Fatal("the same canary's duplicate event id stored a second row")
		}
	})
}

func TestInsertAlertIfNewEmptyEventIDNeverDeduplicates(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		a := AlertInsert{
			InstanceID: "canary-b", SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh",
			Raw: "raw-1", ReceivedAt: mustParse(t, "2026-01-01T00:00:00Z"),
		}
		for i := 0; i < 2; i++ {
			stored, err := InsertAlertIfNew(context.Background(), database, a)
			if err != nil {
				t.Fatalf("InsertAlertIfNew (empty event id, call %d): %v", i, err)
			}
			if !stored {
				t.Fatalf("InsertAlertIfNew (empty event id, call %d) reported stored=false, want true", i)
			}
		}

		alerts, err := ListAlerts(context.Background(), database, AlertFilter{InstanceID: "canary-b"})
		if err != nil {
			t.Fatalf("ListAlerts: %v", err)
		}
		if len(alerts) != 2 {
			t.Fatalf("got %d alerts with empty event id, want 2 (never deduplicated)", len(alerts))
		}
	})
}
