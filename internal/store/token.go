// Package store: this file is the write/lookup path for canary_tokens
// (issue #32 slice 1) -- the bearer credential a canary's agent presents
// on the ingest submux, added ahead of that submux itself (slice 2).
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// tokenIDBytes and rawTokenBytes are the random byte lengths behind,
// respectively, a canary_tokens.id and the bearer token itself -- 128
// and 256 bits, hex-encoded by MintCanaryToken.
const (
	tokenIDBytes  = 16
	rawTokenBytes = 32
)

// CanaryToken is one canary_tokens row as read back by
// LookupCanaryTokenByHash. It never carries the raw token value -- that
// exists only as MintCanaryToken's return value, at mint time.
type CanaryToken struct {
	ID         string
	CanaryID   string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// ErrTokenNotFound is returned by LookupCanaryTokenByHash when hash
// matches no row, and by RevokeCanaryToken/RecordCanaryTokenUse when id
// names no row -- callers map it to 401/404 as their context requires.
var ErrTokenNotFound = errors.New("store: canary token not found")

// HashToken returns the SHA-256 hash (hex-encoded) of a raw token value
// -- the form canary_tokens.token_hash stores and LookupCanaryTokenByHash
// looks up by. Exported so the ingest endpoint (#32 slice 2) can hash a
// bearer token it receives without duplicating this package's hash
// choice.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// randomHex returns n random bytes (crypto/rand) as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// MintCanaryToken generates a fresh bearer token for canaryID, stores
// only its SHA-256 hash (never the raw value), and returns the raw value
// -- the only moment it is ever available to a caller; no store function
// can recover it afterwards. createdAt must be set by the caller (e.g.
// time.Now().UTC()), matching InsertCanary's and audit.Append's stance
// on their own created-at fields.
func MintCanaryToken(ctx context.Context, database *db.DB, canaryID string, createdAt time.Time) (raw string, token CanaryToken, err error) {
	if createdAt.IsZero() {
		return "", CanaryToken{}, fmt.Errorf("store: MintCanaryToken: createdAt is zero; callers must set it")
	}
	id, err := randomHex(tokenIDBytes)
	if err != nil {
		return "", CanaryToken{}, fmt.Errorf("generate token id: %w", err)
	}
	raw, err = randomHex(rawTokenBytes)
	if err != nil {
		return "", CanaryToken{}, fmt.Errorf("generate token: %w", err)
	}
	createdAt = createdAt.UTC()

	_, err = database.ExecContext(ctx, `
		INSERT INTO canary_tokens (id, canary_id, token_hash, created_at)
		VALUES (?, ?, ?, ?)`,
		id, canaryID, HashToken(raw), createdAt.Format(receivedAtLayout))
	if err != nil {
		return "", CanaryToken{}, fmt.Errorf("insert canary token: %w", err)
	}
	return raw, CanaryToken{ID: id, CanaryID: canaryID, CreatedAt: createdAt}, nil
}

// LookupCanaryTokenByHash resolves hash (as produced by HashToken) to its
// CanaryToken row. A revoked row (revoked_at set) is excluded at the SQL
// level -- WHERE revoked_at IS NULL, not an application-level check
// after the fact -- so it is indistinguishable from a hash that matches
// no row at all: both return ErrTokenNotFound.
func LookupCanaryTokenByHash(ctx context.Context, database *db.DB, hash string) (CanaryToken, error) {
	row := database.QueryRowContext(ctx, `
		SELECT id, canary_id, created_at, last_used_at, revoked_at
		FROM canary_tokens
		WHERE token_hash = ? AND revoked_at IS NULL`, hash)
	return scanCanaryToken(row)
}

func scanCanaryToken(row *sql.Row) (CanaryToken, error) {
	var (
		t          CanaryToken
		createdAt  string
		lastUsedAt *string
		revokedAt  *string
	)
	if err := row.Scan(&t.ID, &t.CanaryID, &createdAt, &lastUsedAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CanaryToken{}, ErrTokenNotFound
		}
		return CanaryToken{}, fmt.Errorf("scan canary token: %w", err)
	}
	parsed, err := time.Parse(receivedAtLayout, createdAt)
	if err != nil {
		return CanaryToken{}, fmt.Errorf("parse created_at %q: %w", createdAt, err)
	}
	t.CreatedAt = parsed
	if lastUsedAt != nil {
		parsed, err := time.Parse(receivedAtLayout, *lastUsedAt)
		if err != nil {
			return CanaryToken{}, fmt.Errorf("parse last_used_at %q: %w", *lastUsedAt, err)
		}
		t.LastUsedAt = &parsed
	}
	if revokedAt != nil {
		parsed, err := time.Parse(receivedAtLayout, *revokedAt)
		if err != nil {
			return CanaryToken{}, fmt.Errorf("parse revoked_at %q: %w", *revokedAt, err)
		}
		t.RevokedAt = &parsed
	}
	return t, nil
}

// LookupCanaryTokenByHashAnyStatus resolves hash to its CanaryToken row
// regardless of revocation -- unlike LookupCanaryTokenByHash, which the
// ingest auth path uses and which deliberately cannot see revoked rows
// (issue #32 slice 1). This exists only for the token-conflict check
// (slice 5, fail-closed: "slice 1's lookup deliberately cannot see
// revoked rows, so slice 5 adds a separate internal lookup for the
// conflict check; the external 401 must not change"): telling a
// revoked-but-once-valid token apart from a hash that was never minted
// at all is exactly what the ingest auth path must not be able to do.
func LookupCanaryTokenByHashAnyStatus(ctx context.Context, database *db.DB, hash string) (CanaryToken, error) {
	row := database.QueryRowContext(ctx, `
		SELECT id, canary_id, created_at, last_used_at, revoked_at
		FROM canary_tokens
		WHERE token_hash = ?`, hash)
	return scanCanaryToken(row)
}

// CanaryHasActiveToken reports whether canaryID has at least one
// non-revoked token. Paired with LookupCanaryTokenByHashAnyStatus to
// tell a token conflict (a revoked token presented while a successor is
// active -- issue #32 slice 5, "the one observable difference between a
// stolen token, a cloned box and noise") apart from a canary whose every
// token happens to be revoked, which is not a conflict.
func CanaryHasActiveToken(ctx context.Context, database *db.DB, canaryID string) (bool, error) {
	var n int
	err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM canary_tokens WHERE canary_id = ? AND revoked_at IS NULL`,
		canaryID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("count active canary tokens: %w", err)
	}
	return n > 0, nil
}

// RevokeOtherCanaryTokens revokes every non-revoked token for canaryID
// except keepID, and reports how many rows it changed. This is issue
// #32 slice 5's central rotation rule (owner, 2026-09-14, replacing "the
// old token is revoked the moment the new one is used" alone): "first
// use of the new token revokes every older token for that canary, not
// just the one presented" -- so an orphaned, issued-but-never-used token
// (a lost rotation response) dies the next time any token for the same
// canary is first used, not only at its own first use. Uses the same
// COALESCE-on-revoked_at shape as RevokeCanaryToken, so a row this call
// revokes keeps whatever revocation timestamp it already had if it was
// somehow revoked a moment earlier.
func RevokeOtherCanaryTokens(ctx context.Context, database *db.DB, canaryID, keepID string, at time.Time) (int64, error) {
	res, err := database.ExecContext(ctx,
		`UPDATE canary_tokens SET revoked_at = COALESCE(revoked_at, ?)
		 WHERE canary_id = ? AND id != ? AND revoked_at IS NULL`,
		at.UTC().Format(receivedAtLayout), canaryID, keepID)
	if err != nil {
		return 0, fmt.Errorf("revoke other canary tokens: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return n, nil
}

// RevokeCanaryToken sets id's revoked_at to at, so every subsequent
// LookupCanaryTokenByHash call for it returns ErrTokenNotFound. Returns
// ErrTokenNotFound if id names no row. Revoking an already-revoked token
// succeeds and changes nothing: COALESCE keeps the first revocation's
// timestamp, which is the one the audit trail (#32 item 10) reports, so
// a second call cannot move the moment the token stopped working.
func RevokeCanaryToken(ctx context.Context, database *db.DB, id string, at time.Time) error {
	res, err := database.ExecContext(ctx,
		`UPDATE canary_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`,
		at.UTC().Format(receivedAtLayout), id)
	if err != nil {
		return fmt.Errorf("revoke canary token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrTokenNotFound
	}
	return nil
}

// RecordCanaryTokenUse sets id's last_used_at to at, the write side of
// "record last use" (issue #32 slice 1); the ingest endpoint (slice 2)
// calls it once per authenticated request. Returns ErrTokenNotFound if
// id names no row.
func RecordCanaryTokenUse(ctx context.Context, database *db.DB, id string, at time.Time) error {
	res, err := database.ExecContext(ctx,
		`UPDATE canary_tokens SET last_used_at = ? WHERE id = ?`,
		at.UTC().Format(receivedAtLayout), id)
	if err != nil {
		return fmt.Errorf("record canary token use: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrTokenNotFound
	}
	return nil
}
