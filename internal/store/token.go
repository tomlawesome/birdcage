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

	"github.com/tomlawesome/birdcage/internal/agentkind"
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

	// Kind is canaries.kind for this token's CanaryID, read via a LEFT
	// JOIN (issue #106) -- populated only by LookupCanaryTokenByHash,
	// the one caller on the ingest auth seam that needs it to authorise
	// a route. Every other lookup in this file leaves it at its zero
	// value (""). LEFT, not INNER: canary_tokens carries no foreign key
	// into canaries (migration 0004_canary_tokens.sql's own comment), so
	// a live token whose canaries row is missing (or was deleted out
	// from under it) resolves with Kind == "", which refuses every
	// kind-gated route -- agentkind.Valid("") is false -- rather than
	// the join silently dropping the row instead.
	Kind agentkind.Kind

	// CertFingerprint is canary_tokens.cert_fingerprint (issue #130,
	// ADR-0012 B3): the SHA-256 fingerprint of the client certificate
	// this token is bound to, "" when the column is NULL. Populated only
	// by LookupCanaryTokenByHash, like Kind; see TokenBoundToCert for how
	// the auth path uses it.
	CertFingerprint string
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
func MintCanaryToken(ctx context.Context, database db.Conn, canaryID string, createdAt time.Time) (raw string, token CanaryToken, err error) {
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
// CanaryToken row, with its canary's registered kind (issue #106) LEFT
// JOINed in -- see CanaryToken.Kind's own doc comment for why LEFT and
// why a missing row still resolves rather than failing the lookup: an
// unknown kind is this function's caller's problem (it refuses at the
// route), not this function's. A revoked row (revoked_at set) is
// excluded at the SQL level -- WHERE revoked_at IS NULL, not an
// application-level check after the fact -- so it is indistinguishable
// from a hash that matches no row at all: both return ErrTokenNotFound.
func LookupCanaryTokenByHash(ctx context.Context, database *db.DB, hash string) (CanaryToken, error) {
	row := database.QueryRowContext(ctx, `
		SELECT canary_tokens.id, canary_tokens.canary_id, canary_tokens.created_at,
			canary_tokens.last_used_at, canary_tokens.revoked_at, canaries.kind,
			canary_tokens.cert_fingerprint
		FROM canary_tokens
		LEFT JOIN canaries ON canaries.id = canary_tokens.canary_id
		WHERE canary_tokens.token_hash = ? AND canary_tokens.revoked_at IS NULL`, hash)
	return scanCanaryTokenWithKind(row)
}

// rowScanner is the common surface of *sql.Row and *sql.Rows that
// scanCanaryToken needs, so the single-row lookups above and
// ListCanaryTokens' multi-row scan below share one scan implementation
// rather than duplicating the column list and its NULL/time handling.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanCanaryToken(row rowScanner) (CanaryToken, error) {
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
	return finishCanaryToken(t, createdAt, lastUsedAt, revokedAt)
}

// scanCanaryTokenWithKind is scanCanaryToken plus the LEFT JOINed
// canaries.kind column LookupCanaryTokenByHash's own query adds (issue
// #106) -- a separate function, not a parameter threaded through
// scanCanaryToken, because every other caller in this file selects no
// such column and must not be made to guess one. kind is scanned as a
// nullable string (the LEFT JOIN's own NULL, for a token whose canaries
// row is missing) and converted to agentkind.Kind's zero value ("") in
// that case, never guessed at.
func scanCanaryTokenWithKind(row rowScanner) (CanaryToken, error) {
	var (
		t          CanaryToken
		createdAt  string
		lastUsedAt *string
		revokedAt  *string
		kind       *string
		certFP     *string
	)
	if err := row.Scan(&t.ID, &t.CanaryID, &createdAt, &lastUsedAt, &revokedAt, &kind, &certFP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CanaryToken{}, ErrTokenNotFound
		}
		return CanaryToken{}, fmt.Errorf("scan canary token: %w", err)
	}
	if kind != nil {
		t.Kind = agentkind.Kind(*kind)
	}
	if certFP != nil {
		t.CertFingerprint = *certFP
	}
	return finishCanaryToken(t, createdAt, lastUsedAt, revokedAt)
}

// finishCanaryToken parses the three timestamp columns both scanners
// above read as text and sets them on t. Shared so the two scanners
// differ only in the columns they select, not in how a timestamp is
// read.
func finishCanaryToken(t CanaryToken, createdAt string, lastUsedAt, revokedAt *string) (CanaryToken, error) {
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

// LookupCanaryTokenByID resolves id to its CanaryToken row, regardless of
// revocation status -- unlike LookupCanaryTokenByHash. The CLI's `canary
// revoke` (issue #32 item 9) uses this to find which canary owns a token
// id before revoking it, so the audit entry (item 10) names the right
// canary; RevokeCanaryToken treats revoking an already-revoked token as a
// harmless no-op, so this lookup must be able to see a revoked row too,
// not reject it as not-found the way LookupCanaryTokenByHash's ingest-auth
// callers need. database is db.Conn so this can run inside the same
// transaction as the revoke and its audit write.
func LookupCanaryTokenByID(ctx context.Context, database db.Conn, id string) (CanaryToken, error) {
	row := database.QueryRowContext(ctx, `
		SELECT id, canary_id, created_at, last_used_at, revoked_at
		FROM canary_tokens
		WHERE id = ?`, id)
	return scanCanaryToken(row)
}

// ListCanaryTokens returns every canary_tokens row, ordered by canary id
// then mint time -- the read path for `birdcage canary list` (issue #32
// item 9: "list never printing a token"). CanaryToken has no field for
// the raw token or its hash, and this query doesn't select token_hash
// either, so there is nothing here a caller could print by mistake.
func ListCanaryTokens(ctx context.Context, database *db.DB) ([]CanaryToken, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT id, canary_id, created_at, last_used_at, revoked_at
		FROM canary_tokens
		ORDER BY canary_id, created_at`)
	if err != nil {
		return nil, fmt.Errorf("list canary tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []CanaryToken
	for rows.Next() {
		t, err := scanCanaryToken(rows)
		if err != nil {
			return nil, fmt.Errorf("scan canary token: %w", err)
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate canary tokens: %w", err)
	}
	return tokens, nil
}

// ListCanaryTokensForCanary returns every canary_tokens row for canaryID,
// in no particular order. Issue #45's rotation-stalled signal needs them
// ordered by mint time to find the latest issuance and the latest
// activated (first-used) token; that ordering happens in Go on parsed
// CreatedAt values, the same rule RevokeCanaryTokensSupersededBy's own
// doc comment explains (SQL ORDER BY on the raw TEXT column would
// reintroduce the trimmed-fractional-second bug).
func ListCanaryTokensForCanary(ctx context.Context, database *db.DB, canaryID string) ([]CanaryToken, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT id, canary_id, created_at, last_used_at, revoked_at
		FROM canary_tokens
		WHERE canary_id = ?`, canaryID)
	if err != nil {
		return nil, fmt.Errorf("list canary tokens for canary: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tokens []CanaryToken
	for rows.Next() {
		t, err := scanCanaryToken(rows)
		if err != nil {
			return nil, fmt.Errorf("scan canary token: %w", err)
		}
		tokens = append(tokens, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate canary tokens: %w", err)
	}
	return tokens, nil
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

// RevokeCanaryTokensSupersededBy revokes every live token for
// tok.CanaryID that was minted BEFORE tok, and reports how many rows it
// changed. This is issue #32 slice 5's central rotation rule (owner,
// 2026-09-14): "first use of the new token revokes every older token for
// that canary, not just the one presented" -- so an orphaned,
// issued-but-never-used token (a lost rotation response) dies when a
// later token is first used.
//
// Older, not merely other. Revoking every other live token would mean an
// agent that presents its OLD token once more -- a retry already in
// flight when it rotated, say -- killing the newer token it had just
// been issued and is about to switch to. The agent would then hold a
// credential birdcage has revoked, and its only way back is
// re-enrolment (#47). Comparing on created_at removes that path: a
// token can only ever be superseded by a later one.
//
// The comparison happens in Go, on parsed timestamps, rather than in SQL.
// SQL would be the obvious home for it, but the two engines do not agree
// on how finely they compare a stored timestamp: SQLite's julianday()
// works to roughly 50 microseconds, Postgres to a microsecond. Two
// tokens minted inside one of those quanta compare EQUAL on SQLite, so
// the older one silently survives a sweep that supersedes it on
// Postgres -- a rule that quietly means something different on each
// engine. It showed up first as two rotation tests failing now and then,
// which is the cheap version of the same bug. Parsing both sides and
// comparing them here is exact everywhere.
//
// Uses the same COALESCE-on-revoked_at shape as RevokeCanaryToken, so a
// row this call revokes keeps whatever revocation timestamp it already
// had if it was somehow revoked a moment earlier.
func RevokeCanaryTokensSupersededBy(ctx context.Context, database *db.DB, tok CanaryToken, at time.Time) (int64, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT id, created_at FROM canary_tokens
		 WHERE canary_id = ? AND id != ? AND revoked_at IS NULL`,
		tok.CanaryID, tok.ID)
	if err != nil {
		return 0, fmt.Errorf("list live canary tokens: %w", err)
	}
	var older []string
	for rows.Next() {
		var id, createdAt string
		if err := rows.Scan(&id, &createdAt); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan canary token: %w", err)
		}
		parsed, err := time.Parse(receivedAtLayout, createdAt)
		if err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("parse created_at %q: %w", createdAt, err)
		}
		if parsed.Before(tok.CreatedAt) {
			older = append(older, id)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("iterate canary tokens: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close canary tokens: %w", err)
	}

	var revoked int64
	for _, id := range older {
		res, err := database.ExecContext(ctx,
			`UPDATE canary_tokens SET revoked_at = COALESCE(revoked_at, ?)
			 WHERE id = ? AND revoked_at IS NULL`,
			at.UTC().Format(receivedAtLayout), id)
		if err != nil {
			return revoked, fmt.Errorf("revoke superseded canary token: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return revoked, fmt.Errorf("rows affected: %w", err)
		}
		revoked += n
	}
	return revoked, nil
}

// RevokeCanaryToken sets id's revoked_at to at, so every subsequent
// LookupCanaryTokenByHash call for it returns ErrTokenNotFound -- the
// next ingest request authenticating with it is refused, immediately,
// since that lookup runs fresh per request with no cache to invalidate.
// Returns ErrTokenNotFound if id names no row. Revoking an already-revoked
// token succeeds and changes nothing: COALESCE keeps the first
// revocation's timestamp, which is the one the audit trail (#32 item 10)
// reports, so a second call cannot move the moment the token stopped
// working. database is db.Conn so the CLI's `canary revoke` (item 9) can
// run this and its audit write in one transaction, the same pattern
// internal/ingest/rotate.go uses for mint-plus-audit.
func RevokeCanaryToken(ctx context.Context, database db.Conn, id string, at time.Time) error {
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
