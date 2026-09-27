// Package store: this file is issue #54's upgrade token (owner,
// 2026-09-27; ADR-0012's B4 amendment). The printed upgrade command
// carries a single-use token bound to one agent; the new build's binary
// presents it once, over the agent's own certificate and bearer token,
// before the new agent starts, and birdcage then gives that agent a
// five-minute window in which the switch from the old build to the new
// one is not credential_conflict.
// Migration 0027 has the table and the reasons for its shape.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

const (
	// UpgradeTokenTTL is how long a minted upgrade token can be
	// presented (owner, 2026-09-27: "Valid for 15 minutes").
	UpgradeTokenTTL = 15 * time.Minute

	// UpgradeWindow is how long, from the token's acceptance, the old
	// build may keep heartbeating beside the new one without B4 flagging
	// the version change (owner, 2026-09-27: "a five minute window exists
	// for the old agent to disappear"). After it, detection is exactly as
	// before.
	UpgradeWindow = 5 * time.Minute

	// upgradeTokenBytes is the token's random length: 256 bits, 64 hex
	// characters, the same as a bearer token.
	upgradeTokenBytes = 32
)

// ErrAgentNotBehind is MintUpgradeToken's refusal for an agent whose
// last-reported build is not behind birdcage's own (agentBehindBirdcage):
// there is no upgrade to cover, so no window to hand out.
var ErrAgentNotBehind = errors.New("store: agent is not behind birdcage; no upgrade token minted")

// UpgradeToken is one upgrade_tokens row as MintUpgradeToken returns it.
// It never carries the raw token, which exists only as MintUpgradeToken's
// own return value.
type UpgradeToken struct {
	ID          string
	CanaryID    string
	FromVersion string
	ToVersion   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// MintUpgradeToken mints a single-use upgrade token for canaryID, valid
// for UpgradeTokenTTL from now, and stores only its hash. The version
// pair the eventual window covers is fixed here: the agent's own
// last-reported build (from) and birdcageVersion (to). Every earlier
// unused token for the same agent is superseded in the same call, so at
// most one is live per agent. Returns ErrCanaryNotFound for an unknown
// agent and ErrAgentNotBehind when the agent is not behind birdcageVersion.
//
// Callers run it in the transaction that writes its audit row, so a
// token is never live without its record.
func MintUpgradeToken(ctx context.Context, database db.Conn, canaryID, birdcageVersion string, now time.Time) (raw string, tok UpgradeToken, err error) {
	if now.IsZero() {
		return "", UpgradeToken{}, fmt.Errorf("store: MintUpgradeToken: now is zero; callers must set it")
	}
	now = now.UTC()

	var agentVersion *string
	if err := database.QueryRowContext(ctx, `SELECT agent_version FROM agents WHERE id = ?`, canaryID).Scan(&agentVersion); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", UpgradeToken{}, ErrCanaryNotFound
		}
		return "", UpgradeToken{}, fmt.Errorf("read agent version: %w", err)
	}
	from := ""
	if agentVersion != nil {
		from = *agentVersion
	}
	if !agentBehindBirdcage(from, birdcageVersion) {
		return "", UpgradeToken{}, ErrAgentNotBehind
	}

	id, err := randomHex(tokenIDBytes)
	if err != nil {
		return "", UpgradeToken{}, fmt.Errorf("generate upgrade token id: %w", err)
	}
	raw, err = randomHex(upgradeTokenBytes)
	if err != nil {
		return "", UpgradeToken{}, fmt.Errorf("generate upgrade token: %w", err)
	}

	if _, err := database.ExecContext(ctx, `
		UPDATE upgrade_tokens SET superseded_at = ?
		WHERE agent_id = ? AND used_at IS NULL AND superseded_at IS NULL`,
		now.Format(receivedAtLayout), canaryID); err != nil {
		return "", UpgradeToken{}, fmt.Errorf("supersede earlier upgrade tokens: %w", err)
	}

	expires := now.Add(UpgradeTokenTTL)
	if _, err := database.ExecContext(ctx, `
		INSERT INTO upgrade_tokens (id, agent_id, token_hash, from_version, to_version, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, canaryID, HashToken(raw), from, birdcageVersion,
		now.Format(receivedAtLayout), expires.Format(receivedAtLayout)); err != nil {
		return "", UpgradeToken{}, fmt.Errorf("insert upgrade token: %w", err)
	}
	return raw, UpgradeToken{
		ID: id, CanaryID: canaryID, FromVersion: from, ToVersion: birdcageVersion,
		CreatedAt: now, ExpiresAt: expires,
	}, nil
}

// UpgradeTokenOutcome is what PresentUpgradeToken made of a presented
// token.
type UpgradeTokenOutcome int

const (
	// UpgradeTokenAccepted: this call spent the token and opened the
	// window.
	UpgradeTokenAccepted UpgradeTokenOutcome = iota
	// UpgradeTokenSpent: the token is this agent's own and was already
	// spent -- a second paste of the same command, or the loser of two
	// concurrent presentations. Opens nothing.
	UpgradeTokenSpent
	// UpgradeTokenUnknown: no token has this hash, or the value is not
	// shaped like one.
	UpgradeTokenUnknown
	// UpgradeTokenWrongAgent: the token was minted for another agent.
	UpgradeTokenWrongAgent
	// UpgradeTokenExpired: unused, but past UpgradeTokenTTL.
	UpgradeTokenExpired
	// UpgradeTokenSuperseded: unused, but a newer token was minted for
	// the same agent.
	UpgradeTokenSuperseded
)

// String is the outcome's audit wording.
func (o UpgradeTokenOutcome) String() string {
	switch o {
	case UpgradeTokenAccepted:
		return "accepted"
	case UpgradeTokenSpent:
		return "already used"
	case UpgradeTokenUnknown:
		return "unknown token"
	case UpgradeTokenWrongAgent:
		return "minted for another agent"
	case UpgradeTokenExpired:
		return "expired"
	case UpgradeTokenSuperseded:
		return "superseded by a newer token"
	default:
		return fmt.Sprintf("outcome(%d)", int(o))
	}
}

// UpgradeTokenResult is PresentUpgradeToken's answer.
type UpgradeTokenResult struct {
	Outcome UpgradeTokenOutcome

	// TokenCanaryID is the agent the token was minted for; set for every
	// outcome but UpgradeTokenUnknown. For UpgradeTokenWrongAgent it is
	// the other agent, which is audit evidence, never shown to the
	// presenter.
	TokenCanaryID string

	// FromVersion, ToVersion and WindowUntil are set on
	// UpgradeTokenAccepted only.
	FromVersion string
	ToVersion   string
	WindowUntil time.Time
}

// validUpgradeTokenShape reports whether raw looks like a minted token:
// exactly 64 lowercase hex characters. Anything else is
// UpgradeTokenUnknown without a lookup.
func validUpgradeTokenShape(raw string) bool {
	if len(raw) != 2*upgradeTokenBytes {
		return false
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type upgradeTokenRow struct {
	id, canaryID, from, to string
	expiresAt              time.Time
	usedAt, supersededAt   *string
}

func lookupUpgradeToken(ctx context.Context, database *db.DB, hash string) (upgradeTokenRow, bool, error) {
	var (
		r       upgradeTokenRow
		expires string
	)
	err := database.QueryRowContext(ctx, `
		SELECT id, agent_id, from_version, to_version, expires_at, used_at, superseded_at
		FROM upgrade_tokens WHERE token_hash = ?`, hash).
		Scan(&r.id, &r.canaryID, &r.from, &r.to, &expires, &r.usedAt, &r.supersededAt)
	if errors.Is(err, sql.ErrNoRows) {
		return upgradeTokenRow{}, false, nil
	}
	if err != nil {
		return upgradeTokenRow{}, false, fmt.Errorf("look up upgrade token: %w", err)
	}
	if r.expiresAt, err = time.Parse(receivedAtLayout, expires); err != nil {
		return upgradeTokenRow{}, false, fmt.Errorf("parse upgrade token expiry %q: %w", expires, err)
	}
	return r, true, nil
}

// classifyUpgradeToken is every refusal PresentUpgradeToken can make
// from a row alone, in precedence order: another agent's token is that,
// whatever else is true of it, so a spent token of another agent's is
// still audited rather than logged quietly.
func classifyUpgradeToken(r upgradeTokenRow, canaryID string, now time.Time) (UpgradeTokenOutcome, bool) {
	switch {
	case r.canaryID != canaryID:
		return UpgradeTokenWrongAgent, true
	case r.usedAt != nil:
		return UpgradeTokenSpent, true
	case r.supersededAt != nil:
		return UpgradeTokenSuperseded, true
	case !now.Before(r.expiresAt):
		return UpgradeTokenExpired, true
	}
	return 0, false
}

// PresentUpgradeToken is the ingest side of an upgrade token: canaryID
// (the presenting credential's own agent, never anything the body says)
// presents raw at now. The token is accepted only when its hash matches
// an unused, unsuperseded, unexpired token minted for canaryID; it is
// then marked used with a single guarded UPDATE (WHERE used_at IS NULL),
// so of two concurrent presentations exactly one is accepted, and the
// window runs UpgradeWindow from now. Every other outcome opens nothing.
//
// The returned error is birdcage's own storage trouble only; a refusal
// is an outcome, not an error.
func PresentUpgradeToken(ctx context.Context, database *db.DB, canaryID, raw string, now time.Time) (UpgradeTokenResult, error) {
	if now.IsZero() {
		return UpgradeTokenResult{}, fmt.Errorf("store: PresentUpgradeToken: now is zero; callers must set it")
	}
	now = now.UTC()
	if !validUpgradeTokenShape(raw) {
		return UpgradeTokenResult{Outcome: UpgradeTokenUnknown}, nil
	}
	hash := HashToken(raw)

	r, found, err := lookupUpgradeToken(ctx, database, hash)
	if err != nil {
		return UpgradeTokenResult{}, err
	}
	if !found {
		return UpgradeTokenResult{Outcome: UpgradeTokenUnknown}, nil
	}
	if outcome, refused := classifyUpgradeToken(r, canaryID, now); refused {
		return UpgradeTokenResult{Outcome: outcome, TokenCanaryID: r.canaryID}, nil
	}

	windowUntil := now.Add(UpgradeWindow)
	res, err := database.ExecContext(ctx, `
		UPDATE upgrade_tokens SET used_at = ?, window_until = ?
		WHERE id = ? AND agent_id = ? AND used_at IS NULL AND superseded_at IS NULL`,
		now.Format(receivedAtLayout), windowUntil.Format(receivedAtLayout), r.id, canaryID)
	if err != nil {
		return UpgradeTokenResult{}, fmt.Errorf("spend upgrade token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return UpgradeTokenResult{}, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		// Lost a race: another presentation spent it, or a mint
		// superseded it, between the read and this write. Read it again
		// to say which.
		r, found, err = lookupUpgradeToken(ctx, database, hash)
		if err != nil {
			return UpgradeTokenResult{}, err
		}
		if !found {
			return UpgradeTokenResult{Outcome: UpgradeTokenUnknown}, nil
		}
		outcome, refused := classifyUpgradeToken(r, canaryID, now)
		if !refused {
			outcome = UpgradeTokenSpent
		}
		return UpgradeTokenResult{Outcome: outcome, TokenCanaryID: r.canaryID}, nil
	}
	return UpgradeTokenResult{
		Outcome:       UpgradeTokenAccepted,
		TokenCanaryID: canaryID,
		FromVersion:   r.from,
		ToVersion:     r.to,
		WindowUntil:   windowUntil,
	}, nil
}

// upgradeWindow is one spent token's window, as upgradeWindows reads it.
type upgradeWindow struct {
	from, to string
	until    time.Time
}

// upgradeWindows returns every spent token's window for canaryID that
// is still open at now. Almost always none or one; a second is only
// possible if an operator minted and used another token inside five
// minutes.
func upgradeWindows(ctx context.Context, database *db.DB, canaryID string, now time.Time) ([]upgradeWindow, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT from_version, to_version, window_until FROM upgrade_tokens
		WHERE agent_id = ? AND used_at IS NOT NULL AND window_until IS NOT NULL`, canaryID)
	if err != nil {
		return nil, fmt.Errorf("list upgrade windows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var open []upgradeWindow
	for rows.Next() {
		var w upgradeWindow
		var until string
		if err := rows.Scan(&w.from, &w.to, &until); err != nil {
			return nil, fmt.Errorf("scan upgrade window: %w", err)
		}
		if w.until, err = time.Parse(receivedAtLayout, until); err != nil {
			return nil, fmt.Errorf("parse upgrade window end %q: %w", until, err)
		}
		if now.Before(w.until) {
			open = append(open, w)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list upgrade windows: %w", err)
	}
	return open, nil
}

// OpenUpgradeWindowUntil returns when canaryID's open upgrade window
// ends, or nil when it has none open at now -- the upgrade_in_progress
// state's whole input.
func OpenUpgradeWindowUntil(ctx context.Context, database *db.DB, canaryID string, now time.Time) (*time.Time, error) {
	windows, err := upgradeWindows(ctx, database, canaryID, now)
	if err != nil {
		return nil, err
	}
	var latest *time.Time
	for i := range windows {
		if latest == nil || windows[i].until.After(*latest) {
			latest = &windows[i].until
		}
	}
	return latest, nil
}

// UpgradeWindowCovers reports whether canaryID has an open upgrade
// window, as of now, whose version pair is exactly {a, b} in either
// order. It is the one question internal/ingest asks before recording a
// version dual use (ADR-0012 B4): a covered pair is the old build
// disappearing, anything else -- a third version, a window that has
// closed, an agent that never had one -- is flagged as before. Address
// dual use never asks.
func UpgradeWindowCovers(ctx context.Context, database *db.DB, canaryID, a, b string, now time.Time) (bool, error) {
	windows, err := upgradeWindows(ctx, database, canaryID, now)
	if err != nil {
		return false, err
	}
	for _, w := range windows {
		if (a == w.from && b == w.to) || (a == w.to && b == w.from) {
			return true, nil
		}
	}
	return false, nil
}
