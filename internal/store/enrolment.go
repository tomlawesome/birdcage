// Package store: this file is the write/lookup path for
// enrolment_sessions (issue #47 slice 1b) -- the deploy token a freshly
// booted canary presents exactly once, to POST /enrol/hello
// (internal/enrol), in exchange for the enrolment secret it uses for the
// rest of enrolment. See 0009_enrolment_sessions.sql for the row shape
// and the design note decisions this file implements.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// enrolmentSessionIDBytes and enrolmentTokenBytes are the random byte
// lengths behind, respectively, an enrolment_sessions.id and the deploy
// token itself -- matching canary_tokens' tokenIDBytes/rawTokenBytes.
// enrolmentSecretBytes is the same length for the secret FirstContact
// mints.
const (
	enrolmentSessionIDBytes = 16
	enrolmentTokenBytes     = 32
	enrolmentSecretBytes    = 32

	// enrolmentFirstContactWindow is design note decision 1's five
	// minutes: a deploy token not presented to POST /enrol/hello within
	// this long of its mint can never succeed.
	enrolmentFirstContactWindow = 5 * time.Minute
	// enrolmentContactWindow is design note decision 1's thirty minutes:
	// how long a session has, from first contact, to finish provisioning
	// (a later slice enforces this; this slice only records the
	// deadline).
	enrolmentContactWindow = 30 * time.Minute
)

// EnrolmentState is the closed set of states an enrolment_sessions row
// can be in -- kept in Go rather than a SQL CHECK constraint, the same
// reasoning settings.go's SettingKey and command.go's CommandKind both
// use.
type EnrolmentState string

const (
	EnrolmentStateMinted      EnrolmentState = "minted"
	EnrolmentStateContacted   EnrolmentState = "contacted"
	EnrolmentStateProvisioned EnrolmentState = "provisioned"
	EnrolmentStateVerified    EnrolmentState = "verified"
	EnrolmentStateExpired     EnrolmentState = "expired"
	EnrolmentStateFailed      EnrolmentState = "failed"
)

// EnrolmentSession is one enrolment_sessions row as read back by
// FirstContact and ListEnrolmentSessions. It never carries the raw
// deploy token or the raw enrolment secret, nor either one's hash --
// those exist only as MintEnrolmentSession's and FirstContact's own
// return values, at the moment each is minted, matching CanaryToken's
// stance on the raw bearer token.
type EnrolmentSession struct {
	ID                   string
	CreatedAt            time.Time
	FirstContactDeadline time.Time
	BurnedAt             *time.Time
	WindowDeadline       *time.Time
	State                EnrolmentState
	CanaryID             *string
}

// ErrEnrolmentSessionNotFound is returned when a token hash or session
// id names no row.
var ErrEnrolmentSessionNotFound = errors.New("store: enrolment session not found")

// MintEnrolmentSession generates a fresh deploy token, stores only its
// SHA-256 hash (never the raw value), and returns the raw value -- the
// only moment it is ever available to a caller; no store function can
// recover it afterwards. now must be set by the caller (e.g.
// time.Now().UTC()), matching MintCanaryToken's stance on its own
// createdAt.
func MintEnrolmentSession(ctx context.Context, database db.Conn, now time.Time) (raw string, session EnrolmentSession, err error) {
	if now.IsZero() {
		return "", EnrolmentSession{}, fmt.Errorf("store: MintEnrolmentSession: now is zero; callers must set it")
	}
	id, err := randomHex(enrolmentSessionIDBytes)
	if err != nil {
		return "", EnrolmentSession{}, fmt.Errorf("generate enrolment session id: %w", err)
	}
	raw, err = randomHex(enrolmentTokenBytes)
	if err != nil {
		return "", EnrolmentSession{}, fmt.Errorf("generate deploy token: %w", err)
	}

	createdAt := now.UTC()
	deadline := createdAt.Add(enrolmentFirstContactWindow)

	_, err = database.ExecContext(ctx, `
		INSERT INTO enrolment_sessions (id, token_hash, created_at, first_contact_deadline, state)
		VALUES (?, ?, ?, ?, ?)`,
		id, HashToken(raw), createdAt.Format(receivedAtLayout), deadline.Format(receivedAtLayout), string(EnrolmentStateMinted))
	if err != nil {
		return "", EnrolmentSession{}, fmt.Errorf("insert enrolment session: %w", err)
	}
	return raw, EnrolmentSession{
		ID:                   id,
		CreatedAt:            createdAt,
		FirstContactDeadline: deadline,
		State:                EnrolmentStateMinted,
	}, nil
}

// FirstContactOutcome is what FirstContact found the presented token to
// be -- Unknown, Expired and Reused all drive the identical refusal
// internal/enrol sends a caller (design note decision 1: "unknown/
// expired/burned all get the same HTTP response"); only the caller (which
// gets to see the session id for its audit entry) can tell them apart.
type FirstContactOutcome int

const (
	// Contacted is success: the token resolved to a live, unburned
	// session within its first-contact deadline, and this call minted
	// and returned its enrolment secret.
	Contacted FirstContactOutcome = iota
	// Unknown means the hash matched no row at all.
	Unknown
	// Expired means the row was found, never burned, but its
	// first_contact_deadline has passed. FirstContact moves it to state
	// "expired" as a side effect.
	Expired
	// Reused means the row was found already burned -- either an
	// earlier, successful first contact, or a concurrent one that won
	// the race this call lost.
	Reused
)

// String renders o for logging; never for a caller-visible response,
// which must stay the fixed {"error":"refused"} body regardless of which
// of these three this is.
func (o FirstContactOutcome) String() string {
	switch o {
	case Contacted:
		return "contacted"
	case Unknown:
		return "unknown"
	case Expired:
		return "expired"
	case Reused:
		return "reused"
	default:
		return "invalid"
	}
}

// FirstContact resolves tokenHash (as produced by HashToken) against
// enrolment_sessions and, on success, burns the session and mints its
// enrolment secret -- all in one transaction, per design note decision
// 1: "First contact sets burned_at in the same transaction that
// generates the enrolment secret." A crash after this call's internal
// commit but before its caller returns a response leaves the row burned
// and the secret undelivered; FirstContact never re-issues one for an
// already-burned row (the Reused case below), by design -- the operator
// re-mints instead.
//
// database is *db.DB rather than db.Conn: unlike this package's other
// mint functions, FirstContact owns its whole transaction rather than
// composing into a caller's, since the lookup, the burn and the secret
// mint must happen atomically and nothing calling this needs to fold
// them into a larger transaction of its own (internal/enrol writes its
// Reused audit entry separately, after this returns, deliberately
// outside this transaction -- see that package's handler).
func FirstContact(ctx context.Context, database *db.DB, tokenHash string, now time.Time) (secretRaw string, session EnrolmentSession, outcome FirstContactOutcome, err error) {
	if now.IsZero() {
		return "", EnrolmentSession{}, Unknown, fmt.Errorf("store: FirstContact: now is zero; callers must set it")
	}
	now = now.UTC()

	tx, err := database.Begin(ctx)
	if err != nil {
		return "", EnrolmentSession{}, Unknown, fmt.Errorf("begin first-contact transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = tx.Rollback() // best-effort; the error already returned above stands regardless
	}()

	found, err := scanEnrolmentSessionByHash(ctx, tx, tokenHash)
	if err != nil {
		if errors.Is(err, ErrEnrolmentSessionNotFound) {
			if cerr := tx.Commit(); cerr != nil {
				return "", EnrolmentSession{}, Unknown, fmt.Errorf("commit first-contact transaction: %w", cerr)
			}
			committed = true
			return "", EnrolmentSession{}, Unknown, nil
		}
		return "", EnrolmentSession{}, Unknown, err
	}

	if found.BurnedAt != nil {
		if cerr := tx.Commit(); cerr != nil {
			return "", EnrolmentSession{}, Unknown, fmt.Errorf("commit first-contact transaction: %w", cerr)
		}
		committed = true
		return "", found, Reused, nil
	}

	if !now.Before(found.FirstContactDeadline) {
		if found.State != EnrolmentStateExpired {
			if _, err := tx.ExecContext(ctx, `
				UPDATE enrolment_sessions SET state = ? WHERE id = ? AND burned_at IS NULL`,
				string(EnrolmentStateExpired), found.ID); err != nil {
				return "", EnrolmentSession{}, Unknown, fmt.Errorf("mark enrolment session expired: %w", err)
			}
			found.State = EnrolmentStateExpired
		}
		if cerr := tx.Commit(); cerr != nil {
			return "", EnrolmentSession{}, Unknown, fmt.Errorf("commit first-contact transaction: %w", cerr)
		}
		committed = true
		return "", found, Expired, nil
	}

	secretRaw, err = randomHex(enrolmentSecretBytes)
	if err != nil {
		return "", EnrolmentSession{}, Unknown, fmt.Errorf("generate enrolment secret: %w", err)
	}
	windowDeadline := now.Add(enrolmentContactWindow)

	// Guarded by "burned_at IS NULL" so a concurrent first contact for
	// the same token can win this race but never both: RowsAffected
	// decides the winner, the same shape ClaimNextCanaryCommand's
	// delivered_at guard uses.
	res, err := tx.ExecContext(ctx, `
		UPDATE enrolment_sessions
		SET burned_at = ?, enrolment_secret_hash = ?, window_deadline = ?, state = ?
		WHERE id = ? AND burned_at IS NULL`,
		now.Format(receivedAtLayout), HashToken(secretRaw), windowDeadline.Format(receivedAtLayout), string(EnrolmentStateContacted), found.ID)
	if err != nil {
		return "", EnrolmentSession{}, Unknown, fmt.Errorf("burn enrolment session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", EnrolmentSession{}, Unknown, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		// Lost the race: another call burned this row between our
		// lookup and this update. Re-read it so the caller's audit entry
		// (Reused) names the right session, then report exactly what
		// that caller would have gotten had it looked a moment later.
		raced, rerr := scanEnrolmentSessionByHash(ctx, tx, tokenHash)
		if rerr != nil {
			return "", EnrolmentSession{}, Unknown, fmt.Errorf("re-read raced enrolment session: %w", rerr)
		}
		if cerr := tx.Commit(); cerr != nil {
			return "", EnrolmentSession{}, Unknown, fmt.Errorf("commit first-contact transaction: %w", cerr)
		}
		committed = true
		return "", raced, Reused, nil
	}

	burnedAt := now
	found.BurnedAt = &burnedAt
	found.WindowDeadline = &windowDeadline
	found.State = EnrolmentStateContacted

	if cerr := tx.Commit(); cerr != nil {
		return "", EnrolmentSession{}, Unknown, fmt.Errorf("commit first-contact transaction: %w", cerr)
	}
	committed = true
	return secretRaw, found, Contacted, nil
}

// ListEnrolmentSessions returns every enrolment_sessions row, oldest
// first -- the read path for `birdcage canary enrol --status`. Like
// EnrolmentSession itself, this selects neither token_hash nor
// enrolment_secret_hash, so there is no hash here a caller could print
// by mistake.
func ListEnrolmentSessions(ctx context.Context, database *db.DB) ([]EnrolmentSession, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT id, created_at, first_contact_deadline, burned_at, window_deadline, state, canary_id
		FROM enrolment_sessions
		ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list enrolment sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []EnrolmentSession
	for rows.Next() {
		s, err := scanEnrolmentSession(rows)
		if err != nil {
			return nil, fmt.Errorf("scan enrolment session: %w", err)
		}
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enrolment sessions: %w", err)
	}
	return sessions, nil
}

// scanEnrolmentSessionByHash resolves tokenHash to its EnrolmentSession
// row via conn, so FirstContact can run it inside its own transaction.
func scanEnrolmentSessionByHash(ctx context.Context, conn db.Conn, tokenHash string) (EnrolmentSession, error) {
	row := conn.QueryRowContext(ctx, `
		SELECT id, created_at, first_contact_deadline, burned_at, window_deadline, state, canary_id
		FROM enrolment_sessions
		WHERE token_hash = ?`, tokenHash)
	return scanEnrolmentSession(row)
}

// scanEnrolmentSession reads one row via the rowScanner interface
// (token.go), shared by the single-row lookup above and
// ListEnrolmentSessions' multi-row scan, the same split
// scanCanaryToken uses.
func scanEnrolmentSession(row rowScanner) (EnrolmentSession, error) {
	var (
		s                     EnrolmentSession
		state                 string
		createdAt             string
		firstContactDeadline  string
		burnedAt, windowDeadl *string
		canaryID              *string
	)
	if err := row.Scan(&s.ID, &createdAt, &firstContactDeadline, &burnedAt, &windowDeadl, &state, &canaryID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EnrolmentSession{}, ErrEnrolmentSessionNotFound
		}
		return EnrolmentSession{}, fmt.Errorf("scan enrolment session: %w", err)
	}
	s.State = EnrolmentState(state)
	s.CanaryID = canaryID

	var err error
	if s.CreatedAt, err = time.Parse(receivedAtLayout, createdAt); err != nil {
		return EnrolmentSession{}, fmt.Errorf("parse created_at %q: %w", createdAt, err)
	}
	if s.FirstContactDeadline, err = time.Parse(receivedAtLayout, firstContactDeadline); err != nil {
		return EnrolmentSession{}, fmt.Errorf("parse first_contact_deadline %q: %w", firstContactDeadline, err)
	}
	if burnedAt != nil {
		parsed, err := time.Parse(receivedAtLayout, *burnedAt)
		if err != nil {
			return EnrolmentSession{}, fmt.Errorf("parse burned_at %q: %w", *burnedAt, err)
		}
		s.BurnedAt = &parsed
	}
	if windowDeadl != nil {
		parsed, err := time.Parse(receivedAtLayout, *windowDeadl)
		if err != nil {
			return EnrolmentSession{}, fmt.Errorf("parse window_deadline %q: %w", *windowDeadl, err)
		}
		s.WindowDeadline = &parsed
	}
	return s, nil
}
