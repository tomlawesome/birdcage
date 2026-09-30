// Package store: this file is the read/write path for the approvals
// table (issue #54, migration 0012) -- every administrator reply
// birdcage has taken out of the approval mailbox, verified or not.
//
// Nothing here decides anything. internal/mailbox fetches the bytes and
// internal/agent/approval judges them; this file only stores the row
// and reads it back, the same split store/mail.go keeps with
// internal/mail. That matters more than usual here: ADR-0007's whole
// design is that birdcage couriers an approval it cannot forge, so the
// raw column holds the message exactly as the IMAP server sent it and
// this file never rewrites it.
//
// Every timestamp is RFC3339Nano text (receivedAtLayout), compared as
// an instant and never as text -- see store/mail.go's package comment
// for the trimmed-fractional-second trap that rule exists for.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// MaxApprovalRawSize is the largest message this table will hold, and
// it is the same 1 MiB internal/mailbox refuses to download past and
// internal/agent/approval refuses to parse past. Enforced in Go rather
// than by a per-engine CHECK constraint, for the reason migration
// 0012's comment gives.
const MaxApprovalRawSize = 1 << 20

// Approval is one row of approvals.
//
// Exactly one of VerifiedAt and RejectReason is ever set: an approval
// either passed every rule or broke one, and the reason is the
// verifier's own wording so a row is readable without re-running it.
//
// AppliedAt is when the approval caused something to happen. It is
// always nil in slice 1 -- `upgrade` is still unmintable and there are
// no pending requests to match -- and exists so slice 2 marks a row
// rather than adding a second table that says the same thing.
type Approval struct {
	ID           int64
	MessageID    string
	FromAddress  string
	Subject      string
	Reference    string
	ReceivedAt   time.Time
	VerifiedAt   *time.Time
	RejectReason *string
	Raw          []byte
	AppliedAt    *time.Time
}

// Verified reports whether this approval passed every rule.
func (a Approval) Verified() bool { return a.VerifiedAt != nil }

// ErrApprovalAlreadyRecorded is what RecordApproval returns when the
// Message-ID is already in the table.
//
// It is a named error rather than a raw constraint violation because
// the caller's right response is specific: this is a replay, and the
// poll should move on and mark the message read rather than retry. The
// UNIQUE constraint behind it is the backstop for two processes racing,
// not the first line of defence -- ApprovalSeen is, and
// internal/agent/approval's Seen hook is wired to it.
var ErrApprovalAlreadyRecorded = errors.New("store: an approval with this Message-ID has already been recorded")

// approvalColumns is the one SELECT list every reader below shares, so
// a column added to the table has one place to be added to the scan.
const approvalColumns = `id, message_id, from_address, subject, reference, received_at, verified_at, reject_reason, raw, applied_at`

// approvalConn is what this file's multi-row readers take: db.Conn's
// Exec/QueryRow plus QueryContext, so a record and the lookups around
// it can all run on the same *db.Tx. Both *db.DB and *db.Tx satisfy it.
// Same shape as mailConn, deliberately.
type approvalConn interface {
	db.Conn
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// RecordApproval writes one reply, verified or not.
//
// a.ID is ignored (both engines generate it). a.Raw is stored byte for
// byte: it is the evidence each agent re-verifies for itself, so a copy
// that had been re-rendered, re-wrapped or re-encoded would verify as
// nothing.
func RecordApproval(ctx context.Context, database db.Conn, a Approval) error {
	switch {
	case a.MessageID == "":
		return errors.New("store: RecordApproval: MessageID is empty; it is what stops an approval being replayed")
	case a.ReceivedAt.IsZero():
		return errors.New("store: RecordApproval: ReceivedAt is zero; callers must set it")
	case len(a.Raw) == 0:
		return errors.New("store: RecordApproval: Raw is empty; the raw message is the evidence and is not optional")
	case len(a.Raw) > MaxApprovalRawSize:
		return fmt.Errorf("store: RecordApproval: Raw is %d bytes, over the %d-byte limit", len(a.Raw), MaxApprovalRawSize)
	case a.VerifiedAt != nil && a.RejectReason != nil:
		return errors.New("store: RecordApproval: an approval is either verified or rejected, never both")
	case a.VerifiedAt == nil && a.RejectReason == nil:
		return errors.New("store: RecordApproval: an approval needs either a verified time or a reason it was rejected")
	case a.VerifiedAt != nil && a.VerifiedAt.IsZero():
		return errors.New("store: RecordApproval: VerifiedAt is set but zero")
	}

	_, err := database.ExecContext(ctx, `
		INSERT INTO approvals (message_id, from_address, subject, reference, received_at, verified_at, reject_reason, raw, applied_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		a.MessageID, a.FromAddress, a.Subject, a.Reference,
		a.ReceivedAt.UTC().Format(receivedAtLayout),
		nullableTime(a.VerifiedAt), nullableString(a.RejectReason), a.Raw)
	if err != nil {
		// Both engines report the UNIQUE violation differently, and
		// neither exposes it as a typed error the standard library
		// knows. A second read is cheap here (this runs once per
		// message, at most fifty times a minute) and turns the engine's
		// own wording into the one case the caller cares about.
		if seen, seenErr := ApprovalSeen(ctx, database, a.MessageID); seenErr == nil && seen {
			return ErrApprovalAlreadyRecorded
		}
		return fmt.Errorf("insert approval: %w", err)
	}
	return nil
}

// ApprovalSeen reports whether messageID is already in the table. It is
// the replay check internal/agent/approval's Seen hook is wired to: an
// approval is used once, and a message replayed later carries a
// signature that is still perfectly valid.
func ApprovalSeen(ctx context.Context, database db.Conn, messageID string) (bool, error) {
	if messageID == "" {
		return false, errors.New("store: ApprovalSeen: MessageID is empty")
	}
	var n int
	err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM approvals WHERE message_id = ?`, messageID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("look up approval %s: %w", messageID, err)
	}
	return n > 0, nil
}

// ApprovalByReference returns the most recently received reply carrying
// reference, or nil when there is none. Sent, verified or rejected
// alike: a rejected first attempt followed by a good second one is a
// sequence worth being able to read both halves of, and the caller
// decides what to do with what it finds.
//
// "Most recent" is by received_at, decided in Go (see the package
// comment); the id breaks a tie, which only two rows written inside one
// transaction could produce.
func ApprovalByReference(ctx context.Context, database approvalConn, reference string) (*Approval, error) {
	if reference == "" {
		return nil, errors.New("store: ApprovalByReference: reference is empty")
	}
	approvals, err := queryApprovals(ctx, database,
		`SELECT `+approvalColumns+` FROM approvals WHERE reference = ?`, reference)
	if err != nil {
		return nil, err
	}
	var latest *Approval
	for i := range approvals {
		a := approvals[i]
		if latest == nil || a.ReceivedAt.After(latest.ReceivedAt) || (a.ReceivedAt.Equal(latest.ReceivedAt) && a.ID > latest.ID) {
			winner := a
			latest = &winner
		}
	}
	return latest, nil
}

// queryApprovals runs one SELECT over approvals and scans every row.
// Every reader above goes through it so the column list, the timestamp
// parsing and the NULL handling exist once.
func queryApprovals(ctx context.Context, database approvalConn, query string, args ...any) ([]Approval, error) {
	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query approvals: %w", err)
	}
	defer func() { _ = rows.Close() }()

	approvals := []Approval{}
	for rows.Next() {
		var (
			a          Approval
			receivedAt string
			verifiedAt *string
			appliedAt  *string
		)
		if err := rows.Scan(&a.ID, &a.MessageID, &a.FromAddress, &a.Subject, &a.Reference,
			&receivedAt, &verifiedAt, &a.RejectReason, &a.Raw, &appliedAt); err != nil {
			return nil, fmt.Errorf("scan approval: %w", err)
		}
		if a.ReceivedAt, err = time.Parse(receivedAtLayout, receivedAt); err != nil {
			return nil, fmt.Errorf("parse approval received_at %q: %w", receivedAt, err)
		}
		if a.VerifiedAt, err = parseNullableTime(verifiedAt, "verified_at"); err != nil {
			return nil, err
		}
		if a.AppliedAt, err = parseNullableTime(appliedAt, "applied_at"); err != nil {
			return nil, err
		}
		approvals = append(approvals, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approvals: %w", err)
	}
	return approvals, nil
}

func parseNullableTime(value *string, column string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	t, err := time.Parse(receivedAtLayout, *value)
	if err != nil {
		return nil, fmt.Errorf("parse approval %s %q: %w", column, *value, err)
	}
	return &t, nil
}

// nullableTime and nullableString turn a nil pointer into a SQL NULL.
// database/sql would store a typed nil as NULL anyway on some drivers
// and not on others; being explicit means both engines agree.
func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(receivedAtLayout)
}

func nullableString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
