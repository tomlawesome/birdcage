// Package store: this file is the read/write path for mail_outbox
// (issue #55, migration 0011) -- the alerts birdcage owes an
// administrator by email.
//
// Nothing here sends anything, composes anything, or decides whether an
// alert is worth sending. internal/mail owns all three; this file only
// stores rows and reads them back, the same split internal/history and
// history.go keep. That matters more here than usual: the enqueue
// happens inside internal/history's own transaction, so these functions
// all take a db.Conn (or mailConn) and work identically on a *db.DB and
// on an in-flight *db.Tx.
//
// Every timestamp is RFC3339Nano text (receivedAtLayout), compared as an
// instant and never as text. Range filters narrow through timeCompare
// and the decision is then made in Go on parsed time.Time values --
// SQL ORDER BY or MAX on these columns would reintroduce the
// trimmed-fractional-second bug token.go's
// RevokeCanaryTokensSupersededBy documents.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// MailKind is the closed set of reasons birdcage sends mail. Closed here
// in Go like SettingKey, CommandKind and the end_reason values, rather
// than by a per-engine CHECK constraint (migration 0011's comment).
type MailKind string

// MailKindTokenConflict is issue #55's one kind: a canary presented a
// credential birdcage had already revoked. It is the only health state
// whose right response is "go and look at that box now" rather than
// "it will be on the dashboard in the morning", which is the whole
// argument for birdcage owning an SMTP client at all.
const MailKindTokenConflict MailKind = "token_conflict"

// mailKinds is EnqueueMail's allow-list, so an unrecognized kind fails
// at the call rather than becoming a value no reader understands.
var mailKinds = map[MailKind]bool{
	MailKindTokenConflict: true,
}

// MailMessage is one row of mail_outbox.
//
// SentAt nil is the whole definition of "still owed", the same shape
// canary_commands.delivered_at uses. CanaryID is nil for a kind that is
// not about one canary; LastError is nil until an attempt has failed.
//
// Subject and Body are the finished text, composed when the row was
// written rather than when it is sent -- a message rendered at send time
// would describe the fleet as it is when the SMTP server finally came
// back, not as it was when the thing it is about happened.
type MailMessage struct {
	ID              int64
	Kind            string
	CanaryID        *string
	Subject         string
	Body            string
	CreatedAt       time.Time
	Attempts        int64
	NextAttemptAt   time.Time
	LastError       *string
	SentAt          *time.Time
	SuppressedCount int64
}

// MailStatus is GET /api/mail's body below the "configured" flag: what
// an operator needs to know about whether the thing that is supposed to
// wake them up is working, and nothing else. It carries its own JSON
// shape directly, the way StatePeriod and Trace do, so the handler has
// no parallel struct to keep in step.
//
// FailingSince is the created_at of the oldest still-unsent row that has
// at least one failed attempt behind it -- "mail has been broken since
// then", which is the question the dashboard's strip actually asks.
// LastError is that same row's error, so the two always describe one
// failure rather than two unrelated ones.
type MailStatus struct {
	LastSentAt   *time.Time `json:"last_sent_at"`
	FailingSince *time.Time `json:"failing_since"`
	LastError    *string    `json:"last_error"`
	Pending      int        `json:"pending"`
	Suppressed   int64      `json:"suppressed"`
}

// mailConn is what this file's multi-row readers take: db.Conn's
// Exec/QueryRow plus QueryContext, so an enqueue and the lookups that
// decide whether to enqueue all run on the same *db.Tx as the state
// period that triggered them. Both *db.DB and *db.Tx satisfy it (see
// db.Tx.QueryContext's doc comment for why that method had to be
// shadowed). Same shape as historyConn, deliberately.
type mailConn interface {
	db.Conn
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// mailColumns is the one SELECT list every reader below shares, so a
// column added to the table has one place to be added to the scan.
const mailColumns = `id, kind, agent_id, subject, body, created_at, attempts, next_attempt_at, last_error, sent_at, suppressed_count`

// EnqueueMail writes m as a row still owed. Normally that is called
// inside internal/history's own transaction, so the mail and the state
// period that caused it land together or not at all.
//
// m.ID is ignored (both engines generate it), and so is m.SentAt: this
// function only ever writes an unsent row. A zero NextAttemptAt means
// "as soon as the next tick runs", which is what every caller wants;
// it is defaulted to CreatedAt rather than rejected.
func EnqueueMail(ctx context.Context, database db.Conn, m MailMessage) error {
	if !mailKinds[MailKind(m.Kind)] {
		return fmt.Errorf("store: EnqueueMail: unknown mail kind %q", m.Kind)
	}
	if m.CreatedAt.IsZero() {
		return fmt.Errorf("store: EnqueueMail: CreatedAt is zero; callers must set it")
	}
	if m.Subject == "" || m.Body == "" {
		return fmt.Errorf("store: EnqueueMail: subject and body must both be set")
	}
	next := m.NextAttemptAt
	if next.IsZero() {
		next = m.CreatedAt
	}
	var canaryID any
	if m.CanaryID != nil {
		canaryID = *m.CanaryID
	}
	suppressed := m.SuppressedCount
	if suppressed < 0 {
		suppressed = 0
	}
	_, err := database.ExecContext(ctx, `
		INSERT INTO mail_outbox (kind, agent_id, subject, body, created_at, attempts, next_attempt_at, last_error, sent_at, suppressed_count)
		VALUES (?, ?, ?, ?, ?, 0, ?, NULL, NULL, ?)`,
		m.Kind, canaryID, m.Subject, m.Body,
		m.CreatedAt.UTC().Format(receivedAtLayout),
		next.UTC().Format(receivedAtLayout),
		suppressed)
	if err != nil {
		return fmt.Errorf("insert mail: %w", err)
	}
	return nil
}

// DueMail returns every row still owed whose next attempt has come
// round: sent_at IS NULL AND next_attempt_at <= now. Oldest first, so a
// backlog drains in the order it was written.
//
// The unsent filter is SQL (it is a NULL check, which is exact on both
// engines); the next_attempt_at comparison and the ordering are done in
// Go on parsed timestamps, per this file's package comment. The scan is
// bounded by the number of unsent rows, which the sender is actively
// draining and the rate limits cap.
func DueMail(ctx context.Context, database mailConn, now time.Time) ([]MailMessage, error) {
	messages, err := queryMail(ctx, database, `SELECT `+mailColumns+` FROM mail_outbox WHERE sent_at IS NULL`)
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	due := messages[:0]
	for _, m := range messages {
		if !m.NextAttemptAt.After(now) {
			due = append(due, m)
		}
	}
	sort.SliceStable(due, func(i, j int) bool {
		if !due[i].CreatedAt.Equal(due[j].CreatedAt) {
			return due[i].CreatedAt.Before(due[j].CreatedAt)
		}
		return due[i].ID < due[j].ID
	})
	return due, nil
}

// LatestMail returns the most recent row for kind, narrowed to canaryID
// when that is non-empty, or nil when there is none. Sent or unsent
// alike: this is the row the cooldown is measured from and the row a
// suppressed alert is counted on, and whether the previous mail has
// actually gone out yet has no bearing on either.
//
// "Most recent" is by created_at, decided in Go (see the package
// comment); the id breaks a tie, which only two rows written inside one
// transaction could produce.
func LatestMail(ctx context.Context, database mailConn, kind MailKind, canaryID string) (*MailMessage, error) {
	query := `SELECT ` + mailColumns + ` FROM mail_outbox WHERE kind = ?`
	args := []any{string(kind)}
	if canaryID != "" {
		query += ` AND agent_id = ?`
		args = append(args, canaryID)
	}
	messages, err := queryMail(ctx, database, query, args...)
	if err != nil {
		return nil, err
	}
	var latest *MailMessage
	for i := range messages {
		m := messages[i]
		if latest == nil || m.CreatedAt.After(latest.CreatedAt) || (m.CreatedAt.Equal(latest.CreatedAt) && m.ID > latest.ID) {
			winner := m
			latest = &winner
		}
	}
	return latest, nil
}

// CountMailSince returns how many rows were created at or after since --
// the fleet-wide rolling-hour cap's input (internal/mail's
// fleetHourlyCap). Every row counts, sent or not: the cap bounds how
// much mail birdcage will generate, and a message stuck in the outbox
// was still generated.
//
// since narrows the scan in SQL through timeCompare, and the count is
// then taken in Go on parsed timestamps so the boundary is exact. The
// engine is passed in rather than read off database for the reason
// LatestClosedStatePeriod takes it too: this runs inside internal/
// history's transaction, and a *db.Tx does not carry its engine.
func CountMailSince(ctx context.Context, database mailConn, engine db.Engine, since time.Time) (int, error) {
	messages, err := queryMail(ctx, database,
		`SELECT `+mailColumns+` FROM mail_outbox WHERE `+timeCompare(engine, "created_at", ">="),
		since.UTC().Format(receivedAtLayout))
	if err != nil {
		return 0, err
	}
	since = since.UTC()
	n := 0
	for _, m := range messages {
		if !m.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

// BumpMailSuppressed records that one more alert was deliberately not
// sent while id was the most recent row for its canary and kind. The
// next mail that does go out reads this count and says how many were
// suppressed and since when -- a rate limit that silently drops what it
// stops is indistinguishable from a bug.
func BumpMailSuppressed(ctx context.Context, database db.Conn, id int64) error {
	_, err := database.ExecContext(ctx, `
		UPDATE mail_outbox SET suppressed_count = suppressed_count + 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("bump suppressed count on mail %d: %w", id, err)
	}
	return nil
}

// MarkMailSent closes out a row: sent_at set, last_error cleared. The
// "AND sent_at IS NULL" guard makes a second call a no-op rather than
// moving a send time already written -- the sender never wants to send
// the same row twice, and if it ever tries, the first (actually
// observed) time stands. Clearing last_error is deliberate: a row that
// failed twice and then went out is not a failing row, and GET
// /api/mail must not keep reporting it as one.
func MarkMailSent(ctx context.Context, database db.Conn, id int64, sentAt time.Time) error {
	if sentAt.IsZero() {
		return fmt.Errorf("store: MarkMailSent: sentAt is zero; callers must set it")
	}
	_, err := database.ExecContext(ctx, `
		UPDATE mail_outbox SET sent_at = ?, last_error = NULL
		WHERE id = ? AND sent_at IS NULL`,
		sentAt.UTC().Format(receivedAtLayout), id)
	if err != nil {
		return fmt.Errorf("mark mail %d sent: %w", id, err)
	}
	return nil
}

// RecordMailFailure records one failed attempt: the attempt count goes
// up by one, the error is stored, and the next attempt is pushed out to
// nextAttemptAt (internal/mail's backoff -- one minute doubled per
// attempt, ceiling one hour).
//
// lastError is stored verbatim, so its caller is responsible for what is
// in it: internal/mail's Sender.scrub removes the credential before this
// is ever called. SECURITY.md's "never logged" rule covers a database
// column exactly as much as a log line.
func RecordMailFailure(ctx context.Context, database db.Conn, id int64, lastError string, nextAttemptAt time.Time) error {
	if nextAttemptAt.IsZero() {
		return fmt.Errorf("store: RecordMailFailure: nextAttemptAt is zero; callers must set it")
	}
	_, err := database.ExecContext(ctx, `
		UPDATE mail_outbox
		SET attempts = attempts + 1, last_error = ?, next_attempt_at = ?
		WHERE id = ? AND sent_at IS NULL`,
		lastError, nextAttemptAt.UTC().Format(receivedAtLayout), id)
	if err != nil {
		return fmt.Errorf("record failure on mail %d: %w", id, err)
	}
	return nil
}

// GetMailStatus answers GET /api/mail: when the last message actually
// went out, whether anything is stuck and since when, how many are
// owed, and how many alerts were deliberately suppressed.
//
// Two reads, deliberately. The unsent rows are bounded by what the
// sender is draining; the sent rows are scanned only for their sent_at,
// and the table grows at most at the fleet cap's rate (20 an hour, and
// in practice a handful ever), so the max is taken in Go rather than by
// a SQL MAX that would compare RFC3339Nano text.
func GetMailStatus(ctx context.Context, database mailConn) (MailStatus, error) {
	all, err := queryMail(ctx, database, `SELECT `+mailColumns+` FROM mail_outbox`)
	if err != nil {
		return MailStatus{}, err
	}

	var status MailStatus
	var oldestFailing *MailMessage
	for i := range all {
		m := all[i]
		status.Suppressed += m.SuppressedCount
		if m.SentAt != nil {
			if status.LastSentAt == nil || m.SentAt.After(*status.LastSentAt) {
				sent := *m.SentAt
				status.LastSentAt = &sent
			}
			continue
		}
		status.Pending++
		if m.Attempts == 0 {
			// Owed but never tried: not evidence that mail is broken.
			continue
		}
		if oldestFailing == nil || m.CreatedAt.Before(oldestFailing.CreatedAt) {
			failing := m
			oldestFailing = &failing
		}
	}
	if oldestFailing != nil {
		created := oldestFailing.CreatedAt
		status.FailingSince = &created
		status.LastError = oldestFailing.LastError
	}
	return status, nil
}

// queryMail runs one SELECT over mail_outbox and scans every row. All
// of this file's readers go through it so the column list, the
// timestamp parsing and the NULL handling exist once.
func queryMail(ctx context.Context, database mailConn, query string, args ...any) ([]MailMessage, error) {
	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query mail outbox: %w", err)
	}
	defer func() { _ = rows.Close() }()

	messages := []MailMessage{}
	for rows.Next() {
		var (
			m             MailMessage
			createdAt     string
			nextAttemptAt string
			sentAt        *string
		)
		if err := rows.Scan(&m.ID, &m.Kind, &m.CanaryID, &m.Subject, &m.Body, &createdAt, &m.Attempts, &nextAttemptAt, &m.LastError, &sentAt, &m.SuppressedCount); err != nil {
			return nil, fmt.Errorf("scan mail: %w", err)
		}
		if m.CreatedAt, err = time.Parse(receivedAtLayout, createdAt); err != nil {
			return nil, fmt.Errorf("parse mail created_at %q: %w", createdAt, err)
		}
		if m.NextAttemptAt, err = time.Parse(receivedAtLayout, nextAttemptAt); err != nil {
			return nil, fmt.Errorf("parse mail next_attempt_at %q: %w", nextAttemptAt, err)
		}
		if sentAt != nil {
			t, err := time.Parse(receivedAtLayout, *sentAt)
			if err != nil {
				return nil, fmt.Errorf("parse mail sent_at %q: %w", *sentAt, err)
			}
			m.SentAt = &t
		}
		messages = append(messages, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate mail outbox: %w", err)
	}
	return messages, nil
}
