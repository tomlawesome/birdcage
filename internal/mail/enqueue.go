package mail

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

// The two rate limits. Both are named constants because both are
// security controls, not tuning: an alert path an attacker can make
// birdcage run as often as they like is a way to attack the operator's
// mailbox, their provider's reputation, and -- once the alerts are
// arriving faster than anyone reads them -- their attention, which is
// the actual thing this feature is defending.
//
// The same argument internal/history's collapseWindow makes about row
// count applies here with a worse consequence: a token conflict is
// driven by a signal an attacker paces (they choose when the stolen
// credential is presented), so without a bound they would choose how
// much mail birdcage sends.
//
// Nothing a limit stops is thrown away. A suppressed alert is counted
// on the most recent outbox row for that canary and kind, and the next
// message that does go out says how many were suppressed and since
// when. The dashboard is never affected: the canary's state is what it
// is whether or not an email went out about it, and the tile says so
// either way.
const (
	// perCanaryCooldown is how recently a canary must have had a
	// message of this kind for another one to be suppressed. One hour:
	// long enough that a flapping conflict cannot mail repeatedly,
	// short enough that a genuinely new conflict the next morning is
	// still mailed rather than folded into yesterday's.
	//
	// The boundary is inclusive, the same way internal/history's
	// collapseWindow is: a conflict exactly perCanaryCooldown after the
	// last message is mailed, not suppressed.
	perCanaryCooldown = time.Hour

	// fleetHourlyCap is the most messages birdcage will generate in any
	// rolling fleetCapWindow, across every canary and every kind. It is
	// the backstop the per-canary cooldown cannot be: twenty canaries
	// conflicting at once are twenty separate canaries as far as the
	// cooldown is concerned, and twenty-one would be twenty-one
	// messages.
	//
	// Twenty is chosen to sit well above any real incident (a fleet
	// where twenty canaries conflict inside an hour has one problem,
	// not twenty, and the first message already said "look at that box
	// now") and well below the rate at which a mail provider starts
	// treating the sender as a source of spam.
	fleetHourlyCap = 20

	// fleetCapWindow is the rolling window fleetHourlyCap is measured
	// over. Rolling, not a clock hour: a burst spread across a
	// boundary would otherwise be counted as two smaller bursts.
	fleetCapWindow = time.Hour
)

// Conn is the database surface an enqueue needs. Both *db.DB and *db.Tx
// satisfy it, which is the point: the enqueue runs inside
// internal/history's own transaction, so the message and the state
// period that caused it land together or not at all. A mail birdcage
// promised about a period it then rolled back would be a lie, and a
// period recorded without the mail it was supposed to trigger would be
// a silence.
type Conn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// EnqueueTokenConflict is what internal/history's recorder calls, through
// the hook cmd/birdcage installs, when a token_conflict period is opened
// or reopened for a canary. It writes the message that alert deserves
// into mail_outbox -- or, if a rate limit says this one is not worth
// waking anybody for, counts it as suppressed so the next message that
// does go out reports it.
//
// A nil *Sender (mail is off) does nothing and reports no error, so the
// recorder's hook can be installed unconditionally.
//
// The message is composed here, at enqueue time, rather than at send
// time: a body rendered when an SMTP server finally came back would
// describe the fleet hours after the event it is about.
func (s *Sender) EnqueueTokenConflict(ctx context.Context, conn Conn, canaryID, canaryName string, now time.Time) error {
	if s == nil {
		return nil
	}
	now = now.UTC()
	kind := store.MailKindTokenConflict

	previous, err := store.LatestMail(ctx, conn, kind, canaryID)
	if err != nil {
		return fmt.Errorf("look up the last %s mail for %s: %w", kind, canaryID, err)
	}
	if previous != nil && now.Sub(previous.CreatedAt) < perCanaryCooldown {
		return s.suppress(ctx, conn, kind, previous, "per-agent cooldown")
	}

	recent, err := store.CountMailSince(ctx, conn, s.db.Engine, now.Add(-fleetCapWindow))
	if err != nil {
		return fmt.Errorf("count recent mail: %w", err)
	}
	if recent >= fleetHourlyCap {
		return s.suppress(ctx, conn, kind, previous, "fleet-wide hourly cap")
	}

	alert := TokenConflictAlert{CanaryID: canaryID, CanaryName: canaryName, At: now}
	// Whatever the previous message accumulated while it was the most
	// recent row is reported now, and stays frozen on that row: this
	// new row becomes the one future suppressions are counted on, so no
	// suppression is ever reported twice or lost between the two.
	if previous != nil && previous.SuppressedCount > 0 {
		alert.SuppressedCount = previous.SuppressedCount
		alert.SuppressedSince = previous.CreatedAt
	}

	return store.EnqueueMail(ctx, conn, store.MailMessage{
		Kind:          string(kind),
		CanaryID:      &canaryID,
		Subject:       TokenConflictSubject,
		Body:          TokenConflictBody(alert),
		CreatedAt:     now,
		NextAttemptAt: now,
	})
}

// suppress records that one more alert was deliberately not sent.
//
// It counts against the most recent message for this canary and kind
// where there is one. Where there is not -- the fleet-wide cap firing
// for a canary that has never been mailed about -- it falls back to the
// most recent message of this kind for any canary, so the count still
// reaches somebody rather than being dropped; that message's own
// "N further alerts were suppressed" line then covers it.
func (s *Sender) suppress(ctx context.Context, conn Conn, kind store.MailKind, previous *store.MailMessage, why string) error {
	target := previous
	if target == nil {
		latest, err := store.LatestMail(ctx, conn, kind, "")
		if err != nil {
			return fmt.Errorf("look up the last %s mail: %w", kind, err)
		}
		target = latest
	}
	if target == nil {
		// Unreachable in practice: the fleet cap only fires once
		// fleetHourlyCap messages exist, so there is always a row to
		// count against. Logged rather than ignored, because a silent
		// drop here is exactly what these limits promise not to do.
		s.log.Warn(fmt.Sprintf("suppressed a %s alert (%s) with no earlier message to count it against", kind, why))
		return nil
	}
	if err := store.BumpMailSuppressed(ctx, conn, target.ID); err != nil {
		return err
	}
	s.log.Info(fmt.Sprintf("suppressed a %s alert (%s); it will be reported on the next message", kind, why))
	return nil
}
