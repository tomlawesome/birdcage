package mail

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

const (
	// baseBackoff is the wait after a first failed attempt. The
	// sequence from there is 1m, 2m, 4m, 8m, 16m, 32m, then maxBackoff
	// for every attempt after that.
	baseBackoff = time.Minute
	// maxBackoff is the ceiling. An hour rather than "give up": an SMTP
	// server that has been down all night should still deliver the
	// alert when it comes back, because the thing the alert is about --
	// a canary running with a stolen identity -- is not less true in
	// the morning. Nothing here ever discards a message.
	maxBackoff = time.Hour
)

// Sender owns issue #55's outbound path: it composes messages, writes
// them to mail_outbox, and drains that table on the same 30-second loop
// as internal/history's recorder (cmd/birdcage's main loop, immediately
// after the recorder tick).
//
// A nil *Sender is the "mail is off" case and every method on it is a
// no-op, so cmd/birdcage can call Tick unconditionally rather than
// guarding the loop.
//
// One per process, constructed after the database is open and migrated.
type Sender struct {
	db  *db.DB
	cfg Config
	log *slog.Logger

	// messageID mints a Message-ID header. A field so a test can pin
	// one and compare a whole message byte for byte; production always
	// gets newMessageID.
	messageID func() string

	// testRoots, when non-nil, is the certificate pool the TLS
	// handshake verifies against instead of the system roots. It exists
	// so this package's own tests can trust the self-signed certificate
	// their in-process capture server presents.
	//
	// It is unexported, has no setter, and is not reachable from any
	// configuration path: New never assigns it, Load never produces it,
	// and no environment variable touches it. The only code that can
	// set it is code compiled into this package, which is this
	// package's tests. That is deliberate -- a "trust this CA instead"
	// knob wired to configuration is how a skip-verify option gets into
	// a product, and issue #55 rules one out.
	testRoots *x509.CertPool
}

// New returns a Sender writing to database and sending through cfg.
// cfg has already been validated by Load -- New does not re-check it.
func New(database *db.DB, cfg Config, log *slog.Logger) *Sender {
	s := &Sender{db: database, cfg: cfg, log: log}
	s.messageID = s.newMessageID
	return s
}

// Tick sends everything that is owed and whose next attempt has come
// round, in the order the messages were written. It runs on the same
// loop as the history recorder, immediately after it, so a mail
// enqueued by a tick goes out on the next one at the latest.
//
// A nil receiver -- mail is not configured -- does nothing and reports
// no error.
//
// Errors are split deliberately. A database failure is returned: the
// caller cannot do anything about it, but it means birdcage's own
// record is not behaving, and hiding it here would make the one
// remaining symptom "no mail ever arrives". An SMTP failure is not
// returned: it is recorded against the message (attempts, error,
// backoff), which is exactly what the outbox is for, and the tick moves
// on to the next message rather than letting one unreachable server
// hold up a queue.
func (s *Sender) Tick(ctx context.Context, now time.Time) error {
	if s == nil {
		return nil
	}
	now = now.UTC()

	due, err := store.DueMail(ctx, s.db, now)
	if err != nil {
		return fmt.Errorf("read mail outbox: %w", err)
	}
	for _, m := range due {
		if err := s.sendOne(ctx, m, now); err != nil {
			return err
		}
	}
	return nil
}

// sendOne attempts one message and writes down what happened. Its
// error return is a database failure only; a failed send is recorded
// and reported as nil, per Tick's doc comment.
func (s *Sender) sendOne(ctx context.Context, m store.MailMessage, now time.Time) error {
	msg, err := s.assemble(m.Subject, m.Body, now)
	if err == nil {
		err = s.deliver(ctx, msg)
	}
	if err == nil {
		if err := store.MarkMailSent(ctx, s.db, m.ID, now); err != nil {
			return fmt.Errorf("record mail %d as sent: %w", m.ID, err)
		}
		s.log.Info(fmt.Sprintf("sent %s alert to %s", m.Kind, s.cfg.To))
		return nil
	}

	// ctx.Err() != nil is shutdown arriving mid-send, not a fault of
	// the server's. It is still recorded -- the message is still owed
	// -- but it is not worth an ERROR line in the log on the way out.
	reason := s.scrub(fmt.Sprintf("could not send the %s alert: %v", m.Kind, err))
	next := now.Add(backoff(m.Attempts + 1))
	if err := store.RecordMailFailure(ctx, s.db, m.ID, reason, next); err != nil {
		return fmt.Errorf("record mail %d failure: %w", m.ID, err)
	}
	if ctx.Err() == nil {
		s.log.Error(fmt.Sprintf("%s; attempt %d, retrying at %s", reason, m.Attempts+1, next.Format(time.RFC3339)))
	}
	return nil
}

// backoff is how long to wait before attempt number attempts+1: one
// minute doubled per attempt already made, with maxBackoff as the
// ceiling.
//
// attempts is the count after the failure that has just been recorded,
// so a first failure waits baseBackoff. The shift is bounded before it
// happens rather than after -- 1 << 63 is not a large duration, it is a
// negative one, and a negative next_attempt_at would turn the backoff
// into a hot loop.
func backoff(attempts int64) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 16 {
		return maxBackoff
	}
	d := baseBackoff << (attempts - 1)
	if d > maxBackoff {
		return maxBackoff
	}
	return d
}

// scrub removes the credential from anything on its way to a log line
// or to mail_outbox.last_error.
//
// An SMTP server's rejection can quote what it was sent, and net/smtp's
// own errors can carry a command back verbatim, so an error string is
// not automatically free of the password. SECURITY.md's "never logged"
// rule covers a database column exactly as much as a log line, and the
// outbox is read back by GET /api/mail and shown on the dashboard --
// so a leak here would be a leak onto the screen as well.
//
// The username goes too. It is not as sensitive as the password, but it
// is half of a credential and the error text reads no worse without it.
func (s *Sender) scrub(msg string) string {
	if s.cfg.Password != "" {
		msg = strings.ReplaceAll(msg, s.cfg.Password, "[redacted]")
	}
	if s.cfg.Username != "" {
		msg = strings.ReplaceAll(msg, s.cfg.Username, "[redacted]")
	}
	return msg
}
