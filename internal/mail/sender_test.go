package mail

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Every credential below is a literal, obviously-fake placeholder. No
// test in this package reads a credential from the environment, and no
// test in this package connects to anything but a listener it created
// itself on 127.0.0.1 (see capture_test.go).
const (
	smtpUser = "birdcage-smtp"
	smtpPass = "not-a-real-password"
	fromAddr = "birdcage@example.invalid"
	toAddr   = "admin@example.invalid"
)

// pinnedNow is the instant every message-pinning test is sent at.
var pinnedNow = time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)

// forEachEngine mirrors internal/store's helper: SQLite always, plus
// Postgres when BIRDCAGE_TEST_DATABASE_URL names one. The SMTP half of
// these tests is engine-independent, but the outbox half is not.
func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) { fn(t, tgt.DB) })
	}
}

// newTestSender builds a Sender pointed at srv, trusting srv's
// self-signed certificate through the test-only injection point and
// with a pinned Message-ID so a whole message can be compared byte for
// byte.
func newTestSender(t *testing.T, database *db.DB, srv *captureServer) *Sender {
	t.Helper()
	s := New(database, Config{
		Host:     srv.Addr,
		STARTTLS: srv.startTLS,
		Username: smtpUser,
		Password: smtpPass,
		From:     fromAddr,
		To:       toAddr,
	}, quietLogger())
	s.testRoots = srv.Roots
	s.messageID = func() string { return "<pinned-for-the-test@example.invalid>" }
	return s
}

// enqueueTokenConflict writes one alert straight into the outbox,
// bypassing the rate limits -- those have their own tests in
// enqueue_test.go, and these tests are about what happens to a message
// once it is owed.
func enqueueTokenConflict(t *testing.T, database *db.DB, canaryID string, at time.Time, alert TokenConflictAlert) {
	t.Helper()
	id := canaryID
	if err := store.EnqueueMail(context.Background(), database, store.MailMessage{
		Kind:          string(store.MailKindTokenConflict),
		CanaryID:      &id,
		Subject:       TokenConflictSubject,
		Body:          TokenConflictBody(alert),
		CreatedAt:     at,
		NextAttemptAt: at,
	}); err != nil {
		t.Fatalf("EnqueueMail: %v", err)
	}
}

func onlyMessage(t *testing.T, database *db.DB) store.MailMessage {
	t.Helper()
	m, err := store.LatestMail(context.Background(), database, store.MailKindTokenConflict, "")
	if err != nil {
		t.Fatalf("LatestMail: %v", err)
	}
	if m == nil {
		t.Fatal("no message in the outbox")
	}
	return *m
}

// TestImplicitTLSSendPinsTheMessage is the happy path: TLS from the
// first byte, the credential offered only after the handshake, and the
// exact bytes that leave birdcage.
//
// The body is built from TokenConflictBody rather than copied in
// literally: the prose is pinned in templates_test.go, and pinning it a
// second time here would mean two places to edit for one wording change
// and no extra guarantee. Every byte of the message is still
// determined -- the headers below are literal, and the body is a pure
// function of the alert.
func TestImplicitTLSSendPinsTheMessage(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		srv := newCaptureServer(t)
		sender := newTestSender(t, database, srv)

		alert := TokenConflictAlert{CanaryID: "canary-iot", CanaryName: "canary-iot", At: pinnedNow}
		enqueueTokenConflict(t, database, "canary-iot", pinnedNow, alert)

		if err := sender.Tick(context.Background(), pinnedNow); err != nil {
			t.Fatalf("Tick: %v", err)
		}

		from, to, data, delivered := srv.received()
		if delivered != 1 {
			t.Fatalf("server took delivery of %d messages, want 1", delivered)
		}
		if from != fromAddr || to != toAddr {
			t.Errorf("envelope = %s -> %s, want %s -> %s", from, to, fromAddr, toAddr)
		}

		header := "From: birdcage@example.invalid\r\n" +
			"To: admin@example.invalid\r\n" +
			"Subject: birdcage: an agent presented a revoked credential\r\n" +
			"Date: Thu, 17 Sep 2026 09:00:00 +0000\r\n" +
			"Message-ID: <pinned-for-the-test@example.invalid>\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"\r\n"
		want := header + strings.ReplaceAll(TokenConflictBody(alert), "\n", "\r\n")
		if data != want {
			t.Errorf("message on the wire:\n%q\nwant:\n%q", data, want)
		}

		user, pass := srv.credentials()
		if user != smtpUser || pass != smtpPass {
			t.Errorf("AUTH PLAIN carried %q/%q, want the configured credential", user, pass)
		}

		sent := onlyMessage(t, database)
		if sent.SentAt == nil {
			t.Error("the row is still unsent after a successful send")
		}
		if sent.LastError != nil {
			t.Errorf("LastError = %q after a successful send, want nil", *sent.LastError)
		}
	})
}

// The STARTTLS path is opt-in and, when the server offers it, works.
func TestSTARTTLSSendSucceedsWhenOffered(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		srv := newCaptureServer(t, withSTARTTLS())
		sender := newTestSender(t, database, srv)
		if !sender.cfg.STARTTLS {
			t.Fatal("the test sender is not on the STARTTLS path")
		}

		enqueueTokenConflict(t, database, "canary-lan", pinnedNow, TokenConflictAlert{
			CanaryID: "canary-lan", CanaryName: "canary-lan", At: pinnedNow,
		})
		if err := sender.Tick(context.Background(), pinnedNow); err != nil {
			t.Fatalf("Tick: %v", err)
		}

		_, _, data, delivered := srv.received()
		if delivered != 1 {
			t.Fatalf("server took delivery of %d messages, want 1", delivered)
		}
		if !strings.Contains(data, TokenConflictSubject) {
			t.Error("the delivered message does not carry the subject")
		}
		user, pass := srv.credentials()
		if user != smtpUser || pass != smtpPass {
			t.Error("AUTH PLAIN did not carry the configured credential")
		}
	})
}

// A server that does not advertise STARTTLS on a connection the
// operator asked to be upgraded gets nothing: no credential, no
// envelope, no message. Downgrading to cleartext here is the one
// failure mode issue #55 rules out absolutely.
func TestSTARTTLSRefusesAServerThatDoesNotOfferIt(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		srv := newCaptureServer(t, withoutSTARTTLSOffer())
		sender := newTestSender(t, database, srv)

		enqueueTokenConflict(t, database, "canary-iot", pinnedNow, TokenConflictAlert{
			CanaryID: "canary-iot", CanaryName: "canary-iot", At: pinnedNow,
		})
		if err := sender.Tick(context.Background(), pinnedNow); err != nil {
			t.Fatalf("Tick: %v", err)
		}

		_, _, _, delivered := srv.received()
		if delivered != 0 {
			t.Fatalf("server took delivery of %d messages over a connection that was never upgraded", delivered)
		}
		if user, pass := srv.credentials(); user != "" || pass != "" {
			t.Fatal("the credential was offered over an unencrypted connection")
		}

		m := onlyMessage(t, database)
		if m.SentAt != nil {
			t.Error("the row was marked sent")
		}
		if m.Attempts != 1 {
			t.Errorf("Attempts = %d, want 1", m.Attempts)
		}
		if m.LastError == nil || !strings.Contains(*m.LastError, "STARTTLS") {
			t.Errorf("LastError = %v, want one naming STARTTLS", m.LastError)
		}
	})
}

// A certificate the client does not trust means no send at all -- and,
// critically, no credential. There is no skip-verify option anywhere in
// this package for a test to have to disable.
func TestUntrustedCertificateSendsNothing(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		srv := newCaptureServer(t)
		sender := newTestSender(t, database, srv)
		// An empty pool: the server's self-signed certificate chains to
		// nothing in it, exactly as a real server with a certificate
		// birdcage's host does not trust would.
		sender.testRoots = x509.NewCertPool()

		enqueueTokenConflict(t, database, "canary-iot", pinnedNow, TokenConflictAlert{
			CanaryID: "canary-iot", CanaryName: "canary-iot", At: pinnedNow,
		})
		if err := sender.Tick(context.Background(), pinnedNow); err != nil {
			t.Fatalf("Tick: %v", err)
		}

		if _, _, _, delivered := srv.received(); delivered != 0 {
			t.Fatalf("server took delivery of %d messages behind an untrusted certificate", delivered)
		}
		if user, pass := srv.credentials(); user != "" || pass != "" {
			t.Fatal("the credential reached a server whose certificate was not trusted")
		}
		m := onlyMessage(t, database)
		if m.SentAt != nil {
			t.Error("the row was marked sent")
		}
		if m.LastError == nil || !strings.Contains(*m.LastError, "certificate") {
			t.Errorf("LastError = %v, want one naming the certificate", m.LastError)
		}
	})
}

// A rejected credential must not come back out of the server's own
// error text and into the outbox -- which GET /api/mail reads and the
// dashboard shows.
func TestARejectedCredentialIsNeverStored(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		srv := newCaptureServer(t, withAuthFailure())
		sender := newTestSender(t, database, srv)

		enqueueTokenConflict(t, database, "canary-iot", pinnedNow, TokenConflictAlert{
			CanaryID: "canary-iot", CanaryName: "canary-iot", At: pinnedNow,
		})
		if err := sender.Tick(context.Background(), pinnedNow); err != nil {
			t.Fatalf("Tick: %v", err)
		}

		m := onlyMessage(t, database)
		if m.LastError == nil {
			t.Fatal("no error stored for a rejected credential")
		}
		if strings.Contains(*m.LastError, smtpPass) {
			t.Errorf("the stored error quotes the password: %q", *m.LastError)
		}
		if strings.Contains(*m.LastError, smtpUser) {
			t.Errorf("the stored error quotes the username: %q", *m.LastError)
		}
		if !strings.Contains(*m.LastError, "[redacted]") {
			t.Errorf("the stored error does not show the redaction: %q", *m.LastError)
		}
	})
}

// TestBackoffSequence pins the retry ladder: one minute, doubling, with
// a one-hour ceiling that holds forever after.
func TestBackoffSequence(t *testing.T) {
	want := []time.Duration{
		time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
		16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour, time.Hour,
	}
	for i, d := range want {
		attempts := int64(i + 1)
		if got := backoff(attempts); got != d {
			t.Errorf("backoff(%d) = %s, want %s", attempts, got, d)
		}
	}
	// Far past the ceiling, where an unbounded shift would go negative
	// and turn the backoff into a hot loop.
	for _, attempts := range []int64{20, 64, 1 << 20} {
		if got := backoff(attempts); got != maxBackoff {
			t.Errorf("backoff(%d) = %s, want the %s ceiling", attempts, got, maxBackoff)
		}
	}
}

// A failing send walks the ladder: each tick records one more attempt
// and pushes the next one out by the next step, and a tick before that
// time does nothing at all.
func TestFailedSendsWalkTheBackoffLadder(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		srv := newCaptureServer(t, withAuthFailure())
		sender := newTestSender(t, database, srv)

		now := pinnedNow
		enqueueTokenConflict(t, database, "canary-iot", now, TokenConflictAlert{
			CanaryID: "canary-iot", CanaryName: "canary-iot", At: now,
		})

		for attempt, wait := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute} {
			if err := sender.Tick(context.Background(), now); err != nil {
				t.Fatalf("Tick %d: %v", attempt+1, err)
			}
			m := onlyMessage(t, database)
			if m.Attempts != int64(attempt+1) {
				t.Fatalf("after tick %d, Attempts = %d", attempt+1, m.Attempts)
			}
			if want := now.Add(wait); !m.NextAttemptAt.Equal(want) {
				t.Fatalf("after tick %d, NextAttemptAt = %s, want %s", attempt+1, m.NextAttemptAt, want)
			}

			// A tick one second before the next attempt is due must not
			// touch the row.
			early := m.NextAttemptAt.Add(-time.Second)
			if err := sender.Tick(context.Background(), early); err != nil {
				t.Fatalf("early tick: %v", err)
			}
			if again := onlyMessage(t, database); again.Attempts != m.Attempts {
				t.Fatalf("a tick before next_attempt_at retried the message (Attempts %d -> %d)", m.Attempts, again.Attempts)
			}

			now = m.NextAttemptAt
		}
	})
}

// A message that could not be sent is still owed after a restart. The
// outbox is the durable part of this feature: "restart" here is a new
// Sender over the same database, which is exactly what the process
// starting again produces.
func TestPendingMailSurvivesARestart(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		dead := newCaptureServer(t, withAuthFailure())
		before := newTestSender(t, database, dead)

		enqueueTokenConflict(t, database, "canary-iot", pinnedNow, TokenConflictAlert{
			CanaryID: "canary-iot", CanaryName: "canary-iot", At: pinnedNow,
		})
		if err := before.Tick(context.Background(), pinnedNow); err != nil {
			t.Fatalf("Tick before restart: %v", err)
		}
		if m := onlyMessage(t, database); m.SentAt != nil || m.Attempts != 1 {
			t.Fatalf("before restart: SentAt=%v Attempts=%d, want unsent with one attempt", m.SentAt, m.Attempts)
		}

		// Restart, and this time the server works.
		alive := newCaptureServer(t)
		after := newTestSender(t, database, alive)
		later := pinnedNow.Add(2 * time.Minute)
		if err := after.Tick(context.Background(), later); err != nil {
			t.Fatalf("Tick after restart: %v", err)
		}

		if _, _, _, delivered := alive.received(); delivered != 1 {
			t.Fatalf("after restart the server took delivery of %d messages, want 1", delivered)
		}
		m := onlyMessage(t, database)
		if m.SentAt == nil {
			t.Fatal("the message is still owed after a successful send")
		}
		if !m.SentAt.Equal(later) {
			t.Errorf("SentAt = %s, want %s", m.SentAt, later)
		}
	})
}

// A database failure is the one thing Tick returns rather than swallows:
// birdcage can retry a dead SMTP server forever, but it cannot do
// anything about not being able to read its own outbox, and hiding that
// would leave "no mail ever arrives" as the only symptom.
func TestTickPropagatesADatabaseError(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		srv := newCaptureServer(t)
		sender := newTestSender(t, database, srv)

		enqueueTokenConflict(t, database, "canary-iot", pinnedNow, TokenConflictAlert{
			CanaryID: "canary-iot", CanaryName: "canary-iot", At: pinnedNow,
		})
		// The fault: the table the tick reads is gone.
		if _, err := database.ExecContext(context.Background(), `DROP TABLE mail_outbox`); err != nil {
			t.Fatalf("drop mail_outbox: %v", err)
		}

		err := sender.Tick(context.Background(), pinnedNow)
		if err == nil {
			t.Fatal("Tick returned nil with the outbox table missing")
		}
		if !strings.Contains(err.Error(), "mail outbox") {
			t.Errorf("error %q does not say which read failed", err)
		}
		if _, _, _, delivered := srv.received(); delivered != 0 {
			t.Errorf("server took delivery of %d messages during a failed tick", delivered)
		}
	})
}

// A nil Sender is how cmd/birdcage expresses "mail is off", so the tick
// loop needs no branch of its own.
func TestNilSenderTickIsANoOp(t *testing.T) {
	var s *Sender
	if err := s.Tick(context.Background(), pinnedNow); err != nil {
		t.Errorf("Tick on a nil Sender: %v", err)
	}
}
