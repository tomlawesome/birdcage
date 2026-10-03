package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

const (
	// dialTimeout bounds the TCP (and, on the implicit-TLS path, the
	// handshake) portion of one send. The send runs on the same 30s
	// loop as the history recorder, so a submission server that accepts
	// a connection and then says nothing must not be able to hold that
	// loop open indefinitely.
	dialTimeout = 10 * time.Second
	// sendDeadline bounds the whole SMTP conversation after the
	// connection is up, for the same reason. Generous: a greylisting
	// server can take several seconds to answer MAIL FROM, and a
	// failure here costs a retry rather than an alert.
	sendDeadline = 30 * time.Second
)

// tlsConfig is the one place this package decides what it will accept
// from a submission server. Two things are fixed and have no
// configuration knob at all: the certificate is verified against the
// system roots, and the server name is the host from
// BIRDCAGE_MAIL_HOST. There is no InsecureSkipVerify here and there is
// no environment variable that reaches one -- an operator who cannot
// get their mail server's certificate to verify has a mail server
// problem, and quietly accepting any certificate would turn birdcage's
// one outbound credential into something any machine on the path could
// collect.
//
// MinVersion is TLS 1.2 rather than the TLS 1.3 floor birdcage sets on
// every listener of its own (internal/tlsconfig, internal/ingest). Both
// ends of those connections are ours, so 1.3 costs nothing. This
// connection's far end is whatever submission server the operator
// already uses, and a good number of them -- self-hosted Postfix and
// Exim installations, and several relay providers -- still terminate
// submission at TLS 1.2. Refusing to speak to them would mean the one
// alert birdcage exists to raise silently never arriving, which is a
// worse outcome than a 1.2 handshake to a fully verified server.
//
// s.testRoots is the test-only injection point (see Sender).
func (s *Sender) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName: s.cfg.Hostname(),
		MinVersion: tls.VersionTLS12,
		RootCAs:    s.testRoots,
	}
}

// deliver opens a connection, authenticates, and sends one already
// assembled message. It returns an error for every failure and never
// falls back to anything: there is no cleartext path out of this
// function.
func (s *Sender) deliver(ctx context.Context, msg []byte) error {
	conn, err := s.dial(ctx)
	if err != nil {
		return err
	}
	// Closing the connection is what makes ctx cancellation (shutdown,
	// mostly) actually interrupt a conversation net/smtp has no way to
	// abort: the in-flight read returns "use of closed network
	// connection" and the send fails, which is correct -- it will be
	// retried. Double-closing is harmless.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(sendDeadline)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	host := s.cfg.Hostname()
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP greeting from %s: %w", s.cfg.Host, err)
	}
	defer func() { _ = client.Close() }()

	if s.cfg.STARTTLS {
		// Refuse rather than downgrade. A server that does not
		// advertise STARTTLS on a connection the operator asked to be
		// upgraded is either misconfigured or being impersonated, and
		// in both cases sending the credential in the clear is the one
		// thing that must not happen. net/smtp would happily continue.
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%s does not offer STARTTLS; refusing to continue in the clear (unset %s to use implicit TLS on port 465)", s.cfg.Host, EnvSTARTTLS)
		}
		if err := client.StartTLS(s.tlsConfig()); err != nil {
			return fmt.Errorf("STARTTLS to %s: %w", s.cfg.Host, err)
		}
	}

	if err := client.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, host)); err != nil {
		return fmt.Errorf("SMTP authentication as %s: %w", s.cfg.Username, err)
	}
	if err := client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("MAIL FROM %s: %w", s.cfg.From, err)
	}
	if err := client.Rcpt(s.cfg.To); err != nil {
		return fmt.Errorf("RCPT TO %s: %w", s.cfg.To, err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finish message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("QUIT: %w", err)
	}
	return nil
}

// dial opens the transport for one send: TLS from the first byte
// (implicit TLS, the default and what port 465 expects), or a plain TCP
// connection that deliver immediately upgrades with STARTTLS and never
// uses for anything else.
//
// tls.DialWithDialer rather than tls.Dial, and DialContext rather than
// Dial, only so the connection attempt is bounded and cancellable --
// tls.Dial uses the zero net.Dialer, which has no timeout at all, and a
// submission server that accepts a TCP connection and then stalls would
// hold the tick loop open.
func (s *Sender) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	if s.cfg.STARTTLS {
		conn, err := dialer.DialContext(ctx, "tcp", s.cfg.Host)
		if err != nil {
			return nil, fmt.Errorf("connect to %s: %w", s.cfg.Host, err)
		}
		return conn, nil
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", s.cfg.Host, s.tlsConfig())
	if err != nil {
		return nil, fmt.Errorf("TLS connect to %s: %w", s.cfg.Host, err)
	}
	return conn, nil
}

// assemble builds the whole message: seven fixed headers, a blank line,
// and the body.
//
// Every header value is checked with headerSafe immediately before it is
// written, regardless of what net/smtp does with the addresses it is
// separately handed. Four of these values (Subject, Date, Message-ID,
// and the two MIME headers) never pass through net/smtp at all -- they
// are bytes written straight into the DATA stream -- so a library's own
// validation would leave exactly the fields this function composes
// unguarded. The addresses have already been checked at startup too;
// checking again here costs nothing and means the guarantee belongs to
// this function rather than to the order in which it happens to be
// called.
//
// Line endings are plain "\n". net/smtp's DATA writer is a
// textproto.DotWriter, which translates them to CRLF and handles
// dot-stuffing, so the message on the wire is correct without this
// function duplicating either rule.
func (s *Sender) assemble(subject, body string, now time.Time) ([]byte, error) {
	headers := [][2]string{
		{"From", s.cfg.From},
		{"To", s.cfg.To},
		{"Subject", subject},
		{"Date", now.UTC().Format(time.RFC1123Z)},
		{"Message-ID", s.messageID()},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
	}

	var b strings.Builder
	for _, h := range headers {
		if !headerSafe(h[1]) {
			return nil, fmt.Errorf("mail: refusing to send: the %s header value contains a control character or a line break", h[0])
		}
		b.WriteString(h[0])
		b.WriteString(": ")
		b.WriteString(h[1])
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(body)
	return []byte(b.String()), nil
}

// newMessageID mints a Message-ID: 16 bytes of randomness and the
// sending domain. Random rather than derived from the alert, because a
// message id derived from what happened would leak that to anything
// that sees only the envelope -- a mail server's logs, for one.
//
// A failure from crypto/rand is not survivable and not worth a branch
// at every call site; it falls back to the timestamp, which is still
// unique enough for the only thing a Message-ID does here (stop a mail
// client threading unrelated alerts together).
func (s *Sender) newMessageID() string {
	var buf [16]byte
	domain := "birdcage.invalid"
	if _, at, ok := strings.Cut(s.cfg.From, "@"); ok && at != "" && headerSafe(at) {
		domain = at
	}
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), domain)
	}
	return fmt.Sprintf("<%s@%s>", hex.EncodeToString(buf[:]), domain)
}
