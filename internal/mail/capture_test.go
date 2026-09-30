package mail

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file is the in-process SMTP server every send test in this
// package talks to. Nothing in this package's tests ever opens a
// connection to a real mail server, and there is no environment
// variable or build tag that would let one: the only address a test
// ever dials is a listener it created itself on 127.0.0.1.
//
// The dialogue is the minimum a send needs -- greeting, EHLO, AUTH
// PLAIN, MAIL FROM, RCPT TO, DATA, QUIT -- and the server records what
// it was told rather than delivering anything.

// captureServer is one test's SMTP server. Everything it received is
// readable after the test's send returns.
type captureServer struct {
	// Addr is "127.0.0.1:port", ready to be used as BIRDCAGE_MAIL_HOST.
	Addr string
	// Roots trusts this server's own self-signed certificate. Tests
	// assign it to Sender.testRoots; the untrusted-certificate test
	// deliberately does not.
	Roots *x509.CertPool

	// startTLS makes this a plain listener that advertises STARTTLS and
	// upgrades on the command. false is implicit TLS from the first
	// byte.
	startTLS bool
	// offerSTARTTLS controls whether the EHLO response lists STARTTLS.
	// A plain server with this false is the "server does not offer
	// STARTTLS" case the client must refuse rather than downgrade to.
	offerSTARTTLS bool
	// rejectAuth makes AUTH PLAIN fail, so a test can see what
	// birdcage stores about a rejected credential.
	rejectAuth bool

	tlsConfig *tls.Config
	listener  net.Listener

	mu sync.Mutex
	// AuthUser/AuthPass are what AUTH PLAIN carried. Recorded so a test
	// can prove the credential arrived only over TLS; never logged.
	AuthUser string
	AuthPass string
	// MailFrom/RcptTo are the envelope, Data the message exactly as it
	// arrived on the wire (dot-stuffing undone, CRLF left alone).
	MailFrom string
	RcptTo   string
	Data     string
	// Sessions counts completed connections, and Delivered counts
	// messages that reached the end of DATA -- so a test can assert
	// that nothing was sent, not merely that nothing was recorded.
	Sessions  int
	Delivered int
}

type captureOption func(*captureServer)

// withSTARTTLS makes the server a plain listener that advertises
// STARTTLS and upgrades on the command -- the port-587 shape.
func withSTARTTLS() captureOption {
	return func(s *captureServer) { s.startTLS, s.offerSTARTTLS = true, true }
}

// withoutSTARTTLSOffer makes the server a plain listener that never
// advertises STARTTLS. A client configured for STARTTLS must refuse it.
func withoutSTARTTLSOffer() captureOption {
	return func(s *captureServer) { s.startTLS, s.offerSTARTTLS = true, false }
}

// withAuthFailure makes the server reject the credential, so a test can
// prove the stored error does not quote it back.
func withAuthFailure() captureOption {
	return func(s *captureServer) { s.rejectAuth = true }
}

// newCaptureServer starts a server on 127.0.0.1 and stops it when the
// test ends.
func newCaptureServer(t *testing.T, opts ...captureOption) *captureServer {
	t.Helper()
	s := &captureServer{}
	for _, opt := range opts {
		opt(s)
	}

	cert, roots := selfSignedCert(t)
	s.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	s.Roots = roots

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if !s.startTLS {
		ln = tls.NewListener(ln, s.tlsConfig)
	}
	s.listener = ln
	s.Addr = ln.Addr().String()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.serve(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return s
}

// serve runs one session. Every failure simply ends the session: this
// is a test double, and a client that hangs up mid-conversation is
// exactly what some of these tests are asserting.
func (s *captureServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	write := func(lines ...string) bool {
		for _, l := range lines {
			if _, err := rw.WriteString(l + "\r\n"); err != nil {
				return false
			}
		}
		return rw.Flush() == nil
	}

	s.mu.Lock()
	s.Sessions++
	s.mu.Unlock()

	if !write("220 capture.invalid ESMTP birdcage-test") {
		return
	}

	upgraded := !s.startTLS
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb, rest, _ := strings.Cut(line, " ")

		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			greeting := []string{"250-capture.invalid"}
			if s.startTLS && !upgraded && s.offerSTARTTLS {
				greeting = append(greeting, "250-STARTTLS")
			}
			greeting = append(greeting, "250-AUTH PLAIN", "250 SIZE 10240000")
			if !write(greeting...) {
				return
			}
		case "STARTTLS":
			if !s.offerSTARTTLS {
				if !write("500 5.5.1 command not recognized") {
					return
				}
				continue
			}
			if !write("220 2.0.0 ready to start TLS") {
				return
			}
			tlsConn := tls.Server(conn, s.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			rw = bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
			write = func(lines ...string) bool {
				for _, l := range lines {
					if _, err := rw.WriteString(l + "\r\n"); err != nil {
						return false
					}
				}
				return rw.Flush() == nil
			}
			upgraded = true
		case "AUTH":
			mech, payload, _ := strings.Cut(rest, " ")
			if !strings.EqualFold(mech, "PLAIN") {
				if !write("504 5.5.4 unrecognized authentication type") {
					return
				}
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
			if err != nil {
				if !write("535 5.7.8 bad credentials") {
					return
				}
				continue
			}
			// AUTH PLAIN is identity\0username\0password.
			parts := strings.Split(string(raw), "\x00")
			if len(parts) == 3 {
				s.mu.Lock()
				s.AuthUser, s.AuthPass = parts[1], parts[2]
				s.mu.Unlock()
			}
			if s.rejectAuth {
				// Quotes the credential back deliberately: a real
				// server can, and birdcage's own scrub is what has to
				// stop that reaching the outbox or a log line.
				if !write("535 5.7.8 authentication failed for " + strings.ReplaceAll(string(raw), "\x00", " ")) {
					return
				}
				continue
			}
			if !write("235 2.7.0 authentication succeeded") {
				return
			}
		case "MAIL":
			s.mu.Lock()
			s.MailFrom = addressIn(rest)
			s.mu.Unlock()
			if !write("250 2.1.0 sender ok") {
				return
			}
		case "RCPT":
			s.mu.Lock()
			s.RcptTo = addressIn(rest)
			s.mu.Unlock()
			if !write("250 2.1.5 recipient ok") {
				return
			}
		case "DATA":
			if !write("354 end with <CR><LF>.<CR><LF>") {
				return
			}
			data, err := readDotBlock(rw)
			if err != nil {
				return
			}
			s.mu.Lock()
			s.Data = data
			s.Delivered++
			s.mu.Unlock()
			if !write("250 2.0.0 queued") {
				return
			}
		case "QUIT":
			write("221 2.0.0 bye")
			return
		case "RSET", "NOOP":
			if !write("250 2.0.0 ok") {
				return
			}
		default:
			if !write("500 5.5.1 command not recognized") {
				return
			}
		}
	}
}

// readDotBlock reads a DATA payload up to the lone "." line, undoing
// dot-stuffing and leaving the CRLF line endings exactly as they
// arrived -- pinning the wire form is the point, since one of the
// things under test is that the message leaves with CRLF at all.
func readDotBlock(rw *bufio.ReadWriter) (string, error) {
	var b strings.Builder
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return "", err
		}
		if line == ".\r\n" || line == ".\n" {
			return b.String(), nil
		}
		b.WriteString(strings.TrimPrefix(line, "."))
	}
}

// addressIn pulls the address out of "FROM:<a@b>" / "TO:<a@b>".
func addressIn(rest string) string {
	_, addr, ok := strings.Cut(rest, "<")
	if !ok {
		return strings.TrimSpace(rest)
	}
	addr, _, _ = strings.Cut(addr, ">")
	return addr
}

// received returns everything the server recorded, under its lock.
func (s *captureServer) received() (from, to, data string, delivered int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.MailFrom, s.RcptTo, s.Data, s.Delivered
}

func (s *captureServer) credentials() (user, pass string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.AuthUser, s.AuthPass
}

// selfSignedCert mints a certificate for 127.0.0.1, valid for an hour,
// and a pool that trusts it. Self-signed and generated per test, so
// nothing here is a checked-in key and nothing survives the test binary.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "birdcage mail capture"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// quietLogger keeps the sender's own ERROR lines out of test output --
// several tests here make a send fail on purpose.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
