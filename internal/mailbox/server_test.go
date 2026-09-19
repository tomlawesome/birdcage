package mailbox

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// This file is the in-process IMAP server every test in this package
// talks to. Nothing here ever opens a connection to a real mail
// provider, and there is no environment variable or build tag that
// would let one: the only address a test dials is a TLS listener it
// created itself on 127.0.0.1, with a certificate generated in the
// test and thrown away with it.

const (
	testUser     = "birdcage@example.net"
	testPassword = "correct-horse-battery-staple"
)

// testServer is one test's IMAP server, plus the handles a test needs
// to put messages into it and to point a Reader at it.
type testServer struct {
	// Addr is "127.0.0.1:port", ready to be used as Config.Host.
	Addr string
	// Roots trusts this server's own self-signed certificate. Tests
	// assign it to Reader.testRoots; the untrusted-certificate test
	// deliberately does not.
	Roots *x509.CertPool

	user *imapmemserver.User
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()

	cert, roots := selfSignedCert(t)

	mem := imapmemserver.New()
	user := imapmemserver.NewUser(testUser, testPassword)
	if err := user.Create(DefaultMailbox, nil); err != nil {
		t.Fatalf("create %s: %v", DefaultMailbox, err)
	}
	mem.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {},
			imap.CapIMAP4rev2: {},
		},
		// Errors from a connection a test deliberately broke are not
		// test output worth reading.
		Logger: quietServerLogger{},
	})

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := tls.NewListener(tcpLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})

	return &testServer{Addr: tcpLn.Addr().String(), Roots: roots, user: user}
}

// reader returns a Reader pointed at this server and trusting its
// certificate.
func (s *testServer) reader(t *testing.T) *Reader {
	t.Helper()
	r := New(Config{
		Host:     s.Addr,
		Username: testUser,
		Password: testPassword,
		Mailbox:  DefaultMailbox,
	}, quietLogger(t))
	r.testRoots = s.Roots
	return r
}

// deliver puts one message in the mailbox, unread.
func (s *testServer) deliver(t *testing.T, raw []byte) {
	t.Helper()
	if _, err := s.user.Append(DefaultMailbox, &literal{Reader: bytes.NewReader(raw), size: int64(len(raw))}, &imap.AppendOptions{
		Time: time.Now(),
	}); err != nil {
		t.Fatalf("append message: %v", err)
	}
}

// literal adapts a byte slice to imap.LiteralReader.
type literal struct {
	io.Reader
	size int64
}

func (l *literal) Size() int64 { return l.size }

// testMessage builds a plausible approval reply of the given size. Only
// the subject and the body length matter to this package -- whether the
// message is genuine is internal/agent/approval's question, asked on
// the bytes this package hands over.
func testMessage(subject string, bodyLen int) []byte {
	var b bytes.Buffer
	b.WriteString("From: Birdcage Admin <admin@example.net>\r\n")
	b.WriteString("To: birdcage@example.net\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: Fri, 19 Sep 2026 10:00:00 +0000\r\n")
	b.WriteString("Message-ID: <" + subject + "@example.net>\r\n")
	b.WriteString("\r\n")
	for b.Len() < bodyLen {
		b.WriteString("yes go ahead\r\n")
	}
	return b.Bytes()
}

// selfSignedCert mints a certificate for 127.0.0.1, valid for an hour,
// and a pool that trusts it. Self-signed and generated per test, so
// nothing here is a checked-in key and nothing survives the test
// binary. Same helper, same reasoning, as internal/mail's.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "birdcage mailbox test"},
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

// quietLogger keeps the reader's own WARN lines out of test output --
// several tests here make a poll skip a message on purpose.
func quietLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type quietServerLogger struct{}

func (quietServerLogger) Printf(format string, args ...any) {}
