package tlssniff

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const allowedHost = "birdcage.example.com"

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// allowOnly accepts one name, with or without a port, and returns it bare.
func allowOnly(name string) HostAllower {
	return func(requested string) string {
		h := requested
		if hh, _, err := net.SplitHostPort(requested); err == nil {
			h = hh
		}
		if strings.EqualFold(h, name) {
			return name
		}
		return ""
	}
}

// setLimits lowers the package limits for one test and restores them after.
func setLimits(t *testing.T, timeout time.Duration, maxConc int) {
	t.Helper()
	oldT, oldM := SniffTimeout, MaxConcurrentSniffs
	SniffTimeout, MaxConcurrentSniffs = timeout, maxConc
	t.Cleanup(func() { SniffTimeout, MaxConcurrentSniffs = oldT, oldM })
}

// serveRaw starts the sniffing listener on loopback and drains Accept in the
// background; every connection Accept returns is sent on the channel.
func serveRaw(t *testing.T, allow HostAllower) (addr string, port string, accepted chan net.Conn) {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := Listener(inner, discardLog(), allow)
	t.Cleanup(func() { _ = l.Close() })
	accepted = make(chan net.Conn, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	_, port, _ = net.SplitHostPort(inner.Addr().String())
	return inner.Addr().String(), port, accepted
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// roundTripPlain sends raw bytes and reads one response; the connection must
// then be closed by the server.
func roundTripPlain(t *testing.T, addr, raw string) *http.Response {
	t.Helper()
	c := dial(t, addr)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, _ = io.Copy(io.Discard, resp.Body)
	if _, err := br.ReadByte(); err == nil {
		t.Error("connection still open after the answer, want closed")
	}
	return resp
}

func noAccepted(t *testing.T, accepted chan net.Conn) {
	t.Helper()
	select {
	case c := <-accepted:
		_ = c.Close()
		t.Error("Accept returned a plain-HTTP connection, want it answered inside the package")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPlainGetWithAllowedHostRedirects308KeepingPathQueryAndPort(t *testing.T) {
	for _, host := range []string{allowedHost, allowedHost + ":8443"} {
		t.Run(host, func(t *testing.T) {
			addr, port, accepted := serveRaw(t, allowOnly(allowedHost))
			resp := roundTripPlain(t, addr, "GET /a/b?x=1&y=2 HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
			if resp.StatusCode != http.StatusPermanentRedirect {
				t.Fatalf("status = %d, want 308", resp.StatusCode)
			}
			want := "https://" + allowedHost + ":" + port + "/a/b?x=1&y=2"
			if got := resp.Header.Get("Location"); got != want {
				t.Errorf("Location = %q, want %q", got, want)
			}
			if c := resp.Header.Values("Set-Cookie"); len(c) != 0 {
				t.Errorf("Set-Cookie sent over plain HTTP: %v", c)
			}
			noAccepted(t, accepted)
		})
	}
}

func TestPlainGetRootPathRedirects(t *testing.T) {
	addr, port, _ := serveRaw(t, allowOnly(allowedHost))
	resp := roundTripPlain(t, addr, "GET / HTTP/1.1\r\nHost: "+allowedHost+"\r\n\r\n")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "https://"+allowedHost+":"+port+"/"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestPlainRequestWithDisallowedHostGets400NoLocation(t *testing.T) {
	addr, _, accepted := serveRaw(t, allowOnly(allowedHost))
	resp := roundTripPlain(t, addr, "GET /x HTTP/1.1\r\nHost: attacker.example.org\r\n\r\n")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if l := resp.Header.Get("Location"); l != "" {
		t.Errorf("Location = %q, want none", l)
	}
	noAccepted(t, accepted)
}

func TestPlainRequestWithMissingHostGets400NoLocation(t *testing.T) {
	// The allower would accept anything: the package itself must refuse a
	// request that names no host.
	any := func(string) string { return "anything.example.com" }
	addr, _, _ := serveRaw(t, any)
	resp := roundTripPlain(t, addr, "GET /x HTTP/1.0\r\n\r\n")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if l := resp.Header.Get("Location"); l != "" {
		t.Errorf("Location = %q, want none", l)
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: allowedHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{allowedHost},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestTLSClientStillCompletesARequestAndPlainOnSamePortRedirects(t *testing.T) {
	cert := selfSigned(t)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var handled atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled.Add(1)
		_, _ = io.WriteString(w, "hello over tls")
	})}
	tl := tls.NewListener(Listener(inner, discardLog(), allowOnly(allowedHost)), &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() { _ = srv.Serve(tl) }()
	t.Cleanup(func() { _ = srv.Close() })

	pool := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool.AddCert(leaf)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	resp, err := client.Get("https://" + inner.Addr().String() + "/")
	if err != nil {
		t.Fatalf("TLS request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello over tls" {
		t.Errorf("got %d %q, want 200 \"hello over tls\"", resp.StatusCode, body)
	}
	if handled.Load() != 1 {
		t.Fatalf("handler calls = %d, want 1", handled.Load())
	}

	// Plain HTTP on the same port is redirected and never reaches the handler.
	r2 := roundTripPlain(t, inner.Addr().String(), "GET /p HTTP/1.1\r\nHost: "+allowedHost+"\r\n\r\n")
	if r2.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("plain status = %d, want 308", r2.StatusCode)
	}
	if handled.Load() != 1 {
		t.Errorf("handler reached by plain HTTP (calls = %d)", handled.Load())
	}
}

func TestSilentClientIsClosedAfterSniffTimeout(t *testing.T) {
	setLimits(t, 200*time.Millisecond, 256)
	addr, _, accepted := serveRaw(t, allowOnly(allowedHost))
	c := dial(t, addr)
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("read = %v, want the server to close the connection", err)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 2*time.Second {
		t.Errorf("closed after %s, want about the 200ms timeout", d)
	}
	noAccepted(t, accepted)
}

func TestSlowPlainClientIsClosedAfterSniffTimeout(t *testing.T) {
	setLimits(t, 200*time.Millisecond, 256)
	addr, _, _ := serveRaw(t, allowOnly(allowedHost))
	c := dial(t, addr)
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: "+allowedHost+"\r\n") // never finishes the headers
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := io.ReadAll(c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("connection still open after the timeout")
	}
	if strings.Contains(string(b), "308") {
		t.Errorf("redirected an incomplete request: %q", b)
	}
}

func TestOversizedRequestLineGetsNoRedirect(t *testing.T) {
	addr, _, accepted := serveRaw(t, allowOnly(allowedHost))
	c := dial(t, addr)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	raw := "GET /" + strings.Repeat("a", 9*1024) + " HTTP/1.1\r\nHost: " + allowedHost + "\r\n\r\n"
	_, _ = io.WriteString(c, raw) // may fail once the server closes
	b, _ := io.ReadAll(c)
	s := string(b)
	if strings.Contains(s, "308") || strings.Contains(strings.ToLower(s), "location:") {
		t.Errorf("oversized request was redirected: %q", s)
	}
	noAccepted(t, accepted)
}

func TestOversizedHeadersGetNoRedirect(t *testing.T) {
	addr, _, _ := serveRaw(t, allowOnly(allowedHost))
	c := dial(t, addr)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	raw := "GET / HTTP/1.1\r\nHost: " + allowedHost + "\r\nX-Pad: " + strings.Repeat("b", 9*1024) + "\r\n\r\n"
	_, _ = io.WriteString(c, raw)
	b, _ := io.ReadAll(c)
	if strings.Contains(string(b), "308") || strings.Contains(strings.ToLower(string(b)), "location:") {
		t.Errorf("oversized headers were redirected: %q", b)
	}
}

func TestConcurrencyCapClosesExcessConnections(t *testing.T) {
	setLimits(t, 5*time.Second, 2)
	addr, _, _ := serveRaw(t, allowOnly(allowedHost))

	held := []net.Conn{dial(t, addr), dial(t, addr)}
	time.Sleep(150 * time.Millisecond) // let both be taken into the sniff

	extra := dial(t, addr)
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess connection got data, want it closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("excess connection still open past the cap, want it closed")
	}

	// The held ones are still waiting, not closed.
	for i, h := range held {
		_ = h.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := h.Read(make([]byte, 1)); err == nil {
			t.Errorf("held conn %d got data", i)
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Errorf("held conn %d closed (%v), want still waiting", i, err)
		}
	}

	// Freeing a slot lets a new connection through.
	_ = held[0].Close()
	time.Sleep(150 * time.Millisecond)
	resp := roundTripPlain(t, addr, "GET / HTTP/1.1\r\nHost: "+allowedHost+"\r\n\r\n")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("after a slot freed, status = %d, want 308", resp.StatusCode)
	}
}

type tempErr struct{}

func (tempErr) Error() string   { return "temporary accept failure" }
func (tempErr) Timeout() bool   { return true }
func (tempErr) Temporary() bool { return true }

type flakyListener struct {
	net.Listener
	failures atomic.Int32
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.failures.Add(-1) >= 0 {
		return nil, tempErr{}
	}
	return f.Listener.Accept()
}

func TestTemporaryAcceptErrorDoesNotStopTheListener(t *testing.T) {
	real, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fl := &flakyListener{Listener: real}
	fl.failures.Store(2)
	l := Listener(fl, discardLog(), allowOnly(allowedHost))
	t.Cleanup(func() { _ = l.Close() })

	got := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			_ = c.Close()
		}
		got <- err
	}()

	// A TLS-looking first byte makes Accept return the connection.
	c := dial(t, real.Addr().String())
	_, _ = c.Write([]byte{0x16, 0x03, 0x01})
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("Accept = %v, want the connection after temporary errors", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal(fmt.Sprint("Accept did not return a connection after temporary errors"))
	}
}

func TestTLSFirstByteIsReplayed(t *testing.T) {
	addr, _, accepted := serveRaw(t, allowOnly(allowedHost))
	c := dial(t, addr)
	want := []byte{0x16, 0x03, 0x01, 0xAA, 0xBB}
	_, _ = c.Write(want)
	select {
	case sc := <-accepted:
		defer sc.Close()
		_ = sc.SetReadDeadline(time.Now().Add(2 * time.Second))
		got := make([]byte, len(want))
		if _, err := io.ReadFull(sc, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("replayed bytes = %x, want %x", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS-looking connection not returned by Accept")
	}
}
