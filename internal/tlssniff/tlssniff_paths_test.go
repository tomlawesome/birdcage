package tlssniff

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeInner is an inner listener the test drives by hand: each Accept returns
// the next item sent on feed, or net.ErrClosed once Close has been called.
type fakeInner struct {
	feed      chan acceptResult
	closed    chan struct{}
	closeOnce sync.Once
}

type acceptResult struct {
	c   net.Conn
	err error
}

func newFakeInner() *fakeInner {
	return &fakeInner{feed: make(chan acceptResult, 8), closed: make(chan struct{})}
}

func (f *fakeInner) Accept() (net.Conn, error) {
	select {
	case r := <-f.feed:
		return r.c, r.err
	case <-f.closed:
		return nil, net.ErrClosed
	}
}
func (f *fakeInner) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}
func (f *fakeInner) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4433} }

// signalHandler sends a message on ch whenever a record contains substr.
type signalHandler struct {
	substr string
	ch     chan struct{}
}

func (h signalHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h signalHandler) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.substr) {
		select {
		case h.ch <- struct{}{}:
		default:
		}
	}
	return nil
}
func (h signalHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h signalHandler) WithGroup(string) slog.Handler      { return h }

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// requireEOF asserts the peer end sees the connection closed with no data.
func requireEOF(t *testing.T, peer net.Conn, what string) {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := peer.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("%s: read = %d bytes, %v; want the connection closed with no data", what, n, err)
	}
}

func TestAcceptAfterCloseReturnsErrClosedAndCloseIsIdempotent(t *testing.T) {
	l := Listener(newFakeInner(), discardLog(), allowOnly(allowedHost))
	if err := l.Close(); err != nil {
		t.Fatalf("first Close = %v", err)
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
	}
	_ = l.Close() // must not panic on the already-closed done channel
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after second Close = %v, want net.ErrClosed", err)
	}
}

func TestAcceptReturnsTheInnerListenersFatalError(t *testing.T) {
	inner := newFakeInner()
	l := Listener(inner, discardLog(), allowOnly(allowedHost))
	t.Cleanup(func() { _ = l.Close() })
	fatal := errors.New("inner listener failed for good")
	inner.feed <- acceptResult{err: fatal}
	for i := 0; i < 2; i++ { // the error is sticky, not consumed by one caller
		if _, err := l.Accept(); !errors.Is(err, fatal) {
			t.Fatalf("Accept #%d = %v, want the inner fatal error", i, err)
		}
	}
}

func TestCloseDuringTemporaryErrorBackoffStopsRetrying(t *testing.T) {
	inner := newFakeInner()
	warned := make(chan struct{}, 1)
	log := slog.New(signalHandler{substr: "accept error", ch: warned})
	l := Listener(inner, log, allowOnly(allowedHost))
	inner.feed <- acceptResult{err: tempErr{}}
	waitFor(t, warned, "the temporary-error warning")
	_ = l.Close()
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept = %v, want net.ErrClosed (a temporary error is not a permanent one)", err)
	}
}

// pipePair returns the server end handed to the listener and the client end.
func pipePair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	s, c := net.Pipe()
	t.Cleanup(func() { _ = s.Close(); _ = c.Close() })
	return s, c
}

func TestFullSniffCapConnectionIsClosedNotLeakedWhenListenerClosesUnaccepted(t *testing.T) {
	setLimits(t, time.Minute, 1)
	inner := newFakeInner()
	passed := make(chan struct{}, 1)
	l := Listener(inner, slog.New(signalHandler{substr: "passing", ch: passed}), allowOnly(allowedHost))

	holdS, _ := pipePair(t) // silent: occupies the only sniff slot
	waitS, waitC := pipePair(t)
	inner.feed <- acceptResult{c: holdS}
	inner.feed <- acceptResult{c: waitS}
	// The second connection found the cap full and now waits for an Accept
	// that never comes.
	waitFor(t, passed, "the bulkhead-full pass-through")
	_ = l.Close()
	requireEOF(t, waitC, "connection waiting past a full sniff cap when the listener closed")
}

func TestTLSConnectionIsClosedNotLeakedWhenListenerClosesUnaccepted(t *testing.T) {
	setLimits(t, time.Minute, 4)
	inner := newFakeInner()
	l := Listener(inner, discardLog(), allowOnly(allowedHost))
	s, c := pipePair(t)
	inner.feed <- acceptResult{c: s}
	if _, err := c.Write([]byte{tlsHandshake}); err != nil { // returns once the sniff read it
		t.Fatal(err)
	}
	_ = l.Close() // nobody ever called Accept
	requireEOF(t, c, "TLS connection handed off while the listener closed")
}

// expectClosedSilently sends raw and requires the server to close with no answer.
func expectClosedSilently(t *testing.T, raw string) {
	t.Helper()
	addr, _, accepted := serveRaw(t, allowOnly(allowedHost))
	c := dial(t, addr)
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil || len(b) != 0 {
		t.Fatalf("answer = %q, %v; want the connection closed with no answer", b, err)
	}
	noAccepted(t, accepted)
}

func TestMalformedRequestLineGetsNoAnswer(t *testing.T) {
	for name, raw := range map[string]string{
		"two fields":        "GET /\r\nHost: " + allowedHost + "\r\n\r\n",
		"not HTTP/1":        "GET / HTTP/2.0\r\nHost: " + allowedHost + "\r\n\r\n",
		"empty method":      " / HTTP/1.1\r\nHost: " + allowedHost + "\r\n\r\n",
		"target not a path": "GET relative HTTP/1.1\r\nHost: " + allowedHost + "\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) { expectClosedSilently(t, raw) })
	}
}

func TestAsteriskTargetRedirectsToRoot(t *testing.T) {
	u, _, port := redirectLocation(t, "OPTIONS * HTTP/1.1\r\nHost: "+allowedHost+"\r\n\r\n")
	if u.Scheme != "https" || u.Host != allowedHost+":"+port || u.Path != "/" {
		t.Errorf("Location = %s, want https://%s:%s/", u, allowedHost, port)
	}
}

func TestAllowerNameThatCouldBreakTheHeaderGets400(t *testing.T) {
	for _, name := range []string{"evil\thost", "evil\x7fhost", "evil\xc3\xa9host"} {
		t.Run(name, func(t *testing.T) {
			addr, _, accepted := serveRaw(t, func(string) string { return name })
			resp := roundTripPlain(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
			if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
				t.Errorf("status %d Location %q, want 400 and none", resp.StatusCode, resp.Header.Get("Location"))
			}
			noAccepted(t, accepted)
		})
	}
}
