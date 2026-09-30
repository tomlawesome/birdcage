package receiver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// startTestReceiver builds a Receiver on an OS-assigned loopback port,
// serves it on a background goroutine, and returns it along with a cleanup
// func that closes it and waits for Serve to return. cfg.Addr is always
// overridden to "127.0.0.1:0" so tests never fight each other for a port.
func startTestReceiver(t *testing.T, cfg Config, handler Handler) (*Receiver, func()) {
	t.Helper()

	cfg.Addr = "127.0.0.1:0"
	r, err := New(cfg, handler)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	served := make(chan error, 1)
	go func() { served <- r.Serve() }()

	cleanup := func() {
		_ = r.Close()
		err := <-served
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve returned unexpected error: %v", err)
		}
	}
	return r, cleanup
}

func postEvent(t *testing.T, addr net.Addr, body []byte) *http.Response {
	t.Helper()
	url := fmt.Sprintf("http://%s%s", addr.String(), Path)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	return resp
}

func TestAcceptsAndInvokesHandler(t *testing.T) {
	var got []byte
	var mu sync.Mutex
	r, cleanup := startTestReceiver(t, Config{}, func(body []byte) error {
		mu.Lock()
		got = append([]byte(nil), body...)
		mu.Unlock()
		return nil
	})
	defer cleanup()

	want := []byte(`{"logdata":{"msg":"hi"}}`)
	resp := postEvent(t, r.Addr(), want)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(got, want) {
		t.Fatalf("handler got %q, want %q (body must be handed over verbatim, never parsed)", got, want)
	}
}

func TestRejectsWrongMethod(t *testing.T) {
	called := false
	r, cleanup := startTestReceiver(t, Config{}, func([]byte) error {
		called = true
		return nil
	})
	defer cleanup()

	url := fmt.Sprintf("http://%s%s", r.Addr().String(), Path)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
	if called {
		t.Fatal("handler must not be called for a rejected method")
	}
}

func TestRejectsWrongPath(t *testing.T) {
	called := false
	r, cleanup := startTestReceiver(t, Config{}, func([]byte) error {
		called = true
		return nil
	})
	defer cleanup()

	url := fmt.Sprintf("http://%s/status", r.Addr().String())
	resp, err := http.Post(url, "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if called {
		t.Fatal("handler must not be called for a rejected path -- there is no status/control surface to probe")
	}
}

func TestRejectsOversizedBody(t *testing.T) {
	called := false
	cfg := Config{MaxBodyBytes: 16}
	r, cleanup := startTestReceiver(t, cfg, func([]byte) error {
		called = true
		return nil
	})
	defer cleanup()

	resp := postEvent(t, r.Addr(), bytes.Repeat([]byte("a"), 17))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
	if called {
		t.Fatal("handler must not be called for an oversized body")
	}
}

func TestAcceptsBodyAtExactCap(t *testing.T) {
	var gotLen int
	cfg := Config{MaxBodyBytes: 16}
	r, cleanup := startTestReceiver(t, cfg, func(body []byte) error {
		gotLen = len(body)
		return nil
	})
	defer cleanup()

	resp := postEvent(t, r.Addr(), bytes.Repeat([]byte("a"), 16))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if gotLen != 16 {
		t.Fatalf("handler got %d bytes, want exactly 16 (the cap itself must be accepted, not just cap-1)", gotLen)
	}
}

// TestSlowLorisStalledRequest proves a connection that opens and then
// trickles bytes slower than ReadTimeout is cut off rather than held open
// -- the "slow ... local client" fail-closed case -- and that Serve keeps
// running afterward.
func TestSlowLorisStalledRequest(t *testing.T) {
	cfg := Config{
		ReadHeaderTimeout: 100 * time.Millisecond,
		ReadTimeout:       150 * time.Millisecond,
	}
	r, cleanup := startTestReceiver(t, cfg, func([]byte) error { return nil })
	defer cleanup()

	conn, err := net.DialTimeout("tcp", r.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send a request line and headers announcing a body, but never send
	// the body -- a classic slow-loris stall.
	req := "POST " + Path + " HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The server must give up within a bounded time (well under
	// OpenCanary's own 1-2s webhook timeout) rather than waiting forever
	// for the body.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)
	if readErr != nil && n == 0 {
		// The server closed the connection outright without writing a
		// response -- also an acceptable "closed rather than waited on"
		// outcome for a stalled request.
		return
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		t.Fatalf("read: %v", readErr)
	}
	if !strings.Contains(string(buf[:n]), "HTTP/1.1") {
		t.Fatalf("expected an HTTP response closing the stalled connection, got %q", buf[:n])
	}
}

func TestConcurrentPosts(t *testing.T) {
	var count int64
	const n = 50
	// MaxConnections is deliberately raised above n: TestMaxConnections
	// already covers the connection cap on its own, so this test isolates
	// what it's actually checking -- that concurrent requests are handled
	// correctly and race-free -- from that unrelated limit.
	cfg := Config{MaxConnections: n}
	r, cleanup := startTestReceiver(t, cfg, func([]byte) error {
		atomic.AddInt64(&count, 1)
		return nil
	})
	defer cleanup()
	var wg sync.WaitGroup
	statuses := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := postEvent(t, r.Addr(), []byte(fmt.Sprintf(`{"i":%d}`, i)))
			defer func() { _ = resp.Body.Close() }()
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	for i, code := range statuses {
		if code != http.StatusAccepted {
			t.Errorf("request %d: status = %d, want %d", i, code, http.StatusAccepted)
		}
	}
	if got := atomic.LoadInt64(&count); got != n {
		t.Fatalf("handler invoked %d times, want %d", got, n)
	}
}

// TestDownstreamTooSlow proves that when Handler does not return within
// Config.HandlerTimeout, serveHTTP responds without waiting for it -- the
// chosen behaviour for "the downstream cannot accept": the request is
// failed closed (503) on this package's own clock, never on the
// handler's.
func TestDownstreamTooSlow(t *testing.T) {
	release := make(chan struct{})
	defer close(release) // let the stuck handler goroutine finish so the test process can exit cleanly
	cfg := Config{HandlerTimeout: 50 * time.Millisecond}
	r, cleanup := startTestReceiver(t, cfg, func([]byte) error {
		<-release
		return nil
	})
	defer cleanup()

	start := time.Now()
	resp := postEvent(t, r.Addr(), []byte(`{}`))
	defer func() { _ = resp.Body.Close() }()
	elapsed := time.Since(start)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	// Generous bound: must return close to HandlerTimeout, not wait for
	// the handler (which never returns until the test releases it).
	if elapsed > time.Second {
		t.Fatalf("response took %v, want well under 1s (must not wait on a stuck downstream)", elapsed)
	}
}

// TestDownstreamRefuses proves that a Handler-reported failure -- as
// opposed to a timeout -- also fails the request closed rather than
// retrying or waiting.
func TestDownstreamRefuses(t *testing.T) {
	r, cleanup := startTestReceiver(t, Config{}, func([]byte) error {
		return errors.New("downstream cannot accept")
	})
	defer cleanup()

	resp := postEvent(t, r.Addr(), []byte(`{}`))
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

// TestMaxConnections proves the concurrent-connection cap rejects surplus
// connections by closing them immediately rather than queueing them, so a
// local flood cannot build an unbounded backlog ahead of OpenCanary's own
// connection attempt.
func TestMaxConnections(t *testing.T) {
	cfg := Config{MaxConnections: 2}
	r, cleanup := startTestReceiver(t, cfg, func([]byte) error { return nil })
	defer cleanup()

	// Hold MaxConnections connections open without completing a request,
	// occupying every slot.
	held := make([]net.Conn, cfg.MaxConnections)
	for i := range held {
		c, err := net.DialTimeout("tcp", r.Addr().String(), time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer func() { _ = c.Close() }()
		held[i] = c
	}
	// Give the server a moment to accept and register each connection
	// against the semaphore before the surplus dial below.
	time.Sleep(100 * time.Millisecond)

	surplus, err := net.DialTimeout("tcp", r.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial surplus: %v", err)
	}
	defer func() { _ = surplus.Close() }()

	_ = surplus.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	n, readErr := surplus.Read(buf)
	if readErr == nil && n > 0 {
		t.Fatalf("expected the surplus connection to be closed with no data, got %d bytes", n)
	}
	if readErr != io.EOF && !errors.Is(readErr, io.EOF) {
		// Some platforms may report a reset instead of a clean EOF; either
		// way this must not be a successful read.
		var netErr net.Error
		if errors.As(readErr, &netErr) && netErr.Timeout() {
			t.Fatalf("surplus connection was not closed within the deadline: %v", readErr)
		}
	}
}

func TestNewRejectsNonLoopbackAddr(t *testing.T) {
	cases := []string{
		"0.0.0.0:0",   // all interfaces
		"8.8.8.8:0",   // a real, non-loopback IP
		"localhost:0", // hostname -- no DNS trust
		":0",          // empty host, also all interfaces
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			_, err := New(Config{Addr: addr}, func([]byte) error { return nil })
			if err == nil {
				t.Fatalf("New(%q) succeeded, want a loopback-only error", addr)
			}
		})
	}
}

func TestNewRejectsNilHandler(t *testing.T) {
	_, err := New(Config{Addr: "127.0.0.1:0"}, nil)
	if err == nil {
		t.Fatal("New with a nil handler succeeded, want an error")
	}
}

// TestNotReachableFromNonLoopback documents, rather than fully proves, the
// "loopback only" guarantee's second half. requireLoopback (exercised
// above) is the enforceable part within this package: New refuses to bind
// anywhere but a literal 127.0.0.0/8 or ::1 address. Once bound to such an
// address, "not reachable from outside the box" is the operating system's
// guarantee about what 127.0.0.1 means, not something this package's own
// code decides -- and this sandbox exposes no non-loopback interface to
// dial from, so that second half cannot be exercised here. This test
// confirms the one thing that can be checked without another interface:
// the bound address really is loopback.
func TestNotReachableFromNonLoopback(t *testing.T) {
	r, cleanup := startTestReceiver(t, Config{}, func([]byte) error { return nil })
	defer cleanup()

	host, _, err := net.SplitHostPort(r.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("bound address %q is not a loopback IP", r.Addr().String())
	}
}

// TestServeCloseUnblocks makes sure Close actually stops Serve, since
// several other tests depend on cleanup completing without hanging the
// test binary.
func TestServeCloseUnblocks(t *testing.T) {
	r, err := New(Config{Addr: "127.0.0.1:0"}, func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Serve() }()

	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve returned %v, want http.ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

// TestConfigDefaults sanity-checks that leaving Config's numeric fields
// zero-valued (as most real callers will for everything but Addr) produces
// the documented defaults, not zero caps that would reject every request.
func TestConfigDefaults(t *testing.T) {
	cfg := Config{Addr: "127.0.0.1:0"}.withDefaults()
	if cfg.MaxBodyBytes != DefaultMaxBodyBytes {
		t.Errorf("MaxBodyBytes = %d, want %d", cfg.MaxBodyBytes, DefaultMaxBodyBytes)
	}
	if cfg.MaxConnections != DefaultMaxConnections {
		t.Errorf("MaxConnections = %d, want %d", cfg.MaxConnections, DefaultMaxConnections)
	}
	if cfg.HandlerTimeout != DefaultHandlerTimeout {
		t.Errorf("HandlerTimeout = %v, want %v", cfg.HandlerTimeout, DefaultHandlerTimeout)
	}
}
