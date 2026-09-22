package readiness

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// listenLoopback opens a real TCP listener on loopback, accepting (and
// immediately closing) whatever connects, and returns its port. A real
// socket rather than a fake dialer is the point of this test: what Check
// must prove is that dialing an address that nothing is listening on
// behaves differently from dialing one that is, and only a real listener
// (or its absence) demonstrates that.
func listenLoopback(t *testing.T) (port int, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p := 0
	for _, c := range portStr {
		p = p*10 + int(c-'0')
	}
	return p, func() { _ = ln.Close() }
}

// closedPort returns a port nothing is listening on: opened then
// immediately closed, so the kernel has released it but nothing has
// re-bound it in the meantime -- on loopback, on this host, a connect to
// it comes back refused rather than hanging.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p := 0
	for _, c := range portStr {
		p = p*10 + int(c-'0')
	}
	_ = ln.Close()
	return p
}

func TestCheckDistinguishesUpFromDown(t *testing.T) {
	t.Parallel()

	upPort, closeFn := listenLoopback(t)
	defer closeFn()
	downPort := closedPort(t)

	ports := map[string]int{
		"ftp":   upPort,
		"https": downPort,
	}

	results := Check(context.Background(), Dial, "127.0.0.1", ports, 2*time.Second)

	byModule := map[string]Result{}
	for _, r := range results {
		byModule[r.Module] = r
	}

	if !byModule["ftp"].Up {
		t.Errorf("ftp (a real listener) reported Up=false, err=%v", byModule["ftp"].Err)
	}
	if byModule["https"].Up {
		t.Error("https (nothing listening) reported Up=true")
	}
	if byModule["https"].Err == nil {
		t.Error("https (nothing listening) reported a nil error")
	}
}

func TestCheckReturnsOneResultPerModule(t *testing.T) {
	t.Parallel()

	ports := map[string]int{"a": closedPort(t), "b": closedPort(t), "c": closedPort(t)}
	results := Check(context.Background(), Dial, "127.0.0.1", ports, 500*time.Millisecond)
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
}

// TestCheckHonoursACanceledContext: a canceled context must not hang --
// dial errors out instead of blocking on the timeout.
func TestCheckHonoursACanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ports := map[string]int{"ftp": closedPort(t)}
	done := make(chan []Result, 1)
	go func() { done <- Check(ctx, Dial, "127.0.0.1", ports, 5*time.Second) }()

	select {
	case results := <-done:
		if results[0].Up {
			t.Error("dial succeeded against a canceled context")
		}
		if !errors.Is(results[0].Err, context.Canceled) && results[0].Err == nil {
			t.Errorf("expected a context-canceled-flavoured error, got %v", results[0].Err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Check did not return promptly for a canceled context")
	}
}
