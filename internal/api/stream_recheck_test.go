package api

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/stream"
)

const recheckTestInterval = 30 * time.Millisecond

// setRecheckInterval sets StreamRecheckInterval for streams opened after
// the call and restores it when the test ends.
func setRecheckInterval(t *testing.T, d time.Duration) {
	t.Helper()
	old := StreamRecheckInterval
	StreamRecheckInterval = d
	t.Cleanup(func() { StreamRecheckInterval = old })
}

type recheckStream struct {
	hub     *stream.Hub
	db      *db.DB
	resp    *http.Response
	cancel  context.CancelFunc
	done    chan struct{} // closed when the handler returns
	lines   chan string
	eof     chan struct{} // closed when the body reaches EOF
	handled atomic.Bool
}

// openRecheckStream opens GET /api/stream against the real handler. When
// check is non-nil it is put on the request context the way the sign-in
// layer does, via WithCredentialCheck.
func openRecheckStream(t *testing.T, check func() bool) *recheckStream {
	t.Helper()
	database := openTempDB(t)
	hub := stream.NewHub()
	h := NewHandlerWithHub(database, nil, hub, false, "", UpgradeConfig{})
	rs := &recheckStream{hub: hub, db: database, done: make(chan struct{}), lines: make(chan string, 64), eof: make(chan struct{})}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			r = r.WithContext(WithCredentialCheck(r.Context(), check))
		}
		defer close(rs.done)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	rs.cancel = cancel
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/stream", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/stream: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	rs.resp = resp
	go func() {
		defer close(rs.eof)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			select {
			case rs.lines <- sc.Text():
			default:
			}
		}
	}()
	return rs
}

func (rs *recheckStream) handlerEnded(d time.Duration) bool {
	select {
	case <-rs.done:
		return true
	case <-time.After(d):
		return false
	}
}

func (rs *recheckStream) bodyEnded(d time.Duration) bool {
	select {
	case <-rs.eof:
		return true
	case <-time.After(d):
		return false
	}
}

// waitCalls waits up to 5s for the counter to reach n.
func waitCalls(t *testing.T, c *atomic.Int64, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("check called %d times, want at least %d", c.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Catches: a revoked credential keeps its stream open forever (check
// never consulted, or its false result ignored).
func TestStreamRecheckEndsStreamWhenCheckReturnsFalse(t *testing.T) {
	setRecheckInterval(t, recheckTestInterval)
	var calls atomic.Int64
	rs := openRecheckStream(t, func() bool {
		return calls.Add(1) < 3 // valid twice, then revoked
	})
	if !rs.handlerEnded(2 * time.Second) {
		t.Fatal("handler did not return after the check returned false")
	}
	if !rs.bodyEnded(2 * time.Second) {
		t.Fatal("response body did not reach EOF after the check returned false")
	}
	if got := calls.Load(); got < 3 {
		t.Errorf("check called %d times, want at least 3 (once per interval)", got)
	}
}

// Catches: the check being called only once (or never) rather than every
// interval while the stream is open.
func TestStreamRecheckCallsCheckRepeatedly(t *testing.T) {
	setRecheckInterval(t, recheckTestInterval)
	var calls atomic.Int64
	rs := openRecheckStream(t, func() bool { calls.Add(1); return true })
	waitCalls(t, &calls, 5)
	select {
	case <-rs.done:
		t.Fatal("stream ended although the check kept returning true")
	default:
	}
}

// Catches: re-checking breaking delivery -- a valid stream must still
// deliver alerts stored after checks have run.
func TestStreamRecheckValidStreamStillDeliversAlerts(t *testing.T) {
	setRecheckInterval(t, recheckTestInterval)
	var calls atomic.Int64
	rs := openRecheckStream(t, func() bool { calls.Add(1); return true })
	waitCalls(t, &calls, 3)

	a := store.AlertInsert{
		InstanceID: "node-1",
		SourceIP:   "203.0.113.9",
		DestPort:   22,
		Service:    "ssh",
		Raw:        `{"src_host":"203.0.113.9"}`,
		ReceivedAt: time.Now().UTC(),
	}
	stored, err := store.InsertAlertIfNew(context.Background(), rs.db, a)
	if err != nil || !stored {
		t.Fatalf("InsertAlertIfNew: stored=%v err=%v", stored, err)
	}
	rs.hub.PublishAlert(a)

	deadline := time.After(2 * time.Second)
	for {
		select {
		case l := <-rs.lines:
			if strings.HasPrefix(l, "data: ") {
				goto delivered
			}
		case <-deadline:
			t.Fatal("no data event after an alert was stored on a re-checked stream")
		}
	}
delivered:
	if got := calls.Load(); got < 3 {
		t.Errorf("check calls = %d, want at least 3", got)
	}
}

// Catches: a missing check being treated as "invalid" (stream cut) or
// causing a nil-call panic; with no check the stream stays open.
func TestStreamRecheckWithoutCheckStaysOpen(t *testing.T) {
	setRecheckInterval(t, recheckTestInterval)
	rs := openRecheckStream(t, nil)
	if rs.handlerEnded(10 * recheckTestInterval) {
		t.Fatal("stream ended with no credential check in the context")
	}
	if rs.bodyEnded(time.Millisecond) {
		t.Fatal("body reached EOF with no credential check in the context")
	}
}

// Catches: a zero interval being treated as "check continuously" (ticker
// with 0 panics or spins) instead of disabling re-checking.
func TestStreamRecheckIntervalZeroDisablesChecking(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		setRecheckInterval(t, d)
		var calls atomic.Int64
		rs := openRecheckStream(t, func() bool { calls.Add(1); return false })
		if rs.handlerEnded(500 * time.Millisecond) {
			t.Fatalf("interval %v: stream ended although re-checking is disabled", d)
		}
		if got := calls.Load(); got != 0 {
			t.Errorf("interval %v: check called %d times, want 0", d, got)
		}
		rs.cancel()
		rs.handlerEnded(2 * time.Second)
	}
}

// Catches: the re-check loop outliving the request (leaked goroutine
// still calling the check after the client left).
func TestStreamRecheckStopsAfterClientDisconnect(t *testing.T) {
	setRecheckInterval(t, recheckTestInterval)
	var calls atomic.Int64
	rs := openRecheckStream(t, func() bool { calls.Add(1); return true })
	waitCalls(t, &calls, 2)

	rs.cancel()
	_, _ = io.Copy(io.Discard, rs.resp.Body)
	if !rs.handlerEnded(2 * time.Second) {
		t.Fatal("handler did not return after the client disconnected")
	}
	after := calls.Load()
	time.Sleep(10 * recheckTestInterval)
	if got := calls.Load(); got != after {
		t.Errorf("check called %d more times after the client disconnected", got-after)
	}
}
