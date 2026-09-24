package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/scan"
)

// TestJitteredIntervalStaysInBound mirrors
// cmd/mockingbird/command_test.go's own test of the identical function.
func TestJitteredIntervalStaysInBound(t *testing.T) {
	base, jitter := commandPollInterval, commandPollJitter
	for i := 0; i < 200; i++ {
		got := jitteredInterval(base, jitter)
		if got < base-jitter || got > base+jitter {
			t.Fatalf("jitteredInterval() = %v, want within [%v, %v]", got, base-jitter, base+jitter)
		}
	}
	if got := jitteredInterval(base, 0); got != base {
		t.Fatalf("jitteredInterval(base, 0) = %v, want %v unchanged", got, base)
	}
}

// withFastPoll shrinks commandPollInterval/Jitter for the duration of a
// test, matching cmd/mockingbird/command_test.go's own pattern, so a
// poll loop test runs in milliseconds rather than minutes.
func withFastPoll(t *testing.T) {
	t.Helper()
	origInterval, origJitter := commandPollInterval, commandPollJitter
	commandPollInterval, commandPollJitter = 5*time.Millisecond, 0
	t.Cleanup(func() { commandPollInterval, commandPollJitter = origInterval, origJitter })
}

// TestRunCommandPollLoopClaimsScanAndIgnoresSelftest proves ADR-0012
// decision 2's own fail-closed rule: a `selftest` command (the kind
// Mockingbird handles, never Nightjar) is logged and skipped, never
// producing an order, while a `scan` command with a well-formed
// {"run_id": ...} body reaches the orders channel.
func TestRunCommandPollLoopClaimsScanAndIgnoresSelftest(t *testing.T) {
	withFastPoll(t)

	var n atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch n.Add(1) {
		case 1:
			_, _ = w.Write([]byte(`{"command":{"id":"cmd-1","kind":"selftest","params":{},"expires_at":"2099-01-01T00:00:00Z"}}`))
		case 2:
			_, _ = w.Write([]byte(`{"command":{"id":"cmd-2","kind":"scan","params":{"run_id":"run-1"},"expires_at":"2099-01-01T00:00:00Z"}}`))
		default:
			_, _ = w.Write([]byte(`{"command":null}`))
		}
	}))
	defer ts.Close()
	c := newTestClient(t, ts)
	orders := make(chan scanOrder, orderRunnerBuffer)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runCommandPollLoop(ctx, c, "tok", orders, time.Now)
		close(done)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("runCommandPollLoop did not return after context cancellation")
		}
	}()

	select {
	case order := <-orders:
		if order.runID != "run-1" || order.commandID != "cmd-2" {
			t.Errorf("order = %+v, want commandID cmd-2, runID run-1", order)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no order delivered within 2s")
	}

	// The selftest command must never have produced an order of its
	// own: with only one order sent by the server before it, the
	// channel must be empty after draining the one we just received.
	select {
	case extra := <-orders:
		t.Errorf("unexpected second order %+v -- the selftest command must never be executed", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

// TestRunCommandPollLoopDeclinesExpiredCommand proves the client-side
// expiry check: a `scan` command whose expires_at is already past now
// is declined -- never handed to the order runner -- even though
// ClaimNextCanaryCommand should never deliver one in the first place
// (defence in depth, this file's own doc comment).
func TestRunCommandPollLoopDeclinesExpiredCommand(t *testing.T) {
	withFastPoll(t)

	var polls atomic.Int32
	seenTwo := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"command":{"id":"cmd-1","kind":"scan","params":{"run_id":"run-1"},"expires_at":"2020-01-01T00:00:00Z"}}`))
		if polls.Add(1) == 2 {
			close(seenTwo)
		}
	}))
	defer ts.Close()
	c := newTestClient(t, ts)
	orders := make(chan scanOrder, orderRunnerBuffer)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runCommandPollLoop(ctx, c, "tok", orders, time.Now)
		close(done)
	}()

	select {
	case <-seenTwo:
	case <-time.After(2 * time.Second):
		t.Fatal("the poll loop never reached its second poll")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCommandPollLoop did not return after context cancellation")
	}

	select {
	case order := <-orders:
		t.Errorf("order %+v delivered, want the expired command declined", order)
	default:
	}
}

// TestRunCommandPollLoopUnreadableParamsDeclined proves a `scan`
// command whose params do not carry a run_id is declined rather than
// handed on with an empty one.
func TestRunCommandPollLoopUnreadableParamsDeclined(t *testing.T) {
	withFastPoll(t)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"command":{"id":"cmd-1","kind":"scan","params":{},"expires_at":"2099-01-01T00:00:00Z"}}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)
	orders := make(chan scanOrder, orderRunnerBuffer)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runCommandPollLoop(ctx, c, "tok", orders, time.Now)
		close(done)
	}()

	select {
	case order := <-orders:
		t.Errorf("order %+v delivered, want params without run_id declined", order)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCommandPollLoop did not return after context cancellation")
	}
}

// gateFree non-blockingly checks whether gate is currently free,
// releasing it again immediately if so -- a test-only probe, never used
// by production code, which always blocks on acquire.
func gateFree(gate scanGate) bool {
	select {
	case tok := <-gate:
		gate <- tok
		return true
	default:
		return false
	}
}

// TestScanGateSerialisesAcquirers proves ADR-0012 decision 2: a second
// acquirer blocks until the first releases -- the primitive
// runScanLoop and runOrderRunner both share to keep a timer scan and an
// ordered scan from ever running at once.
func TestScanGateSerialisesAcquirers(t *testing.T) {
	gate := newScanGate()
	if !gate.acquire(context.Background()) {
		t.Fatal("first acquire failed")
	}

	acquired := make(chan struct{})
	go func() {
		gate.acquire(context.Background())
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("second acquire succeeded while the gate was still held")
	case <-time.After(50 * time.Millisecond):
	}

	gate.release()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("second acquire never succeeded after release")
	}
}

// TestScanGateAcquireRespectsContext proves acquire returns false rather
// than blocking forever once ctx is done -- what lets runOrderRunner
// stop promptly at shutdown even mid-wait.
func TestScanGateAcquireRespectsContext(t *testing.T) {
	gate := newScanGate()
	gate.acquire(context.Background()) // hold it

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if gate.acquire(ctx) {
		t.Fatal("acquire succeeded against an already-cancelled context")
	}
}

// TestRunOrderRunnerRunsScanAndCarriesRunID drives runOrderRunner end to
// end against a fake ingest server: an order on the channel results in
// exactly one posted snapshot carrying that run_id.
func TestRunOrderRunnerRunsScanAndCarriesRunID(t *testing.T) {
	var gotBody map[string]any
	posted := make(chan struct{})
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ingest/scans":
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusOK)
			close(posted)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	deps, _ := testDeps(fixedNow(time.Now()), func() error { return nil }, func(context.Context) (scan.Result, error) {
		return scan.Result{Status: scan.StatusOK}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orders := make(chan scanOrder, 1)
	gate := newScanGate()

	done := make(chan struct{})
	go func() {
		runOrderRunner(ctx, deps, gate, c, "tok", commandLog, orders)
		close(done)
	}()

	orders <- scanOrder{commandID: "cmd-1", runID: "run-77"}

	select {
	case <-posted:
	case <-time.After(2 * time.Second):
		t.Fatal("no snapshot posted within 2s")
	}
	if gotBody["run_id"] != "run-77" {
		t.Errorf("run_id = %v, want run-77", gotBody["run_id"])
	}

	// The server has received the request, but the client's own
	// SendScan call may not have finished reading the response yet --
	// wait for runOrderRunner to release the gate (its own cycle-done
	// signal) before cancelling ctx, or SendScan itself can race and
	// report a spurious "context canceled" (its request shares ctx with
	// the loop's own lifecycle, exactly as production does).
	deadline := time.After(2 * time.Second)
	for !gateFree(gate) {
		select {
		case <-deadline:
			t.Fatal("scan cycle never released the gate")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runOrderRunner did not return after context cancellation")
	}
}

// TestNewStageReporterSendsRunAndDBRefresh proves the reportStage
// closure run() wires up sends a heartbeat carrying both the run's
// stage and, while the database refresh is failing, the db_refresh
// object on the same request.
func TestNewStageReporterSendsRunAndDBRefresh(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	tracker := newDBRefreshTracker(t.TempDir(), dbRefreshStatus{FailingSince: time.Now(), LastError: "down"})
	runTracker := newCurrentRunTracker()
	reportStage := newStageReporter(c, "tok", "v1", tracker, runTracker, commandLog)

	reportStage(context.Background(), "run-1", stageMountsChecked)

	run, _ := gotBody["run"].(map[string]any)
	if run == nil || run["run_id"] != "run-1" || run["stage"] != stageMountsChecked {
		t.Errorf("run = %v, want run-1/%s", run, stageMountsChecked)
	}
	if _, present := gotBody["db_refresh"]; !present {
		t.Error("db_refresh missing from the stage report while the refresh is failing")
	}
	if gotRunID, gotStage := runTracker.get(); gotRunID != "run-1" || gotStage != stageMountsChecked {
		t.Errorf("runTracker = (%q, %q), want (run-1, %s)", gotRunID, gotStage, stageMountsChecked)
	}
}

// TestOrderedAndTimerScansNeverOverlap drives runScanLoop (timer) and
// runOrderRunner (ordered) concurrently, sharing one scanGate, against a
// runScan stub that records whether it is ever entered while another
// call is still in flight -- ADR-0012 decision 2's own core guarantee,
// proven directly rather than inferred from the gate's own unit tests.
func TestOrderedAndTimerScansNeverOverlap(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	var inFlight atomic.Int32
	var overlapped atomic.Bool
	runScan := func(context.Context) (scan.Result, error) {
		if inFlight.Add(1) > 1 {
			overlapped.Store(true)
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		return scan.Result{Status: scan.StatusOK}, nil
	}

	deps, _ := testDeps(fixedNow(time.Now()), func() error { return nil }, runScan)
	gate := newScanGate()
	orders := make(chan scanOrder, orderRunnerBuffer)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		runScanLoop(ctx, c, "tok", deps, gate, 2*time.Millisecond, commandLog)
	}()
	go func() {
		defer wg.Done()
		runOrderRunner(ctx, deps, gate, c, "tok", commandLog, orders)
	}()

	for i := 0; i < 20; i++ {
		select {
		case orders <- scanOrder{commandID: "cmd", runID: "run"}:
		default:
		}
		time.Sleep(time.Millisecond)
	}

	cancel()
	wg.Wait()

	if overlapped.Load() {
		t.Error("a timer scan and an ordered scan ran concurrently -- ADR-0012 decision 2 requires they never overlap")
	}
}
