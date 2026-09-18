package probe

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/selftest"
)

// listenTCP starts a TCP listener that accepts and immediately closes
// every connection, and returns its port. Good enough to prove a
// carrier can complete a write against a live socket without needing a
// real OpenCanary.
func listenTCP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port
}

// TestSweepWithConfig_ClassifiesEachTargetIndependently exercises every
// Status a sweep can produce in one run, over params.Targets in one
// call, proving neither one target's outcome nor its ordering leaks
// into another's -- the property cmd/birdcage-agent's logging and the
// eventual heartbeat counters both depend on.
func TestSweepWithConfig_ClassifiesEachTargetIndependently(t *testing.T) {
	livePort := listenTCP(t)

	params := selftest.Params{
		RunID:   "run-1",
		Address: "127.0.0.1",
		Targets: []selftest.Target{
			{Service: "ftp", DestPort: livePort, Marker: "m-ok"},
			{Service: "smb", DestPort: 1, Marker: "m-notprobeable"},
			{Service: "made-up-service", DestPort: 1, Marker: "m-nocarrier"},
			// Port 1 has nothing listening in this sandbox; dialing it
			// should be refused quickly rather than hang out to the
			// probe timeout.
			{Service: "ftp", DestPort: 1, Marker: "m-failed"},
		},
	}

	cfg := Config{ProbeTimeout: 2 * time.Second, SweepTimeout: 10 * time.Second, Concurrency: 2}
	outcomes := SweepWithConfig(context.Background(), params, cfg)

	if len(outcomes) != len(params.Targets) {
		t.Fatalf("got %d outcomes, want %d", len(outcomes), len(params.Targets))
	}

	want := []Status{StatusOK, StatusNotProbeable, StatusNoCarrier, StatusFailed}
	for i, w := range want {
		if outcomes[i].Status != w {
			t.Errorf("target %d (%s): got status %s, want %s (err=%v)",
				i, params.Targets[i].Service, outcomes[i].Status, w, outcomes[i].Err)
		}
	}
	if outcomes[3].Err == nil {
		t.Error("target 3: StatusFailed outcome carries a nil Err")
	}
	for i, o := range outcomes {
		if i == 3 {
			continue
		}
		if o.Err != nil {
			t.Errorf("target %d: non-failed outcome carries Err: %v", i, o.Err)
		}
	}
}

// TestSweepWithConfig_BoundsTheWholeRun proves a sweep never runs
// longer than its own SweepTimeout, even when every target would
// otherwise block for its full ProbeTimeout -- the house rule that a
// canary must never hang in a self-test.
func TestSweepWithConfig_BoundsTheWholeRun(t *testing.T) {
	// 10.255.255.1 is routable but answers nothing in CI/sandbox
	// networks, so the dial blocks until its context expires rather
	// than failing fast the way a refused local port does.
	params := selftest.Params{
		RunID:   "run-2",
		Address: "10.255.255.1",
		Targets: []selftest.Target{
			{Service: "ftp", DestPort: 21, Marker: "m1"},
			{Service: "ftp", DestPort: 21, Marker: "m2"},
		},
	}
	cfg := Config{ProbeTimeout: time.Hour, SweepTimeout: 500 * time.Millisecond, Concurrency: 2}

	start := time.Now()
	outcomes := SweepWithConfig(context.Background(), params, cfg)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("sweep took %s, want it bounded near its 500ms SweepTimeout", elapsed)
	}
	for i, o := range outcomes {
		if o.Status != StatusFailed {
			t.Errorf("target %d: got status %s, want StatusFailed once the sweep deadline lands", i, o.Status)
		}
	}
}
