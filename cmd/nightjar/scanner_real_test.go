package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/scan"
)

// TestCheckMountsRefusesWithoutHostBind proves the real checkMounts --
// the function that runs in production, not the injected stand-in
// buildSnapshot's other tests use -- refuses to let a scan proceed when
// this process's own mount table has no /host mount at all. That is
// exactly the state any test environment (and any container that had
// `-v /:/host:ro` dropped from its run command) is in, so this is a
// deterministic security-refusal test, not a flaky one: checkMounts
// reads the real /proc/self/mountinfo (mountinfoPath is a fixed
// constant, never overridden for tests -- there is no seam to inject a
// fixture path without adding one, which the brief for this package
// forbids) and hostRoot is the fixed "/host" constant, so the only two
// external facts this depends on -- this process's real mount table,
// and whether "/host" happens to be mounted -- are both stable in CI
// and on a workstation alike.
func TestCheckMountsRefusesWithoutHostBind(t *testing.T) {
	err := checkMounts()
	if err == nil {
		t.Fatal("checkMounts() = nil, want a refusal: this test process has no /host mount")
	}
	if !strings.Contains(err.Error(), "/host") {
		t.Errorf("checkMounts() error = %q, want it to name /host", err.Error())
	}
	if !strings.Contains(err.Error(), "not mounted") {
		t.Errorf("checkMounts() error = %q, want the root-missing reason (no /host mount at all)", err.Error())
	}
}

// TestRealScanFailsWithoutGrypeBinary proves the real runScan argument
// -- realScan, wired to the pinned grypeBin/hostRoot constants -- comes
// back as a failed scan.Result rather than a Go error or a panic when
// the grype binary is not present at its pinned path. grypeBin
// ("/usr/local/bin/grype") is a fixed constant with no env-var override
// (same constraint as hostRoot above), so this exercises the real
// subprocess-invocation path end to end: no test environment ships
// grype at that exact path, matching production's own contract that a
// missing/misconfigured binary must fail closed (ADR-0010 decision 8),
// never silently report a clean scan.
func TestRealScanFailsWithoutGrypeBinary(t *testing.T) {
	result, err := realScan(context.Background())
	if err != nil {
		t.Fatalf("realScan() error = %v, want nil (scan.Run only errors on an already-canceled context)", err)
	}
	if result.Status != scan.StatusFailed {
		t.Errorf("Status = %q, want %q", result.Status, scan.StatusFailed)
	}
	if result.Reason == "" {
		t.Error("Reason is empty on a failed scan")
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0 on a failed scan", len(result.Findings))
	}
}

// TestRunScanOnceMountFailurePostsFailedSnapshot drives runScanOnce
// itself (not buildSnapshot, which the other tests in this package
// already cover) against a real TLS test server, proving the whole
// wire-up -- checkMounts's failure reaching SendScan's request body --
// works end to end, and that runScan is never invoked when the mount
// check refuses.
func TestRunScanOnceMountFailurePostsFailedSnapshot(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ingest/scans" {
			t.Errorf("path = %q, want /ingest/scans", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	scanCalled := false
	checkMounts := func() error { return errors.New("hostmask: /host is not mounted at all") }
	runScan := func(context.Context) (scan.Result, error) {
		scanCalled = true
		return scan.Result{}, nil
	}

	deps, _ := testDeps(fixedNow(time.Now()), checkMounts, runScan)
	runScanOnce(context.Background(), c, "tok", deps, slog.New(slog.DiscardHandler), "")

	if scanCalled {
		t.Error("runScan was called despite a failed mount check")
	}
	if gotBody == nil {
		t.Fatal("server never received a request")
	}
	if gotBody["status"] != "failed" {
		t.Errorf("status = %v, want \"failed\"", gotBody["status"])
	}
	if gotBody["reason"] == "" || gotBody["reason"] == nil {
		t.Error("reason is empty on a failed snapshot")
	}
}

// TestRunScanOncePostsOKSnapshot is the same wiring's happy path: a
// clean mount check and a successful runScan reach the server as an
// "ok" snapshot carrying the findings runScan produced.
func TestRunScanOncePostsOKSnapshot(t *testing.T) {
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) {
		return scan.Result{
			Status: scan.StatusOK,
			Engine: scan.Engine{Name: "grype", Version: "0.119.0"},
			Findings: []scan.Finding{
				{Target: "dir:/host", Package: "openssl", Vulnerability: "CVE-2014-0160", Severity: "critical"},
			},
		}, nil
	}

	deps, _ := testDeps(fixedNow(time.Now()), checkMounts, runScan)
	runScanOnce(context.Background(), c, "tok", deps, slog.New(slog.DiscardHandler), "")

	if gotBody == nil {
		t.Fatal("server never received a request")
	}
	if gotBody["status"] != "ok" {
		t.Errorf("status = %v, want \"ok\"", gotBody["status"])
	}
	findings, _ := gotBody["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
}

// TestRunScanOnceLogsWarnOnSendFailure proves runScanOnce's own error
// path: when the server refuses the post (a 500, in this case), the
// function logs a warning and returns rather than panicking or retrying
// forever -- retry cadence belongs to the next scan cycle, not to this
// function.
func TestRunScanOnceLogsWarnOnSendFailure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	checkMounts := func() error { return nil }
	runScan := func(context.Context) (scan.Result, error) {
		return scan.Result{Status: scan.StatusOK}, nil
	}

	done := make(chan struct{})
	go func() {
		deps, _ := testDeps(fixedNow(time.Now()), checkMounts, runScan)
		runScanOnce(context.Background(), c, "tok", deps, slog.New(slog.DiscardHandler), "")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runScanOnce did not return after a failed send")
	}
}

// TestRunScanLoopRunsAndStops proves runScanLoop -- the goroutine main()
// starts, wired to the real checkMounts/realScan -- runs at least one
// cycle promptly and stops promptly on cancellation, the same cadence
// contract TestRunLoopRunsImmediatelyThenStops proves for runLoop alone,
// but through the real production wiring this time (checkMounts will
// refuse, same as TestCheckMountsRefusesWithoutHostBind, so the request
// that reaches the server is a failed snapshot -- still a real request,
// proving the whole loop is reachable and terminates).
func TestRunScanLoopRunsAndStops(t *testing.T) {
	var requests atomic.Int32
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		deps, _ := testDeps(fixedNow(time.Now()), checkMounts, realScan)
		runScanLoop(ctx, c, "tok", deps, newScanGate(), time.Hour, slog.New(slog.DiscardHandler))
		close(done)
	}()

	// The first cycle runs immediately; give it a moment to land before
	// cancelling -- an hour-long interval means only cancellation could
	// otherwise end the loop.
	deadline := time.After(2 * time.Second)
	for requests.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("runScanLoop never posted a request")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runScanLoop did not stop promptly after cancel")
	}
}
