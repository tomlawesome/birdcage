package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// captureLogger is a *slog.Logger whose output can be asserted on,
// unlike discardLogger (portscan_test.go), which throws it away. Text
// output, not JSON: readiness's own WARN lines are meant for a human
// reading `docker logs`, and this test checks the words in them.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// writeConf writes an opencanary.conf fixture enabling exactly the given
// module/port pairs, in the same flat "<module>.<setting>" shape the real
// file uses.
func writeConf(t *testing.T, modules map[string]int) string {
	t.Helper()
	fields := map[string]any{}
	for module, port := range modules {
		fields[module+".enabled"] = true
		fields[module+".port"] = port
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal fixture conf: %v", err)
	}
	path := filepath.Join(t.TempDir(), "opencanary.conf")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write fixture conf: %v", err)
	}
	return path
}

// listenAndAccept opens a real loopback listener standing in for a
// module that started, accepting (and closing) whatever connects.
func listenAndAccept(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
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
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	return port
}

// closedLoopbackPort returns a port nothing is listening on, standing in
// for a module that opencanary.conf enables but that failed to start --
// #65's exact scenario, reproduced with the https module against a real
// container on 2026-09-22 (see internal/agent/readiness's doc comment).
func closedLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	_ = ln.Close()
	return port
}

func fastReadinessConfig(confPath string) readinessConfig {
	return readinessConfig{
		ConfPath:    confPath,
		Host:        "127.0.0.1",
		Window:      300 * time.Millisecond,
		PollEvery:   50 * time.Millisecond,
		DialTimeout: 100 * time.Millisecond,
	}
}

// TestRunReadinessCheckWarnsOnAModuleThatNeverStarted is #65's
// reproduction, at the unit level: a module opencanary.conf enables but
// that never accepts a connection -- exactly what was observed for the
// https module in a real container, and what OpenCanary's own log does
// not distinguish from a module that started cleanly (both log through
// the same helper, at the same logtype). Before this check existed,
// nothing in this binary noticed; this test fails against that absence.
func TestRunReadinessCheckWarnsOnAModuleThatNeverStarted(t *testing.T) {
	t.Parallel()

	up := listenAndAccept(t)
	down := closedLoopbackPort(t)
	conf := writeConf(t, map[string]int{"ftp": up, "https": down})

	log, buf := captureLogger()
	runReadinessCheck(context.Background(), fastReadinessConfig(conf), log)

	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "module") || !strings.Contains(out, "https") {
		t.Errorf("expected a WARN naming module https, got log:\n%s", out)
	}
	if !strings.Contains(out, "port "+strconv.Itoa(down)) {
		t.Errorf("expected the WARN to name port %d, got log:\n%s", down, out)
	}
	if strings.Contains(out, "ftp") {
		t.Errorf("ftp actually answered; it must not be named anywhere in the log, got log:\n%s", out)
	}
}

// TestRunReadinessCheckIsQuietWhenEverythingAnswers proves the check does
// not cry wolf on a healthy canary -- the same shape of false positive
// #48's own tailer intake gate and portscan's ignore-list both take pains
// to avoid.
func TestRunReadinessCheckIsQuietWhenEverythingAnswers(t *testing.T) {
	t.Parallel()

	a := listenAndAccept(t)
	b := listenAndAccept(t)
	conf := writeConf(t, map[string]int{"ftp": a, "ssh": b})

	log, buf := captureLogger()
	runReadinessCheck(context.Background(), fastReadinessConfig(conf), log)

	if out := buf.String(); strings.Contains(out, "level=WARN") {
		t.Errorf("expected no WARN when every enabled module answered, got log:\n%s", out)
	}
}

// TestRunReadinessCheckLogsReadyWhenEverythingAnswers is issue #47 step
// 7's required test: the agent's own "I believe I am ready" signal is an
// INFO line naming #47, present only when every enabled module answered.
func TestRunReadinessCheckLogsReadyWhenEverythingAnswers(t *testing.T) {
	t.Parallel()

	a := listenAndAccept(t)
	conf := writeConf(t, map[string]int{"ftp": a})

	log, buf := captureLogger()
	runReadinessCheck(context.Background(), fastReadinessConfig(conf), log)

	out := buf.String()
	if !strings.Contains(out, "level=INFO") || !strings.Contains(out, "believes it is ready") {
		t.Errorf("expected an INFO line saying the agent believes it is ready, got log:\n%s", out)
	}
}

// TestRunReadinessCheckDoesNotLogReadyWhenSomethingFailed proves the
// ready signal is all-or-nothing: a canary with one module down never
// claims readiness alongside the WARN naming it.
func TestRunReadinessCheckDoesNotLogReadyWhenSomethingFailed(t *testing.T) {
	t.Parallel()

	up := listenAndAccept(t)
	down := closedLoopbackPort(t)
	conf := writeConf(t, map[string]int{"ftp": up, "https": down})

	log, buf := captureLogger()
	runReadinessCheck(context.Background(), fastReadinessConfig(conf), log)

	if out := buf.String(); strings.Contains(out, "believes it is ready") {
		t.Errorf("expected no readiness claim with a module down, got log:\n%s", out)
	}
}

// TestRunReadinessCheckSurvivesAnUnreadableConf: a missing or unreadable
// configuration must not panic or hang this road -- the same fail-soft
// contract newPortscanRoad and newSNMPRoad both already have with a
// config problem: report and carry on.
func TestRunReadinessCheckSurvivesAnUnreadableConf(t *testing.T) {
	t.Parallel()

	log, buf := captureLogger()
	runReadinessCheck(context.Background(), fastReadinessConfig(filepath.Join(t.TempDir(), "absent.conf")), log)

	if out := buf.String(); !strings.Contains(out, "level=WARN") {
		t.Errorf("expected a WARN about the unreadable config, got log:\n%s", out)
	}
}

// TestOpenCanaryProbeReportsUpWhenEverythingAnswers is issue #132's own
// reproduction of what replaces #69: with OpenCanary no longer this
// agent's own child process, nothing tells the agent it died except this
// probe. Before it existed there was no way for a heartbeat to say
// anything about OpenCanary's liveness at all; this test fails against
// that absence (Probe returning nil, not a true *bool).
func TestOpenCanaryProbeReportsUpWhenEverythingAnswers(t *testing.T) {
	t.Parallel()

	a := listenAndAccept(t)
	b := listenAndAccept(t)
	conf := writeConf(t, map[string]int{"ftp": a, "ssh": b})

	log, _ := captureLogger()
	probe := newOpenCanaryProbe(fastReadinessConfig(conf), log)
	got := probe.Probe(context.Background())
	if got == nil || !*got {
		t.Fatalf("Probe() = %v, want a true *bool", got)
	}
}

// TestOpenCanaryProbeReportsDownWhenAModuleDoesNotAnswer is the state
// #132's own health state (StateOpenCanaryDown) is built on: one
// configured module not answering is enough to call OpenCanary down,
// the same all-or-nothing rule the boot-time readiness check uses for
// its own "believes it is ready" line.
func TestOpenCanaryProbeReportsDownWhenAModuleDoesNotAnswer(t *testing.T) {
	t.Parallel()

	up := listenAndAccept(t)
	down := closedLoopbackPort(t)
	conf := writeConf(t, map[string]int{"ftp": up, "https": down})

	log, buf := captureLogger()
	probe := newOpenCanaryProbe(fastReadinessConfig(conf), log)
	got := probe.Probe(context.Background())
	if got == nil || *got {
		t.Fatalf("Probe() = %v, want a false *bool", got)
	}
	if out := buf.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "https") {
		t.Errorf("expected a WARN naming https on the first down probe, got log:\n%s", out)
	}
}

// TestOpenCanaryProbeLogsOnlyOnTransition proves the WARN fires once per
// failure, not once per heartbeat -- a canary stuck reporting
// opencanary_down for hours must not also flood its own container log
// once per tick.
func TestOpenCanaryProbeLogsOnlyOnTransition(t *testing.T) {
	t.Parallel()

	down := closedLoopbackPort(t)
	conf := writeConf(t, map[string]int{"https": down})

	log, buf := captureLogger()
	probe := newOpenCanaryProbe(fastReadinessConfig(conf), log)
	probe.Probe(context.Background())
	firstLen := buf.Len()
	probe.Probe(context.Background())
	if buf.Len() != firstLen {
		t.Errorf("a second consecutive down probe logged more output; got:\n%s", buf.String())
	}
}

// TestOpenCanaryProbeReportsNoOpinionWithNoPorts matches
// TestRunReadinessCheckSurvivesAnUnreadableConf's own contract: an
// unreadable or empty configuration is "no opinion", never a false
// claiming OpenCanary is down -- that distinction is exactly what keeps
// canaries.agent_opencanary_up NULL instead of wrongly raising
// StateOpenCanaryDown (internal/store/health.go's openCanaryDown).
func TestOpenCanaryProbeReportsNoOpinionWithNoPorts(t *testing.T) {
	t.Parallel()

	log, _ := captureLogger()
	probe := newOpenCanaryProbe(fastReadinessConfig(filepath.Join(t.TempDir(), "absent.conf")), log)
	if got := probe.Probe(context.Background()); got != nil {
		t.Errorf("Probe() = %v, want nil (no opinion)", *got)
	}
}

// TestOpenCanaryProbeIgnoresUDPOnlyModules is issue #132's own
// reproduction of a real false alarm: internal/agent/readiness.Dial only
// ever dials "tcp" (its own doc comment), so a UDP-only module like sip
// or tftp always looks down to a TCP probe, whether or not OpenCanary is
// actually running. Reproduced directly (2026-09-26) against the real
// image: with sip and tftp counted, every heartbeat reported OpenCanary
// down permanently. This test fails without udpOnlyModules' exclusion --
// every TCP module answering, with sip and tftp both configured and
// silent, must still read up.
func TestOpenCanaryProbeIgnoresUDPOnlyModules(t *testing.T) {
	t.Parallel()

	up := listenAndAccept(t)
	sipPort := closedLoopbackPort(t)
	tftpPort := closedLoopbackPort(t)
	conf := writeConf(t, map[string]int{"ftp": up, "sip": sipPort, "tftp": tftpPort})

	log, buf := captureLogger()
	probe := newOpenCanaryProbe(fastReadinessConfig(conf), log)
	got := probe.Probe(context.Background())
	if got == nil || !*got {
		t.Fatalf("Probe() = %v, want a true *bool -- sip/tftp not answering over TCP must not count against it", got)
	}
	if out := buf.String(); strings.Contains(out, "level=WARN") {
		t.Errorf("expected no WARN with only UDP-only modules silent, got log:\n%s", out)
	}
}

// TestDefaultReadinessConfigMatchesShippedDefaults pins the values #65's
// own doc comment on defaultReadinessConfig documents -- a 10s window,
// a 250ms poll, a 500ms dial timeout and 127.0.0.1 -- so a change to any
// of them is a deliberate edit to this test, not a silent behavior
// change nothing catches. ConfPath is read from envOpenCanaryConf,
// unset here, matching a real boot before any override.
func TestDefaultReadinessConfigMatchesShippedDefaults(t *testing.T) {
	t.Setenv(envOpenCanaryConf, "")

	got := defaultReadinessConfig()
	want := readinessConfig{
		ConfPath:    "",
		Host:        "127.0.0.1",
		Window:      10 * time.Second,
		PollEvery:   250 * time.Millisecond,
		DialTimeout: 500 * time.Millisecond,
	}
	if got != want {
		t.Errorf("defaultReadinessConfig() = %+v, want %+v", got, want)
	}
}
