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
