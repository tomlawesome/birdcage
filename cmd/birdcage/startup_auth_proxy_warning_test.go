package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// Issue #210 item 2: start-up says so when no trusted proxy is named and
// every visitor will therefore share one sign-in limit and audit address.
// The tests call loadAuthConfig with the proposed extra parameter
// onUnixSocket (true when the dashboard listens on a unix socket); with it
// false and offBoxAddr empty the listener is loopback TCP.

// proxyLines returns the log lines that name BIRDCAGE_TRUSTED_PROXIES and
// say visitors "share" something.
func proxyLines(t *testing.T, env map[string]string, onUnixSocket bool, offBoxAddr string) []string {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	e := map[string]string{testEnvAuthKeyFile: writeKeyFile(t, 32)}
	for k, v := range env {
		e[k] = v
	}
	if _, err := loadAuthConfig(envMap(e), t.TempDir(), false, offBoxAddr, onUnixSocket, log); err != nil {
		t.Fatalf("loadAuthConfig: %v", err)
	}
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "BIRDCAGE_TRUSTED_PROXIES") && strings.Contains(line, "share") {
			out = append(out, line)
		}
	}
	return out
}

func TestUnixSocketWithoutTrustedProxiesWarnsOnce(t *testing.T) {
	lines := proxyLines(t, nil, true, "")
	if len(lines) != 1 {
		t.Fatalf("lines naming BIRDCAGE_TRUSTED_PROXIES and \"share\" = %d (%q), want exactly 1", len(lines), lines)
	}
	if !strings.Contains(lines[0], "level=WARN") {
		t.Errorf("line = %q, want warn level", lines[0])
	}
}

func TestLoopbackTCPWithoutTrustedProxiesLogsInfoNotWarn(t *testing.T) {
	lines := proxyLines(t, nil, false, "")
	if len(lines) != 1 {
		t.Fatalf("lines naming BIRDCAGE_TRUSTED_PROXIES and \"share\" = %d (%q), want exactly 1", len(lines), lines)
	}
	if !strings.Contains(lines[0], "level=INFO") || strings.Contains(lines[0], "level=WARN") {
		t.Errorf("line = %q, want info level, not warn", lines[0])
	}
}

func TestTrustedProxiesSetLogsNoSharedLimitLine(t *testing.T) {
	for _, onUnix := range []bool{true, false} {
		lines := proxyLines(t, map[string]string{"BIRDCAGE_TRUSTED_PROXIES": "unix"}, onUnix, "")
		if len(lines) != 0 {
			t.Errorf("onUnixSocket=%v with BIRDCAGE_TRUSTED_PROXIES set: got %q, want no sharing line", onUnix, lines)
		}
	}
}

func TestNonLoopbackTCPWithoutTrustedProxiesLogsNoSharedLimitLine(t *testing.T) {
	lines := proxyLines(t, nil, false, "198.51.100.7:8443")
	if len(lines) != 0 {
		t.Errorf("non-loopback TCP, setting empty: got %q, want no sharing line", lines)
	}
}
