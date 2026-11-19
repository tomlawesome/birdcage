package auth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/auth"
)

// Issue #210 item 3: the setup and unlock codes reach the log only once
// every start-up step that can refuse has passed. The seam is
// (*auth.Service).ReleaseCodes(), called by main after the last refusable
// step; auth.Open no longer releases the codes itself.

func openHeld(t *testing.T) (*auth.Service, *logCapture) {
	t.Helper()
	log, capture := newLogCapture()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	svc, err := auth.Open(ctx, openDatabase(t), auth.Config{Key: testKey('a')}, log)
	if err != nil {
		t.Fatalf("auth.Open: %v", err)
	}
	return svc, capture
}

func TestOpenDoesNotLogSetupCodeUntilReleased(t *testing.T) {
	svc, capture := openHeld(t)
	defer svc.Close()
	if codes := capture.setupCodes(); len(codes) != 0 {
		t.Fatalf("setup codes logged by Open before ReleaseCodes = %v, want none", codes)
	}
	svc.ReleaseCodes()
	if codes := capture.setupCodes(); len(codes) != 1 {
		t.Errorf("setup codes logged after ReleaseCodes = %v, want exactly one", codes)
	}
}

// A refused start closes the handle without releasing: no code is logged.
func TestCloseWithoutReleaseLogsNoCode(t *testing.T) {
	svc, capture := openHeld(t)
	svc.Close()
	for _, line := range capture.all() {
		if strings.Contains(strings.ToLower(line), "setup code") {
			t.Errorf("log line after Close without ReleaseCodes mentions a setup code: %q", line)
		}
	}
}
