package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/store"
)

func TestAgentSettingsShowNoneYet(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	insertTestCanary(t, database, "canary-settings-test")

	out, err := captureStdout(t, func() error { return runAgentSettingsShow([]string{"canary-settings-test"}) })
	if err != nil {
		t.Fatalf("runAgentSettingsShow: %v", err)
	}
	if !strings.Contains(out, "no settings pushed") {
		t.Fatalf("output = %q, want it to say no settings have been pushed", out)
	}
}

func TestAgentSettingsShowUnknownAgent(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	if _, err := captureStdout(t, func() error { return runAgentSettingsShow([]string{"does-not-exist"}) }); err == nil {
		t.Fatal("runAgentSettingsShow(unknown agent) returned no error")
	}
}

// TestAgentSettingsSetThenShowRoundTrips proves the CLI write path end to
// end: set stores the value (via store.SetCanarySettings), and show reads
// it back with version and confirmed=false (no agent has ever reported a
// matching hash).
func TestAgentSettingsSetThenShowRoundTrips(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	insertTestCanary(t, database, "canary-settings-test")

	setOut, err := captureStdout(t, func() error {
		return runAgentSettingsSet([]string{"canary-settings-test", "segment_profile=off"})
	})
	if err != nil {
		t.Fatalf("runAgentSettingsSet: %v", err)
	}
	if !strings.Contains(setOut, "segment_profile=off") {
		t.Fatalf("set output = %q, want it to echo segment_profile=off", setOut)
	}

	showOut, err := captureStdout(t, func() error { return runAgentSettingsShow([]string{"canary-settings-test"}) })
	if err != nil {
		t.Fatalf("runAgentSettingsShow: %v", err)
	}
	if !strings.Contains(showOut, "segment_profile=off") || !strings.Contains(showOut, "version=1") || !strings.Contains(showOut, "confirmed=false") {
		t.Fatalf("show output = %q, want segment_profile=off, version=1, confirmed=false", showOut)
	}
}

// TestAgentSettingsSetMultipleKeysAtomically proves a batch of key=value
// pairs writes in one call, and that a bad key in the batch stores
// nothing at all -- store.SetCanarySettings' own atomicity, exercised
// through the CLI.
func TestAgentSettingsSetMultipleKeysAtomically(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	insertTestCanary(t, database, "canary-settings-test")

	if err := runAgentSettingsSet([]string{"canary-settings-test", "segment_profile=linux", "pace_floor=2h"}); err != nil {
		t.Fatalf("runAgentSettingsSet: %v", err)
	}
	settings, err := store.ListCanarySettings(context.Background(), database, "canary-settings-test")
	if err != nil {
		t.Fatalf("ListCanarySettings: %v", err)
	}
	if len(settings) != 2 {
		t.Fatalf("ListCanarySettings = %+v, want 2 rows", settings)
	}

	err = runAgentSettingsSet([]string{"canary-settings-test", "segment_profile=windows", "not_a_real_key=x"})
	if err == nil {
		t.Fatal("runAgentSettingsSet with an unknown key returned no error")
	}
	settings, err = store.ListCanarySettings(context.Background(), database, "canary-settings-test")
	if err != nil {
		t.Fatalf("ListCanarySettings: %v", err)
	}
	if len(settings) != 2 {
		t.Fatalf("a rejected batch changed stored settings: %+v", settings)
	}
	for _, s := range settings {
		if s.Key == store.CanarySettingSegmentProfile && s.Value != "linux" {
			t.Fatalf("segment_profile = %q after a rejected batch, want it unchanged (linux)", s.Value)
		}
	}
}

func TestAgentSettingsSetRejectsMalformedPair(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	insertTestCanary(t, database, "canary-settings-test")

	if err := runAgentSettingsSet([]string{"canary-settings-test", "not-a-pair"}); err == nil {
		t.Fatal("runAgentSettingsSet with a pair missing '=' returned no error")
	}
}

func TestAgentSettingsSetUnknownAgent(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	if err := runAgentSettingsSet([]string{"does-not-exist", "segment_profile=off"}); err == nil {
		t.Fatal("runAgentSettingsSet(unknown agent) returned no error")
	}
}

// TestAgentSettingsSetRecordsAuditEntry mirrors
// TestCanaryMintAndRevokeRecordAuditEntries's own shape for this write
// path: one canary_settings.updated entry, triggered_by "cli", naming the
// key but never the value.
func TestAgentSettingsSetRecordsAuditEntry(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	insertTestCanary(t, database, "canary-settings-test")

	secretName := "secret-fs-01"
	if err := runAgentSettingsSet([]string{"canary-settings-test", "bait_names=" + secretName}); err != nil {
		t.Fatalf("runAgentSettingsSet: %v", err)
	}

	var action, target, reason, triggeredBy string
	row := database.QueryRow(`SELECT action, target, reason, triggered_by FROM audit_log ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&action, &target, &reason, &triggeredBy); err != nil {
		t.Fatalf("scan audit row: %v", err)
	}
	if action != "canary_settings.updated" || target != "canary-settings-test" || triggeredBy != "cli" {
		t.Errorf("audit entry = (%q, %q, %q), unexpected", action, target, triggeredBy)
	}
	if !strings.Contains(reason, "bait_names") {
		t.Errorf("audit reason %q does not name the changed key", reason)
	}
	if strings.Contains(reason, secretName) {
		t.Fatalf("audit reason %q leaks the bait name", reason)
	}
}

// TestAgentSettingsKindMismatchIsRefused proves segment_profile
// (honeypot-only) is refused for a scanner via the CLI, the same "only
// the honeypot has lures" rule cmd/birdcage/canary.go's own enrol command
// applies to --lure.
func TestAgentSettingsKindMismatchIsRefused(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	if err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: "scanner-settings-test", Name: "scanner-settings-test", Lane: "lan", Kind: agentkind.Scanner,
		HeartbeatIntervalS: store.DefaultHeartbeatIntervalS, EnrolledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("InsertCanary: %v", err)
	}

	if err := runAgentSettingsSet([]string{"scanner-settings-test", "segment_profile=windows"}); err == nil {
		t.Fatal("runAgentSettingsSet(segment_profile on a scanner) returned no error")
	}
}
