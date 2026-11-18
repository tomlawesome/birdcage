package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #214: every command-line path that loads the CA applies the same
// continuity check as server start-up (checkStartupCAContinuity) before it
// loads, and refuses with the same wording. These tests drive the two CLI
// entry points, `agent enrol` and `agent upgrade-command`.

// assertCANotMinted fails if the CA folder gained any content.
func assertCANotMinted(t *testing.T, caDir string) {
	t.Helper()
	entries, err := os.ReadDir(caDir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read %s: %v", caDir, err)
	}
	if len(entries) != 0 {
		t.Errorf("CA folder %s was written to (%d entries), want it left empty or absent", caDir, len(entries))
	}
}

func assertCAResetWording(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("command succeeded with a missing CA and an issued client certificate, want a refusal")
	}
	for _, want := range []string{"birdcage ca reset", "restored from backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err.Error(), want)
		}
	}
}

// enrolDBWithCert prepares the database runCanaryEnrol opens, optionally
// with one issued client certificate.
func enrolDBWithCert(t *testing.T, withCert bool) {
	t.Helper()
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	now := time.Now().UTC()
	ctx := context.Background()
	if err := store.SetSetting(ctx, database, store.SettingAdminApprovalAddress, "admin@example.net", now); err != nil {
		t.Fatalf("set admin_approval_address: %v", err)
	}
	if err := store.SetSetting(ctx, database, store.SettingReleaseAddress, "release@example.net", now); err != nil {
		t.Fatalf("set release_address: %v", err)
	}
	if withCert {
		insertTestCanary(t, database, "canary-214")
		insertTestClientCert(t, database, "canary-214")
	}
}

func TestCanaryEnrolRefusesToMintCAWhenCertsIssued(t *testing.T) {
	enrolDBWithCert(t, true)
	t.Setenv(envAdvertiseHost, "203.0.113.10")
	caDir := filepath.Join(t.TempDir(), "ca")
	t.Setenv(envCADir, caDir)

	_, err := captureStdout(t, func() error {
		return runCanaryEnrol([]string{"--name", "scanner-1", "--lane", "front-door", "--kind", "scanner"})
	})
	assertCAResetWording(t, err)
	assertCANotMinted(t, caDir)
}

func TestCanaryEnrolFreshInstallStillMintsCA(t *testing.T) {
	enrolDBWithCert(t, false)
	t.Setenv(envAdvertiseHost, "203.0.113.10")
	caDir := filepath.Join(t.TempDir(), "ca")
	t.Setenv(envCADir, caDir)

	out, err := captureStdout(t, func() error {
		return runCanaryEnrol([]string{"--name", "scanner-1", "--lane", "front-door", "--kind", "scanner"})
	})
	if err != nil {
		t.Fatalf("runCanaryEnrol on a fresh install: %v", err)
	}
	if !strings.Contains(out, "docker run -d --name nightjar") {
		t.Errorf("output lacks the run command:\n%s", out)
	}
	if missing, _ := caMissingForTest(caDir); missing != "" {
		t.Errorf("fresh install did not create a CA: %s", missing)
	}
}

func TestAgentUpgradeCommandRefusesToMintCAWhenCertsIssued(t *testing.T) {
	database := behindAgent(t, "agent-up", "1.1.0+old")
	insertTestClientCert(t, database, "agent-up")
	env := upgradeCLIEnv(t)
	caDir := env(envCADir)

	var stdout, stderr strings.Builder
	err := runAgentUpgradeCommand([]string{"agent-up"}, env, &stdout, &stderr)
	assertCAResetWording(t, err)
	assertCANotMinted(t, caDir)
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing printed on refusal", stdout.String())
	}
}

func TestAgentUpgradeCommandFreshInstallStillProceedsPastCA(t *testing.T) {
	behindAgent(t, "agent-up", "1.1.0+old")
	env := upgradeCLIEnv(t)

	var stdout, stderr strings.Builder
	if err := runAgentUpgradeCommand([]string{"agent-up"}, env, &stdout, &stderr); err != nil {
		t.Fatalf("runAgentUpgradeCommand on a fresh install: %v", err)
	}
	if !strings.Contains(stdout.String(), "docker run") {
		t.Errorf("stdout lacks the upgrade command:\n%s", stdout.String())
	}
	if missing, _ := caMissingForTest(env(envCADir)); missing != "" {
		t.Errorf("fresh install did not create a CA: %s", missing)
	}
}

func caMissingForTest(dir string) (string, error) { return ca.CAMissing(dir) }
