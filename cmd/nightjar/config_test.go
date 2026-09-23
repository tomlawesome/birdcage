package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeStateDir creates a valid, already-enrolled state directory (every
// file enrolStateFiles names, present and readable), matching
// cmd/mockingbird/config_test.go's own helper of the same name.
func writeStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range enrolStateFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("placeholder"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func setValidEnv(t *testing.T, stateDir string) {
	t.Helper()
	t.Setenv(envBirdcageURL, "https://birdcage.example:8443")
	t.Setenv(envStateDir, stateDir)
	t.Setenv(envCAPin, "")
	t.Setenv(envDeployToken, "")
	t.Setenv(envScanIntervalS, "")
}

func TestLoadConfigMissingEnvVar(t *testing.T) {
	setValidEnv(t, writeStateDir(t))
	t.Setenv(envStateDir, "")

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig succeeded with NIGHTJAR_STATE_DIR unset")
	}
	if !strings.Contains(err.Error(), envStateDir) {
		t.Fatalf("err = %q, want it to name %s", err, envStateDir)
	}
}

func TestLoadConfigMissingCACert(t *testing.T) {
	dir := writeStateDir(t)
	if err := os.Remove(filepath.Join(dir, caFileName)); err != nil {
		t.Fatalf("remove %s: %v", caFileName, err)
	}
	setValidEnv(t, dir)

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig succeeded with ca.pem missing")
	}
	if !strings.Contains(err.Error(), caFileName) {
		t.Fatalf("err = %q, want it to name %s", err, caFileName)
	}
}

func TestLoadConfigSuccess(t *testing.T) {
	dir := writeStateDir(t)
	setValidEnv(t, dir)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.BirdcageURL != "https://birdcage.example:8443" {
		t.Errorf("BirdcageURL = %q", cfg.BirdcageURL)
	}
	if cfg.TokenPath != filepath.Join(dir, tokenFileName) {
		t.Errorf("TokenPath = %q", cfg.TokenPath)
	}
	if string(cfg.CACert) != "placeholder" {
		t.Errorf("CACert = %q, want placeholder", cfg.CACert)
	}
	if cfg.ScanInterval != time.Duration(defaultScanIntervalS)*time.Second {
		t.Errorf("ScanInterval = %v, want the default", cfg.ScanInterval)
	}
}

// TestLoadConfigPrefersIngestURL proves loadConfig overrides BirdcageURL
// with the ingest-url state file when it exists -- the enrolment
// listener and the ingest listener are different addresses, and only
// the latter is where SendScan should ever point once enrolled.
func TestLoadConfigPrefersIngestURL(t *testing.T) {
	dir := writeStateDir(t)
	if err := os.WriteFile(filepath.Join(dir, ingestURLFileName), []byte("https://ingest.example:9443\n"), 0o600); err != nil {
		t.Fatalf("write ingest-url: %v", err)
	}
	setValidEnv(t, dir)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.BirdcageURL != "https://ingest.example:9443" {
		t.Errorf("BirdcageURL = %q, want the ingest-url file's value", cfg.BirdcageURL)
	}
}

func TestLoadConfigScanIntervalOverride(t *testing.T) {
	dir := writeStateDir(t)
	setValidEnv(t, dir)
	t.Setenv(envScanIntervalS, "60")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ScanInterval != 60*time.Second {
		t.Errorf("ScanInterval = %v, want 60s", cfg.ScanInterval)
	}
}

func TestLoadConfigScanIntervalRejectsNonPositive(t *testing.T) {
	dir := writeStateDir(t)
	setValidEnv(t, dir)
	t.Setenv(envScanIntervalS, "0")

	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig succeeded with NIGHTJAR_SCAN_INTERVAL_S=0")
	}
}
