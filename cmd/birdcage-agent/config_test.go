package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeStateDir creates a valid state directory (CA/client cert/key
// present and readable) and returns its path, for tests that only care
// about the environment-variable side of loadConfig.
func writeStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{caFileName, clientCertFileName, clientKeyFileName} {
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
	t.Setenv(envLogPath, "/var/log/opencanary/opencanary.json")
	t.Setenv(envListen, "127.0.0.1:8081")
}

// TestLoadConfigMissingEnvVar proves a missing required environment
// variable is a clear, non-nil error naming which one -- #48 decision 1:
// "Every missing or unreadable required input ... is a loud non-zero
// exit at startup."
func TestLoadConfigMissingEnvVar(t *testing.T) {
	setValidEnv(t, writeStateDir(t))
	t.Setenv(envListen, "")

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig succeeded with BIRDCAGE_AGENT_LISTEN unset")
	}
	if !strings.Contains(err.Error(), envListen) {
		t.Fatalf("err = %q, want it to name %s", err, envListen)
	}
}

// TestLoadConfigMissingCACert proves an unreadable required state-dir
// file is also a startup failure, not just a missing environment
// variable.
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

// TestLoadConfigSuccess proves the happy path: every field lands where
// it should, and the derived token/position paths sit inside StateDir.
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
	if cfg.PositionPath != filepath.Join(dir, positionFileName) {
		t.Errorf("PositionPath = %q", cfg.PositionPath)
	}
	if string(cfg.CACert) != "placeholder" {
		t.Errorf("CACert = %q", cfg.CACert)
	}
}
