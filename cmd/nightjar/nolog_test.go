package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file is cmd/nightjar's own version of cmd/mockingbird's
// nolog_test.go: the state directory path must never appear in an error
// this agent's startup path returns, however deep the underlying os
// error nests it -- loadConfig is the only code in this package that
// ever touches StateDir directly.
func TestLoadConfigErrorsNeverLeakStateDir(t *testing.T) {
	dir := writeStateDir(t)
	if err := os.Remove(filepath.Join(dir, clientKeyFileName)); err != nil {
		t.Fatalf("remove %s: %v", clientKeyFileName, err)
	}
	setValidEnv(t, dir)

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig succeeded with client-key.pem missing")
	}
	if strings.Contains(err.Error(), dir) {
		t.Fatalf("error %q leaks the state directory path %q", err, dir)
	}
}

// TestLoadTokenErrorNeverLeaksPath proves the same for loadToken's own
// missing-file error.
func TestLoadTokenErrorNeverLeaksPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist")

	_, err := loadToken(path)
	if err == nil {
		t.Fatal("loadToken succeeded against a missing file")
	}
	if strings.Contains(err.Error(), dir) {
		t.Fatalf("error %q leaks the directory path %q", err, dir)
	}
}
