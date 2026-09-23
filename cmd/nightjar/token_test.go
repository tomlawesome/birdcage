package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTokenMissingFile(t *testing.T) {
	_, err := loadToken(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("loadToken succeeded against a missing file")
	}
}

func TestLoadTokenEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if _, err := loadToken(path); err == nil {
		t.Fatal("loadToken succeeded against a blank file")
	}
}

func TestLoadTokenTrimsWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  the-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	got, err := loadToken(path)
	if err != nil {
		t.Fatalf("loadToken: %v", err)
	}
	if got != "the-token" {
		t.Fatalf("loadToken = %q, want %q", got, "the-token")
	}
}
