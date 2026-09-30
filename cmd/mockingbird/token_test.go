package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadTokenStoreMissingFile proves a missing token file is a
// startup failure, not a zero-value TokenStore.
func TestLoadTokenStoreMissingFile(t *testing.T) {
	_, err := loadTokenStore(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("loadTokenStore succeeded against a missing file")
	}
}

// TestLoadTokenStoreEmptyFile proves an empty (or whitespace-only) token
// file is also a startup failure, not a valid empty token.
func TestLoadTokenStoreEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if _, err := loadTokenStore(path); err == nil {
		t.Fatal("loadTokenStore succeeded against a blank file")
	}
}

// TestLoadTokenStoreTrimsWhitespace proves a token file's trailing
// newline (the ordinary shape of a file enrolment wrote with a text
// tool) doesn't become part of the token value.
func TestLoadTokenStoreTrimsWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  the-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	ts, err := loadTokenStore(path)
	if err != nil {
		t.Fatalf("loadTokenStore: %v", err)
	}
	if got := ts.Current(); got != "the-token" {
		t.Fatalf("Current() = %q, want %q", got, "the-token")
	}
}

// TestTokenStoreSetIsVisibleToCurrent proves the store's own get/set
// pair (not the atomic-write side of rotation, covered in
// rotate_test.go) works: what set writes, Current reads back.
func TestTokenStoreSetIsVisibleToCurrent(t *testing.T) {
	ts := &TokenStore{current: "tok-a"}
	ts.set("tok-b")
	if got := ts.Current(); got != "tok-b" {
		t.Fatalf("Current() = %q, want tok-b", got)
	}
}

// TestWriteFileAtomicRoundTrips proves the plain success path: data
// lands at path, readable back exactly, with the requested mode.
func TestWriteFileAtomicRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	if err := writeFileAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("content = %q, want %q", got, "hello")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestWriteFileAtomicLeavesExistingFileOnFailure proves the invariant
// writeFileAtomic promises: a failed write never touches path at all.
// Forced here by pointing path at a directory whose parent does not
// exist, which fails at the CreateTemp step before anything is written.
func TestWriteFileAtomicLeavesExistingFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatalf("seed original file: %v", err)
	}

	badPath := filepath.Join(dir, "no-such-subdir", "out")
	if err := writeFileAtomic(badPath, []byte("new"), 0o600); err == nil {
		t.Fatal("writeFileAtomic succeeded against a nonexistent directory")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back original: %v", err)
	}
	if string(got) != "original" {
		t.Fatalf("original file = %q, want untouched %q", got, "original")
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Fatalf("badPath exists after a failed write: %v", err)
	}
}
