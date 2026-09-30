package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteRoundTrips proves the plain success path: data lands at path,
// readable back exactly, with the requested mode.
func TestWriteRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	if err := Write(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
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

// TestWriteLeavesExistingFileOnFailure proves the invariant Write
// promises: a failed write never touches path at all.
func TestWriteLeavesExistingFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatalf("seed original file: %v", err)
	}

	badPath := filepath.Join(dir, "no-such-subdir", "out")
	if err := Write(badPath, []byte("new"), 0o600); err == nil {
		t.Fatal("Write succeeded against a nonexistent directory")
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

// TestWriteOverwritesExisting proves Write replaces an existing file's
// content rather than merely refusing to touch it -- rotate.go's own use
// (a new token replacing the old one) depends on this.
func TestWriteOverwritesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed original file: %v", err)
	}
	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("content = %q, want %q", got, "new")
	}
}
