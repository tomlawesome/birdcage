package ca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCAMissing covers issue #149's question, asked before Load can mint:
// is the CA directory or its key absent? Absence is reported by name;
// a CA Load already wrote is not missing; a path that cannot be checked
// is an error, never "missing" (which would let a fresh CA be minted).
func TestCAMissing(t *testing.T) {
	t.Run("no directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "ca")
		missing, err := CAMissing(dir)
		if err != nil || !strings.Contains(missing, "CA directory") {
			t.Fatalf("missing = %q, err = %v; want the directory named", missing, err)
		}
	})
	t.Run("no key file", func(t *testing.T) {
		missing, err := CAMissing(newTestDir(t))
		if err != nil || !strings.Contains(missing, caKeyFileName) {
			t.Fatalf("missing = %q, err = %v; want %s named", missing, err, caKeyFileName)
		}
	})
	t.Run("present", func(t *testing.T) {
		dir := newTestDir(t)
		if _, _, err := Load(dir, time.Now); err != nil {
			t.Fatalf("Load: %v", err)
		}
		missing, err := CAMissing(dir)
		if err != nil || missing != "" {
			t.Fatalf("missing = %q, err = %v; want nothing missing", missing, err)
		}
	})
	t.Run("unreadable parent", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads through directory modes")
		}
		parent := t.TempDir()
		dir := filepath.Join(parent, "ca")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		missing, err := CAMissing(dir)
		if err == nil {
			t.Fatalf("missing = %q, err = nil; want an error, not a verdict", missing)
		}
	})
}
