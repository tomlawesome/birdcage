package queue

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPositionStore_SaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	store := NewPositionStore(filepath.Join(dir, "position"))

	want := Position{Inode: 12345, Offset: 6789}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatalf("Load ok = false, want true")
	}
	if got != want {
		t.Fatalf("Load = %+v, want %+v", got, want)
	}
}

func TestPositionStore_LoadNoFileYet(t *testing.T) {
	dir := t.TempDir()
	store := NewPositionStore(filepath.Join(dir, "position"))

	pos, ok, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ok {
		t.Fatalf("Load ok = true with no file saved, want false (pos=%+v)", pos)
	}
}

func TestPositionStore_SaveOverwritesWithLatest(t *testing.T) {
	dir := t.TempDir()
	store := NewPositionStore(filepath.Join(dir, "position"))

	if err := store.Save(Position{Inode: 1, Offset: 10}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Save(Position{Inode: 1, Offset: 20}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok, err := store.Load()
	if err != nil || !ok {
		t.Fatalf("Load: pos=%+v ok=%v err=%v", got, ok, err)
	}
	if got.Offset != 20 {
		t.Fatalf("Offset = %d, want 20 (the later save)", got.Offset)
	}
}

// TestPositionStore_TruncatedFileIsNoPosition simulates a crash that
// left a torn write on the published path itself (e.g. a filesystem
// that doesn't make even a rename fully atomic, or damage after the
// fact) -- #48 requires this be treated as "no saved position", never
// misread as a shorter-than-intended real one, since a wrong position
// could skip unacknowledged events.
func TestPositionStore_TruncatedFileIsNoPosition(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "position")
	store := NewPositionStore(path)

	if err := store.Save(Position{Inode: 1, Offset: 100}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture file: %v", err)
	}
	if err := os.WriteFile(path, full[:len(full)-5], 0o600); err != nil {
		t.Fatalf("truncate fixture file: %v", err)
	}

	pos, ok, err := store.Load()
	if err != nil {
		t.Fatalf("Load on truncated file returned an error, want ok=false, err=nil: %v", err)
	}
	if ok {
		t.Fatalf("Load ok = true on a truncated file, want false (pos=%+v)", pos)
	}
}

// TestPositionStore_CorruptChecksumIsNoPosition covers corruption that
// doesn't change the record's length -- a flipped bit from a bad block,
// for instance -- which truncation detection alone would miss.
func TestPositionStore_CorruptChecksumIsNoPosition(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "position")
	store := NewPositionStore(path)

	if err := store.Save(Position{Inode: 1, Offset: 100}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture file: %v", err)
	}
	buf[0] ^= 0xFF // corrupt the inode field; checksum no longer matches
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("corrupt fixture file: %v", err)
	}

	pos, ok, err := store.Load()
	if err != nil {
		t.Fatalf("Load on corrupted file returned an error, want ok=false, err=nil: %v", err)
	}
	if ok {
		t.Fatalf("Load ok = true on a checksum-mismatched file, want false (pos=%+v)", pos)
	}
}

// TestPositionStore_CrashBeforeRenameLeavesPreviousPositionIntact
// simulates a crash in the window atomic rename exists to make safe:
// the temp file is written but the rename to the real path never
// happens. The previously saved position must be unaffected, and the
// stray temp file must never be picked up as if it were real.
func TestPositionStore_CrashBeforeRenameLeavesPreviousPositionIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "position")
	store := NewPositionStore(path)

	if err := store.Save(Position{Inode: 1, Offset: 100}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	stray, err := os.CreateTemp(dir, ".position-*.tmp")
	if err != nil {
		t.Fatalf("create stray temp file: %v", err)
	}
	if _, err := stray.Write(encodePosition(Position{Inode: 1, Offset: 999})); err != nil {
		t.Fatalf("write stray temp file: %v", err)
	}
	if err := stray.Close(); err != nil {
		t.Fatalf("close stray temp file: %v", err)
	}

	pos, ok, err := store.Load()
	if err != nil || !ok {
		t.Fatalf("Load: pos=%+v ok=%v err=%v", pos, ok, err)
	}
	if pos.Offset != 100 {
		t.Fatalf("Offset = %d, want 100 (the un-renamed stray temp file must be ignored)", pos.Offset)
	}
}

// TestPositionStore_SaveLeavesNoStrayTempFiles guards against a leaked
// temp file on the success path -- a leftover .position-*.tmp file
// wouldn't corrupt anything today, but would give a future reader (or a
// naive "pick the newest file" recovery script) something to trip on.
func TestPositionStore_SaveLeavesNoStrayTempFiles(t *testing.T) {
	dir := t.TempDir()
	store := NewPositionStore(filepath.Join(dir, "position"))

	for i := 0; i < 5; i++ {
		if err := store.Save(Position{Inode: 1, Offset: int64(i)}); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("directory contains %v, want exactly [\"position\"]", names)
	}
}

// TestPositionStore_FilePermissions proves the position file is not
// readable by anyone but its owner (#48's "unreadable by any other user
// on the box" rule, applied here as it is to the token file).
func TestPositionStore_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "position")
	store := NewPositionStore(path)

	if err := store.Save(Position{Inode: 1, Offset: 1}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permissions = %#o, want 0600 (unreadable by group/other)", perm)
	}
}
