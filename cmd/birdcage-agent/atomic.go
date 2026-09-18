package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic durably writes data to path: a temp file in path's own
// directory, chmod'd to mode, fsync'd, renamed over path, then the
// directory itself fsync'd. This is internal/agent/queue.PositionStore's
// own Save pattern, copied rather than reinvented (#48 rotation section:
// "write atomically to a 0600 file (temp + fsync + rename -- copy
// queue.PositionStore.Save's pattern, do not invent one)"). A
// same-directory temp file keeps source and destination on one
// filesystem, which is what makes the rename atomic rather than a copy;
// fsyncing the directory closes the window where a crash could leave a
// completed rename not yet durable on disk.
//
// On any failure before the rename, path is left completely untouched --
// whatever value (or absence) was there before stands, and the caller
// decides how to retry.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup on any early return -- once the rename below
	// succeeds this no longer exists under this name and Remove fails
	// with "not exist", which is expected and not worth reporting.
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("fsync directory: %w", err)
	}
	return nil
}

// syncDir fsyncs a directory's own metadata (e.g. the rename that just
// landed in it), not any file inside it.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
