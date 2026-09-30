package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestApprovalCheckMissingFile proves the os.ReadFile error branch: a
// path that does not exist is reported as a read failure naming the
// (escaped) path, not a panic or a bare os error.
func TestApprovalCheckMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.eml")

	_, err := captureStdout(t, func() error { return runApprovalCheck([]string{path}) })
	if err == nil {
		t.Fatal("runApprovalCheck succeeded against a missing file")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("err = %q, want it to say it could not read the file", err)
	}
}

// TestApprovalCheckDatabaseOpenFailure proves runApprovalCheck's own
// openCanaryDB error branch: a BIRDCAGE_DB_PATH that cannot be migrated
// (a directory that does not exist, so SQLite cannot create the file
// under it) surfaces the wrapped database error rather than reaching
// any of the approval-checking logic below it.
func TestApprovalCheckDatabaseOpenFailure(t *testing.T) {
	t.Setenv(envDatabaseURL, "")
	t.Setenv(envDBPath, "/nonexistent-dir-for-birdcage-coverage-test/db.sqlite")
	path := writeEML(t, unsignedReply)

	_, err := captureStdout(t, func() error { return runApprovalCheck([]string{path}) })
	if err == nil {
		t.Fatal("runApprovalCheck succeeded with an unopenable database")
	}
	if !strings.Contains(err.Error(), "migrate database") {
		t.Errorf("err = %q, want it to surface the database-open failure", err)
	}
}
