package startcheck

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// skipIfRoot skips a permission-based test when running as uid 0:
// root ignores every mode bit these tests set, so the "check refuses"
// half of the test would pass for the wrong reason (or not exercise
// the refusal path at all).
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: file/dir permission checks don't apply")
	}
}

func TestWritableDirAcceptsAWritableDir(t *testing.T) {
	dir := t.TempDir()
	if err := WritableDir(dir); err != nil {
		t.Fatalf("WritableDir(%s): %v", dir, err)
	}
}

func TestWritableDirRefusesAnUnwritableDir(t *testing.T) {
	skipIfRoot(t)

	parent := t.TempDir()
	dir := filepath.Join(parent, "data")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err := WritableDir(dir)
	if err == nil {
		t.Fatal("WritableDir on a 0500 directory returned no error")
	}
	assertNamesPathUIDGIDAndFix(t, err, dir)
}

func TestReadableFileAcceptsAReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, []byte("placeholder"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := ReadableFile(path); err != nil {
		t.Fatalf("ReadableFile(%s): %v", path, err)
	}
}

func TestReadableFileRefusesAnUnreadableFile(t *testing.T) {
	skipIfRoot(t)

	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, []byte("placeholder"), 0o000); err != nil {
		t.Fatalf("write file: %v", err)
	}

	err := ReadableFile(path)
	if err == nil {
		t.Fatal("ReadableFile on a 0000 file returned no error")
	}
	assertNamesPathUIDGIDAndFix(t, err, path)
}

func TestReadableFileRefusesAMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.pem")
	if err := ReadableFile(path); err == nil {
		t.Fatal("ReadableFile on a missing file returned no error")
	}
}

// assertNamesPathUIDGIDAndFix is issue #70's exact requirement: the
// refusal names the path, the uid and gid birdcage is running as, and
// the fix (a chown command or --user).
func assertNamesPathUIDGIDAndFix(t *testing.T, err error, path string) {
	t.Helper()
	msg := err.Error()
	if !strings.Contains(msg, path) {
		t.Errorf("error %q does not name the path %q", msg, path)
	}
	uid := strconv.Itoa(os.Getuid())
	gid := strconv.Itoa(os.Getgid())
	if !strings.Contains(msg, uid) {
		t.Errorf("error %q does not name this process's uid %s", msg, uid)
	}
	if !strings.Contains(msg, gid) {
		t.Errorf("error %q does not name this process's gid %s", msg, gid)
	}
	if !strings.Contains(msg, "chown") || !strings.Contains(msg, "--user") {
		t.Errorf("error %q does not name both fixes (chown and --user)", msg)
	}
}
