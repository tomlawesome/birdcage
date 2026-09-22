package scan

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file drives classify (the classification this package exists
// for) directly against recorded Grype output and exit codes, per the
// plan's own instruction -- no real grype binary is required to run
// these tests. Run itself is proven separately below against a stub
// script standing in for grype, which proves the subprocess plumbing
// (argument construction, stdout/stderr capture) without needing the
// real tool either.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

// TestClassifyVulnerableScan proves the happy path against a recorded
// single-finding document (the plan's own example: openssl/CVE-2014-0160),
// including severity lowercasing and the fixed-version pass-through.
func TestClassifyVulnerableScan(t *testing.T) {
	stdout := readFixture(t, "vulnerable.json")

	result := classify("dir:/host", stdout, nil, nil)

	if result.Status != StatusOK {
		t.Fatalf("Status = %q, want %q (Reason: %q)", result.Status, StatusOK, result.Reason)
	}
	if result.Reason != "" {
		t.Errorf("Reason = %q, want empty on success", result.Reason)
	}
	if result.Engine.Name != EngineName {
		t.Errorf("Engine.Name = %q, want %q", result.Engine.Name, EngineName)
	}
	if result.Engine.Version != "1.14.0" {
		t.Errorf("Engine.Version = %q, want %q", result.Engine.Version, "1.14.0")
	}
	wantBuilt, err := time.Parse(time.RFC3339, "2026-09-20T01:12:07Z")
	if err != nil {
		t.Fatalf("parse want time: %v", err)
	}
	if !result.Engine.DBBuiltAt.Equal(wantBuilt) {
		t.Errorf("Engine.DBBuiltAt = %v, want %v", result.Engine.DBBuiltAt, wantBuilt)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(result.Findings))
	}
	f := result.Findings[0]
	want := Finding{
		Target:        "dir:/host",
		Package:       "openssl",
		Version:       "1.0.1f-1ubuntu2",
		Type:          "deb",
		Vulnerability: "CVE-2014-0160",
		Severity:      "critical",
		FixVersion:    "1.0.1f-1ubuntu2.1",
	}
	if f != want {
		t.Errorf("Findings[0] = %+v, want %+v", f, want)
	}
}

// TestClassifyCleanScan proves a scan with no matches reports Status ==
// StatusOK with an empty (never nil-vs-empty-confused) Findings slice --
// distinguishing a genuinely clean scan from a failed one is the whole
// point of this package existing.
func TestClassifyCleanScan(t *testing.T) {
	stdout := readFixture(t, "clean.json")

	result := classify("dir:/host", stdout, nil, nil)

	if result.Status != StatusOK {
		t.Fatalf("Status = %q, want %q", result.Status, StatusOK)
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(result.Findings))
	}
	if result.Findings == nil {
		t.Errorf("Findings is nil, want a non-nil empty slice")
	}
}

// TestClassifyMultipleFindings proves severity lowercasing and the
// empty-fix-version case (Fix.Versions == []) together, against a second
// recorded document with two matches.
func TestClassifyMultipleFindings(t *testing.T) {
	stdout := readFixture(t, "multiple-findings.json")

	result := classify("dir:/host", stdout, nil, nil)

	if result.Status != StatusOK {
		t.Fatalf("Status = %q, want %q", result.Status, StatusOK)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(result.Findings))
	}
	if got, want := result.Findings[0].Severity, "high"; got != want {
		t.Errorf("Findings[0].Severity = %q, want %q", got, want)
	}
	if got, want := result.Findings[0].FixVersion, "2.4.1-1"; got != want {
		t.Errorf("Findings[0].FixVersion = %q, want %q", got, want)
	}
	if got, want := result.Findings[1].Severity, "negligible"; got != want {
		t.Errorf("Findings[1].Severity = %q, want %q", got, want)
	}
	if got := result.Findings[1].FixVersion; got != "" {
		t.Errorf("Findings[1].FixVersion = %q, want empty (no known fix)", got)
	}
}

// TestClassifyStaleDatabaseIsFailed is ADR-0010 decision 8's own test:
// Grype's fail-closed refusal of a database older than its max allowed
// age (a non-zero exit, recorded stderr text) must classify as a failed
// scan with that reason -- and, just as important, with zero findings,
// never a stale empty result presented as clean.
func TestClassifyStaleDatabaseIsFailed(t *testing.T) {
	stderr := readFixture(t, "stale-db.stderr.txt")
	exitErr := fakeExitError(t, 1)

	result := classify("dir:/host", nil, stderr, exitErr)

	if result.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", result.Status, StatusFailed)
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0 on a failed scan", len(result.Findings))
	}
	if !strings.Contains(result.Reason, "built 6 days ago") {
		t.Errorf("Reason = %q, want it to explain the stale database", result.Reason)
	}
}

// TestClassifyNonZeroExitIsFailed proves the general rule behind the
// stale-database case above: ANY non-zero exit is a failed scan, not
// only the one Grype reason this package happens to have a fixture for.
func TestClassifyNonZeroExitIsFailed(t *testing.T) {
	stderr := readFixture(t, "invalid-target.stderr.txt")
	exitErr := fakeExitError(t, 1)

	result := classify("dir:/no/such/path", nil, stderr, exitErr)

	if result.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", result.Status, StatusFailed)
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0 on a failed scan", len(result.Findings))
	}
	if !strings.Contains(result.Reason, "no such file or directory") {
		t.Errorf("Reason = %q, want it to carry grype's own explanation", result.Reason)
	}
}

// TestClassifyNonZeroExitWithNoStderr proves a non-zero exit that
// somehow carries no stderr text still produces a non-empty Reason --
// never a failed scan with nothing said about why.
func TestClassifyNonZeroExitWithNoStderr(t *testing.T) {
	exitErr := fakeExitError(t, 2)

	result := classify("dir:/host", nil, nil, exitErr)

	if result.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", result.Status, StatusFailed)
	}
	if result.Reason == "" {
		t.Error("Reason is empty, want a fallback reason naming the exit status")
	}
	if !strings.Contains(result.Reason, "2") {
		t.Errorf("Reason = %q, want it to mention the exit status 2", result.Reason)
	}
}

// TestClassifyNeverRanIsFailed proves the subprocess never even
// starting (binary missing, permission denied -- an error that is not a
// *exec.ExitError at all) is still classified as a failed scan rather
// than surfacing as some other shape the caller has to special-case.
func TestClassifyNeverRanIsFailed(t *testing.T) {
	result := classify("dir:/host", nil, nil, errors.New("exec: \"grype\": executable file not found in $PATH"))

	if result.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", result.Status, StatusFailed)
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(result.Findings))
	}
	if !strings.Contains(result.Reason, "not found") {
		t.Errorf("Reason = %q, want it to carry the underlying error", result.Reason)
	}
}

// TestClassifyParseFailureIsFailed proves output this package cannot
// parse as JSON -- Grype exited 0 but something is wrong with what it
// printed -- is a failed scan too, per ADR-0010 decision 8's "parse
// failure" clause, not a panic and not an empty clean result.
func TestClassifyParseFailureIsFailed(t *testing.T) {
	result := classify("dir:/host", []byte("not json at all"), nil, nil)

	if result.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", result.Status, StatusFailed)
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(result.Findings))
	}
	if result.Reason == "" {
		t.Error("Reason is empty, want an explanation of the parse failure")
	}
}

// TestClassifyReasonIsBounded proves a pathologically large stderr never
// turns a failed-scan Reason into an oversized snapshot body.
func TestClassifyReasonIsBounded(t *testing.T) {
	huge := make([]byte, maxReasonLen*3)
	for i := range huge {
		huge[i] = 'x'
	}
	exitErr := fakeExitError(t, 1)

	result := classify("dir:/host", nil, huge, exitErr)

	if len(result.Reason) > maxReasonLen+len("…") {
		t.Errorf("len(Reason) = %d, want <= %d", len(result.Reason), maxReasonLen+len("…"))
	}
}

// fakeExitError produces a real *exec.ExitError with the given exit
// code, by actually running a short-lived subprocess -- the only
// reliable, portable way to obtain one (its concrete os.ProcessState is
// not otherwise constructible), so this stays honest to what Run
// actually receives from exec.Cmd.Run.
func fakeExitError(t *testing.T, code int) *exec.ExitError {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fakeExitError relies on /bin/sh -c 'exit N'")
	}
	cmd := exec.Command("/bin/sh", "-c", "exit "+strconv.Itoa(code))
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError, got %T (%v)", err, err)
	}
	return exitErr
}

// TestRunInvokesGrypeAndParsesOutput proves Run's own subprocess
// plumbing -- the exact arguments it invokes with, and that stdout is
// captured and classified -- against a stub script standing in for
// grype, never the real tool.
func TestRunInvokesGrypeAndParsesOutput(t *testing.T) {
	stub := writeStubGrype(t, `#!/bin/sh
if [ "$1" != "dir:/host" ] || [ "$2" != "-o" ] || [ "$3" != "json" ]; then
  echo "unexpected args: $*" >&2
  exit 1
fi
cat "`+fixtureAbsPath(t, "vulnerable.json")+`"
exit 0
`)

	result, err := Run(context.Background(), stub, "/host")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusOK {
		t.Fatalf("Status = %q, want %q (Reason: %q)", result.Status, StatusOK, result.Reason)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].Vulnerability != "CVE-2014-0160" {
		t.Errorf("Findings[0].Vulnerability = %q, want CVE-2014-0160", result.Findings[0].Vulnerability)
	}
}

// TestRunClassifiesNonZeroExit proves Run's end-to-end path for a
// failing subprocess -- the stub exits 1 with stderr text, and Run
// returns a failed Result rather than a Go error, per ADR-0010 decision
// 8's requirement that the caller always has something honest to post.
func TestRunClassifiesNonZeroExit(t *testing.T) {
	stub := writeStubGrype(t, `#!/bin/sh
echo "db could not be loaded: the vulnerability database was built 9 days ago (max allowed age is 5 days)" >&2
exit 1
`)

	result, err := Run(context.Background(), stub, "/host")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", result.Status, StatusFailed)
	}
	if len(result.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(result.Findings))
	}
	if !strings.Contains(result.Reason, "built 9 days ago") {
		t.Errorf("Reason = %q, want the stale-database explanation", result.Reason)
	}
}

// TestRunMissingBinaryIsFailed proves Run against a binary that does not
// exist at all still returns a failed Result, not a Go error -- the same
// "never nothing to post" guarantee, exercised through the real
// exec.Cmd.Run path rather than classify directly.
func TestRunMissingBinaryIsFailed(t *testing.T) {
	result, err := Run(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"), "/host")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", result.Status, StatusFailed)
	}
	if result.Reason == "" {
		t.Error("Reason is empty, want an explanation")
	}
}

// TestRunContextAlreadyDone proves Run refuses to even attempt starting
// the subprocess once its context is already done, returning that as a
// Go error -- the one case Run does surface as an error rather than a
// failed Result, since the caller's own context lifecycle is not this
// package's to reinterpret.
func TestRunContextAlreadyDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Run(ctx, "irrelevant", "/host")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
}

// writeStubGrype writes script (a shell script) to a temp file, chmod's
// it executable, and returns its path -- a stand-in for the grype
// binary so Run's subprocess plumbing can be proven without the real
// tool installed.
func writeStubGrype(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("writeStubGrype relies on a #!/bin/sh script")
	}
	path := filepath.Join(t.TempDir(), "grype-stub.sh")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return path
}

func fixtureAbsPath(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("abs path for fixture %s: %v", name, err)
	}
	return abs
}
