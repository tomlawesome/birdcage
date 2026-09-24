// Package scan wraps Grype (ADR-0010, "Engine: Grype") as a subprocess:
// run it against a filesystem tree, parse its JSON output into
// birdcage's own wire finding shape, and classify the outcome.
//
// ADR-0010 decision 8 and the "Scanner agent, slice 1" plan (#108,
// section 4) make classification the point of this package: any
// non-zero exit, output the agent cannot parse, or a stale vulnerability
// database Grype itself refused to run against, becomes a failed Result
// with a reason and zero findings -- never an empty finding set
// presented as a clean scan. Grype's own default fail-closed behaviour
// (it refuses to run against a database older than five days) is kept
// at its defaults, not overridden, so that refusal already surfaces as
// a non-zero exit this package classifies the same way as any other.
//
// Grype is invoked as a subprocess, never imported: ADR-0010 records it
// as a pre-1.0 Go library not meant to be embedded.
package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// EngineName is the fixed identity of the engine this package wraps.
// Never parsed from Grype's own output -- ADR-0010 settled the engine,
// this package only ever wraps that one.
const EngineName = "grype"

// Status values for Result.Status -- the wire contract's own strings
// (the plan's section 2).
const (
	StatusOK     = "ok"
	StatusFailed = "failed"
)

// maxReasonLen bounds Result.Reason: Grype's stderr on a failure is
// normally a single short line, but this keeps a runaway or unexpected
// wall of stderr text from turning a failed-scan snapshot into an
// oversized request body.
const maxReasonLen = 2000

// Finding is birdcage's own wire shape for one Grype match -- the "Scanner
// agent, slice 1" plan (#108), section 2. Target is the scan target string
// (e.g. "dir:/host") every finding in one Result shares, not something
// Grype's own output carries per match.
type Finding struct {
	Target        string `json:"target"`
	Package       string `json:"package"`
	Version       string `json:"version"`
	Type          string `json:"type"`
	Vulnerability string `json:"vulnerability"`
	Severity      string `json:"severity"`
	// FixVersion is empty when no fixed version is known.
	FixVersion string `json:"fix_version"`
}

// Engine identifies the scanner and the vulnerability database it ran
// with. Only populated when Grype actually produced a document
// (Status == StatusOK): a failed run may never have loaded a database at
// all, so there is nothing honest to report here.
type Engine struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	DBBuiltAt time.Time `json:"db_built_at"`
}

// Result is one scan's outcome -- the parts of the wire snapshot this
// package determines on its own. TakenAt and the agent's own version are
// the calling binary's facts (when it started the scan, and its own
// build version), not this package's to set; the caller adds them when
// it builds the full snapshot it posts to birdcage.
type Result struct {
	Engine Engine
	Status string
	// Reason is set exactly when Status == StatusFailed, and empty
	// otherwise.
	Reason string
	// Findings is empty exactly when Status == StatusFailed -- this
	// package never returns a partial finding set alongside a failure.
	Findings []Finding
}

// Run invokes `<grypeBin> dir:<path> -o json` as a subprocess and
// classifies the outcome. It never returns a Go error for an ordinary
// scan failure -- a stale database, a crash, output it cannot parse --
// because ADR-0010 decision 8 requires the caller to always have
// something honest to post: a Result whose Status is StatusFailed and
// whose Reason says why. The only Go error this can return is ctx being
// done before the subprocess could even be started.
//
// GRYPE_DB_AUTO_UPDATE=false is always set (ADR-0012 decision 10): the
// caller's own UpdateDB, below, is the one place the database is ever
// refreshed, run as its own loud step immediately before this call, so
// Run itself must never let Grype's own two-hourly default check race
// or duplicate that step -- what UpdateDB fetched is what this scans
// with.
func Run(ctx context.Context, grypeBin, path string) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	target := "dir:" + path
	cmd := exec.CommandContext(ctx, grypeBin, target, "-o", "json")
	cmd.Env = append(os.Environ(), "GRYPE_DB_AUTO_UPDATE=false")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	return classify(target, stdout.Bytes(), stderr.Bytes(), runErr), nil
}

// UpdateDB invokes `<grypeBin> db update` as its own step, meant to run
// immediately before every call to Run (ADR-0012 decision 10: "the
// vulnerability database is refreshed immediately before every scan").
// The `db update` subcommand sets Grype's own RequireUpdateCheck=true
// (research: grype/cmd/grype/cli/commands/database_command.go), so a
// mirror it cannot reach fails this call loudly rather than the silent,
// at-most-two-hourly check Run's own defaults would otherwise make.
//
// Like Run, this never returns a Go error for an ordinary refresh
// failure -- a network error, a stale signature, Grype exiting non-zero
// -- only for ctx already being done before the subprocess could start.
// The caller decides what a failed refresh means for the scan that
// follows (still runs on the last good database, under Grype's own
// five-day cap) and for what it reports to birdcage.
func UpdateDB(ctx context.Context, grypeBin string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, grypeBin, "db", "update")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return errors.New(failureReason(stderr.Bytes(), exitErr.ExitCode()))
		}
		return fmt.Errorf("grype db update did not run: %s", err)
	}
	return nil
}

// classify turns one subprocess invocation's raw outcome into a Result.
// Exit status is decisive and checked first, exactly per ADR-0010
// decision 8: a non-zero exit is always a failed scan, whatever stdout
// contains (Grype does not mix a usable document with a non-zero exit in
// this agent's own usage -- it never asks for --fail-on-severity-- but
// treating exit status as authoritative regardless is what "never
// overridden" fail-closed means in code).
func classify(target string, stdout, stderr []byte, runErr error) Result {
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return Result{Status: StatusFailed, Reason: failureReason(stderr, exitErr.ExitCode())}
		}
		// The subprocess never produced an exit status at all -- the
		// binary was missing, or something else stopped it from
		// running. Still a failed scan, never silence.
		return Result{Status: StatusFailed, Reason: fmt.Sprintf("grype did not run: %s", runErr)}
	}

	var doc document
	if err := json.Unmarshal(stdout, &doc); err != nil {
		return Result{Status: StatusFailed, Reason: fmt.Sprintf("parse grype output: %s", err)}
	}

	findings := make([]Finding, 0, len(doc.Matches))
	for _, m := range doc.Matches {
		findings = append(findings, Finding{
			Target:        target,
			Package:       m.Artifact.Name,
			Version:       m.Artifact.Version,
			Type:          m.Artifact.Type,
			Vulnerability: m.Vulnerability.ID,
			Severity:      strings.ToLower(m.Vulnerability.Severity),
			FixVersion:    firstFixVersion(m.Vulnerability.Fix.Versions),
		})
	}

	return Result{
		Engine: Engine{
			Name:      EngineName,
			Version:   doc.Descriptor.Version,
			DBBuiltAt: doc.Descriptor.DB.Status.Built,
		},
		Status:   StatusOK,
		Findings: findings,
	}
}

// failureReason turns a non-zero exit's stderr into Result.Reason.
// Grype prints its own failure explanation there -- including the stale-
// database refusal this package relies on ("db could not be loaded: the
// vulnerability database was built N days ago (max allowed age is 5
// days)") -- so the whole trimmed, bounded text is used rather than
// pattern-matching for one specific message: any reason Grype gives for
// refusing to run is equally a failed scan.
func failureReason(stderr []byte, exitCode int) string {
	msg := strings.TrimSpace(string(stderr))
	if msg == "" {
		return fmt.Sprintf("grype exited with status %d and no error output", exitCode)
	}
	if len(msg) > maxReasonLen {
		msg = msg[:maxReasonLen] + "…"
	}
	return msg
}

// firstFixVersion returns the first fixed version Grype reports, or ""
// when none is known. Grype's own Vulnerability.Fix.Versions is already
// sorted (grype/presenter/models.sortVersions); the first entry is the
// same one a plain read of `grype -o table` would show as "the" fixed
// version for a single-version case, and multi-version cases are rare
// enough that this wire contract's singular fix_version field does not
// try to carry more than one.
func firstFixVersion(versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	return versions[0]
}

// document is the subset of Grype's own `-o json` schema this package
// reads. Deliberately narrow -- Grype's real document carries far more
// (licenses, CPEs, match details, ignored matches, related
// vulnerabilities...) that birdcage's wire contract has no field for;
// json.Unmarshal ignores whatever this struct does not name, which is
// the point, unlike the DisallowUnknownFields birdcage's own wire
// contract uses on itself (internal/ingest, #108 commit 3) -- that rule
// is for birdcage's request bodies, not for reading a large upstream
// tool's output.
type document struct {
	Matches    []match `json:"matches"`
	Descriptor struct {
		Version string `json:"version"`
		DB      struct {
			Status struct {
				Built time.Time `json:"built"`
			} `json:"status"`
		} `json:"db"`
	} `json:"descriptor"`
}

type match struct {
	Vulnerability struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Fix      struct {
			Versions []string `json:"versions"`
		} `json:"fix"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
	} `json:"artifact"`
}
