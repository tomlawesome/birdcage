// scanner.go is this agent's whole reason to exist: the loop that checks
// the host mount is actually covered (issue #108, "The covering is
// enforced by the agent, not only by the run command"), runs pinned
// Grype over it, and posts the resulting snapshot to birdcage.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/hostmask"
	"github.com/tomlawesome/birdcage/internal/scan"
)

// mountinfoPath is where the running container's own mount table lives
// -- always this path in any Linux container, never configurable.
const mountinfoPath = "/proc/self/mountinfo"

// runScanLoop runs one scan cycle immediately, then again every
// interval, until ctx is done -- "on start and on an interval" (issue
// #108, section 4), against the real mount check and the real grype
// binary.
func runScanLoop(ctx context.Context, cli *client.Client, token string, version string, interval time.Duration, log *slog.Logger, now func() time.Time) {
	runLoop(ctx, interval, func() {
		runScanOnce(ctx, cli, token, version, log, now, checkMounts, realScan)
	})
}

// runLoop calls cycle immediately, then again every interval, until ctx
// is done -- the cadence contract on its own, with no client or scanner
// dependency, so a test can prove "runs immediately, stops promptly on
// cancel" without building either (see scanner_test.go). A cycle's own
// failure never stops the loop: whatever cycle does with an error (log
// and continue, in runScanOnce's case) is its own concern, the same
// "keep the process alive" shape cmd/mockingbird's own long-lived loops
// follow.
func runLoop(ctx context.Context, interval time.Duration, cycle func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		cycle()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// realScan is runScanLoop's production runScan argument: pinned Grype
// over the real host bind. A test substitutes a stub here instead of
// exec'ing a real grype binary.
func realScan(ctx context.Context) (scan.Result, error) {
	return scan.Run(ctx, grypeBin, hostRoot)
}

// runScanOnce builds and posts exactly one snapshot: checkMounts first
// (never scanning if it fails), then runScan, then SendScan. Every path
// through buildSnapshot ends in a snapshot with a status -- ADR-0010
// decision 8, "the agent never posts an empty finding set it did not
// earn" -- there is no code path here that skips posting anything.
// checkMounts and runScan are passed in rather than called directly so a
// test can drive every branch of buildSnapshot without a real container
// or a real grype binary (see scanner_test.go).
func runScanOnce(ctx context.Context, cli *client.Client, token string, version string, log *slog.Logger, now func() time.Time, checkMounts func() error, runScan func(context.Context) (scan.Result, error)) {
	snapshot := buildSnapshot(ctx, version, now, checkMounts, runScan)
	if err := cli.SendScan(ctx, token, snapshot); err != nil {
		log.Warn(fmt.Sprintf("send scan: %s", safeErr(err)))
		return
	}
	log.Info(fmt.Sprintf("scan posted: status=%s findings=%d", snapshot.Status, len(snapshot.Findings)))
}

// buildSnapshot runs checkMounts and, if it holds, runScan, and turns
// either outcome into a client.Snapshot ready to post. MaskedPaths is
// always the full configured list (hostmask.Paths()), on both a failed
// and an ok snapshot -- issue #108: "present on both ... since the blind
// spot exists either way."
func buildSnapshot(ctx context.Context, version string, now func() time.Time, checkMounts func() error, runScan func(context.Context) (scan.Result, error)) client.Snapshot {
	takenAt := now().UTC()
	maskedPaths := hostmask.Paths()

	if err := checkMounts(); err != nil {
		return client.Snapshot{
			TakenAt:      takenAt,
			AgentVersion: version,
			Status:       scan.StatusFailed,
			Reason:       err.Error(),
			MaskedPaths:  maskedPaths,
		}
	}

	result, err := runScan(ctx)
	if err != nil {
		// Only returned when ctx was already done before grype could
		// even start (scan.Run's own doc comment) -- still a failed
		// scan, never silence.
		return client.Snapshot{
			TakenAt:      takenAt,
			AgentVersion: version,
			Status:       scan.StatusFailed,
			Reason:       err.Error(),
			MaskedPaths:  maskedPaths,
		}
	}

	return snapshotFromResult(takenAt, version, result, maskedPaths)
}

// snapshotFromResult carries internal/scan.Result's fields onto
// client.Snapshot's wire-facing shape -- a field-for-field mirror,
// deliberately duplicated rather than sharing a type: internal/scan is
// fenced to this binary alone (ADR-0009 decision 6) and
// internal/agent/client must never depend on it, matching that
// package's own doc comment on wireScan.
func snapshotFromResult(takenAt time.Time, version string, result scan.Result, maskedPaths []string) client.Snapshot {
	findings := make([]client.Finding, len(result.Findings))
	for i, f := range result.Findings {
		findings[i] = client.Finding{
			Target:        f.Target,
			Package:       f.Package,
			Version:       f.Version,
			Type:          f.Type,
			Vulnerability: f.Vulnerability,
			Severity:      f.Severity,
			FixVersion:    f.FixVersion,
		}
	}
	return client.Snapshot{
		TakenAt:      takenAt,
		AgentVersion: version,
		Engine: client.Engine{
			Name:      result.Engine.Name,
			Version:   result.Engine.Version,
			DBBuiltAt: result.Engine.DBBuiltAt,
		},
		Status:      result.Status,
		Reason:      result.Reason,
		Findings:    findings,
		MaskedPaths: maskedPaths,
	}
}

// checkMounts is issue #108's agent-side host-mount enforcement: read
// this container's own mount table and require every existing mask to
// be covered, and every mount under hostRoot to be read-only
// (internal/hostmask.Check). A non-nil error here means the run command
// was edited and the covering silently lost, or an engine older than
// Docker 25 left a host submount writable underneath the root bind --
// either way, the caller must not scan.
func checkMounts() error {
	f, err := os.Open(mountinfoPath)
	if err != nil {
		return fmt.Errorf("read mountinfo: %s", safeErr(err))
	}
	defer func() { _ = f.Close() }()

	mounts, err := hostmask.ParseMountinfo(f)
	if err != nil {
		return err
	}

	exists := func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	}
	return hostmask.Check(hostRoot, mounts, exists)
}
