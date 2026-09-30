package main

import (
	"testing"
	"time"
)

// TestDBRefreshTrackerRecordSuccessClearsFailingSpan proves
// recordSuccess both advances LastOKAt and clears any failing span --
// the "tile may clear" half of ADR-0012 decision 11.
func TestDBRefreshTrackerRecordSuccessClearsFailingSpan(t *testing.T) {
	tracker := newDBRefreshTracker(t.TempDir(), dbRefreshStatus{})
	failAt := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	tracker.recordFailure(failAt, "mirror down")

	okAt := failAt.Add(time.Hour)
	status := tracker.recordSuccess(okAt)
	if !status.LastOKAt.Equal(okAt) {
		t.Errorf("LastOKAt = %v, want %v", status.LastOKAt, okAt)
	}
	if !status.FailingSince.IsZero() {
		t.Errorf("FailingSince = %v, want zero after a success", status.FailingSince)
	}
	if status.LastError != "" {
		t.Errorf("LastError = %q, want empty after a success", status.LastError)
	}
}

// TestDBRefreshTrackerRecordFailureKeepsFirstFailingSince proves
// FailingSince is set only on the first of a run of failures.
func TestDBRefreshTrackerRecordFailureKeepsFirstFailingSince(t *testing.T) {
	tracker := newDBRefreshTracker(t.TempDir(), dbRefreshStatus{})
	first := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	tracker.recordFailure(first, "down 1")

	second := first.Add(time.Hour)
	status := tracker.recordFailure(second, "down 2")
	if !status.FailingSince.Equal(first) {
		t.Errorf("FailingSince = %v, want the first failure's time %v", status.FailingSince, first)
	}
	if status.LastError != "down 2" {
		t.Errorf("LastError = %q, want the latest failure's text", status.LastError)
	}
}

// TestDBRefreshTrackerPersistsAcrossRestart proves ADR-0012 decision
// 10's own requirement -- "persisted in Nightjar's state directory so a
// restart does not forget it" -- for a failing span: a tracker built
// fresh from loadDBRefreshTracker after one recorded a failure sees the
// same FailingSince and error.
func TestDBRefreshTrackerPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	tracker := newDBRefreshTracker(dir, dbRefreshStatus{})
	failAt := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	tracker.recordFailure(failAt, "mirror unreachable")

	reloaded, err := loadDBRefreshTracker(dir)
	if err != nil {
		t.Fatalf("loadDBRefreshTracker: %v", err)
	}
	status := reloaded.get()
	if !status.FailingSince.Equal(failAt) {
		t.Errorf("FailingSince = %v, want %v", status.FailingSince, failAt)
	}
	if status.LastError != "mirror unreachable" {
		t.Errorf("LastError = %q, want %q", status.LastError, "mirror unreachable")
	}
}

// TestDBRefreshTrackerPersistsSuccessAcrossRestart mirrors the above for
// a successful refresh's LastOKAt.
func TestDBRefreshTrackerPersistsSuccessAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	tracker := newDBRefreshTracker(dir, dbRefreshStatus{})
	okAt := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	tracker.recordSuccess(okAt)

	reloaded, err := loadDBRefreshTracker(dir)
	if err != nil {
		t.Fatalf("loadDBRefreshTracker: %v", err)
	}
	status := reloaded.get()
	if !status.LastOKAt.Equal(okAt) {
		t.Errorf("LastOKAt = %v, want %v", status.LastOKAt, okAt)
	}
	if !status.FailingSince.IsZero() {
		t.Errorf("FailingSince = %v, want zero", status.FailingSince)
	}
}

// TestDBRefreshTrackerRestartClearsAfterSuccessFollowsFailure proves a
// success recorded after a failure removes the persisted failing-since
// and error files too, not just the in-memory state -- a fresh load
// after that point must come back healthy.
func TestDBRefreshTrackerRestartClearsAfterSuccessFollowsFailure(t *testing.T) {
	dir := t.TempDir()
	tracker := newDBRefreshTracker(dir, dbRefreshStatus{})
	tracker.recordFailure(time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC), "down")
	tracker.recordSuccess(time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC))

	reloaded, err := loadDBRefreshTracker(dir)
	if err != nil {
		t.Fatalf("loadDBRefreshTracker: %v", err)
	}
	status := reloaded.get()
	if !status.FailingSince.IsZero() {
		t.Errorf("FailingSince = %v, want zero after a restart following a success", status.FailingSince)
	}
	if status.LastError != "" {
		t.Errorf("LastError = %q, want empty", status.LastError)
	}
}

// TestLoadDBRefreshTrackerFreshStateDirIsHealthy proves a first boot,
// with none of the three files present, is not an error and starts
// healthy.
func TestLoadDBRefreshTrackerFreshStateDirIsHealthy(t *testing.T) {
	tracker, err := loadDBRefreshTracker(t.TempDir())
	if err != nil {
		t.Fatalf("loadDBRefreshTracker: %v", err)
	}
	status := tracker.get()
	if !status.LastOKAt.IsZero() || !status.FailingSince.IsZero() || status.LastError != "" {
		t.Errorf("status = %+v, want all zero/empty on a fresh state dir", status)
	}
}

// TestDBRefreshReportIfFailingNilTrackerIsHealthy proves the nil-tracker
// guard sendHeartbeat's doc comment describes.
func TestDBRefreshReportIfFailingNilTrackerIsHealthy(t *testing.T) {
	if got := dbRefreshReportIfFailing(nil); got != nil {
		t.Errorf("dbRefreshReportIfFailing(nil) = %+v, want nil", got)
	}
}

// TestDBRefreshReportIfFailingHealthyTrackerIsNil proves a tracker that
// has never failed (or has since recovered) produces no report --
// "omitted entirely once healthy" (ADR-0012 decision 10).
func TestDBRefreshReportIfFailingHealthyTrackerIsNil(t *testing.T) {
	tracker := newDBRefreshTracker(t.TempDir(), dbRefreshStatus{LastOKAt: time.Now()})
	if got := dbRefreshReportIfFailing(tracker); got != nil {
		t.Errorf("dbRefreshReportIfFailing(healthy) = %+v, want nil", got)
	}
}

// TestDBRefreshReportIfFailingCarriesStatus proves a failing tracker
// produces a report carrying its current status.
func TestDBRefreshReportIfFailingCarriesStatus(t *testing.T) {
	failAt := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	tracker := newDBRefreshTracker(t.TempDir(), dbRefreshStatus{FailingSince: failAt, LastError: "down"})
	got := dbRefreshReportIfFailing(tracker)
	if got == nil {
		t.Fatal("dbRefreshReportIfFailing(failing) = nil, want a report")
	}
	if !got.FailingSince.Equal(failAt) || got.LastError != "down" {
		t.Errorf("report = %+v, want FailingSince %v and LastError %q", got, failAt, "down")
	}
}
