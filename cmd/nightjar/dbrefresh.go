// dbrefresh.go tracks ADR-0012 decision 10's vulnerability-database
// refresh state: the last time `grype db update` succeeded, and -- while
// it is failing -- the first failure since that success and the error
// text, both persisted under the state directory so a restart does not
// forget them ("persisted in Nightjar's state directory so a restart
// does not forget it"). The scan loop updates this after every refresh
// attempt; the heartbeat loop (heartbeat.go) and the stage reporter
// (command.go) both read it to decide whether a heartbeat needs to
// carry a db_refresh object at all.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/atomicfile"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var dbRefreshLog = logging.New("dbrefresh")

// File names inside StateDir for the vulnerability-database refresh
// state -- alongside config.go's own enrolment file names.
const (
	dbRefreshedAtFileName         = "db-refreshed-at"
	dbRefreshFailingSinceFileName = "db-refresh-failing-since"
	dbRefreshErrorFileName        = "db-refresh-error"
)

// dbRefreshStatus is dbRefreshTracker's own snapshot of its state, safe
// to copy and read without the tracker's lock.
type dbRefreshStatus struct {
	// LastOKAt is the last successful refresh's time, the zero time when
	// none has ever succeeded. This is what Snapshot.Engine.DBRefreshedAt
	// carries.
	LastOKAt time.Time
	// FailingSince is the zero time when the last refresh attempt
	// succeeded (or none has run yet), and the first failure's time,
	// unchanged across repeated failures, once one starts failing.
	FailingSince time.Time
	// LastError is the most recent refresh failure's text, empty when
	// FailingSince is zero.
	LastError string
}

// dbRefreshTracker holds the current database-refresh status in memory
// and persists every change to stateDir -- safe for concurrent use, so
// the scan loop (writer), the heartbeat loop and the stage reporter
// (both readers) can all share one instance.
type dbRefreshTracker struct {
	mu       sync.Mutex
	status   dbRefreshStatus
	stateDir string
}

func newDBRefreshTracker(stateDir string, initial dbRefreshStatus) *dbRefreshTracker {
	return &dbRefreshTracker{status: initial, stateDir: stateDir}
}

// loadDBRefreshTracker builds a tracker seeded with whatever a previous
// boot persisted under stateDir. A first boot, with none of the three
// files present yet, is not an error -- the tracker simply starts
// healthy with no known-good refresh, exactly like a fresh state
// directory's own token/certificate files before enrolment.
func loadDBRefreshTracker(stateDir string) (*dbRefreshTracker, error) {
	lastOK, err := readTimeFile(filepath.Join(stateDir, dbRefreshedAtFileName))
	if err != nil {
		return nil, fmt.Errorf("read db-refreshed-at: %s", safeErr(err))
	}
	failingSince, err := readTimeFile(filepath.Join(stateDir, dbRefreshFailingSinceFileName))
	if err != nil {
		return nil, fmt.Errorf("read db-refresh-failing-since: %s", safeErr(err))
	}
	lastErrText, err := readStringFile(filepath.Join(stateDir, dbRefreshErrorFileName))
	if err != nil {
		return nil, fmt.Errorf("read db-refresh-error: %s", safeErr(err))
	}
	return newDBRefreshTracker(stateDir, dbRefreshStatus{
		LastOKAt:     lastOK,
		FailingSince: failingSince,
		LastError:    lastErrText,
	}), nil
}

func (t *dbRefreshTracker) get() dbRefreshStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

// recordSuccess marks a refresh that just succeeded at now: LastOKAt
// advances and any failing span ends -- decision 11's "the tile may
// clear" for this signal, since a success is real evidence the refresh
// road works again.
func (t *dbRefreshTracker) recordSuccess(now time.Time) dbRefreshStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status = dbRefreshStatus{LastOKAt: now}
	t.persistLocked()
	return t.status
}

// recordFailure marks a refresh that just failed at now with errText.
// FailingSince is set only the first time a failure follows a success
// (or a fresh start) -- "first failure since the last success" -- so
// birdcage's 24-hour db_stale comparison is always against the start of
// the current failing span, not the most recent failed attempt.
func (t *dbRefreshTracker) recordFailure(now time.Time, errText string) dbRefreshStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status.FailingSince.IsZero() {
		t.status.FailingSince = now
	}
	t.status.LastError = errText
	t.persistLocked()
	return t.status
}

// persistLocked writes the tracker's current status to stateDir,
// best-effort: a scan already has a real result to post whether or not
// this bookkeeping reaches disk, so a write failure here is logged and
// otherwise ignored -- the next successful persist corrects any gap.
// Must be called with mu held.
func (t *dbRefreshTracker) persistLocked() {
	if t.stateDir == "" {
		return
	}
	if err := writeOrRemoveTimeFile(filepath.Join(t.stateDir, dbRefreshedAtFileName), t.status.LastOKAt); err != nil {
		dbRefreshLog.Warn(fmt.Sprintf("persist db-refreshed-at: %s", safeErr(err)))
	}
	if err := writeOrRemoveTimeFile(filepath.Join(t.stateDir, dbRefreshFailingSinceFileName), t.status.FailingSince); err != nil {
		dbRefreshLog.Warn(fmt.Sprintf("persist db-refresh-failing-since: %s", safeErr(err)))
	}
	if err := writeOrRemoveStringFile(filepath.Join(t.stateDir, dbRefreshErrorFileName), t.status.LastError); err != nil {
		dbRefreshLog.Warn(fmt.Sprintf("persist db-refresh-error: %s", safeErr(err)))
	}
}

// readTimeFile reads an RFC3339Nano timestamp from path, returning the
// zero time (not an error) when path does not exist -- "no known value
// yet" is an ordinary state for a fresh state directory.
func readTimeFile(path string) (time.Time, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse timestamp: %w", err)
	}
	return parsed, nil
}

// readStringFile reads path's trimmed contents, returning "" (not an
// error) when path does not exist.
func readStringFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// writeOrRemoveTimeFile writes t (RFC3339Nano) to path, or removes path
// entirely when t is the zero time -- "no known value" is represented by
// the file's absence, never an empty file, so readTimeFile's caller
// never has to distinguish "empty" from "zero" on the next boot.
func writeOrRemoveTimeFile(path string, t time.Time) error {
	if t.IsZero() {
		return removeIfExists(path)
	}
	return atomicfile.Write(path, []byte(t.UTC().Format(time.RFC3339Nano)), 0o600)
}

// writeOrRemoveStringFile mirrors writeOrRemoveTimeFile for a plain
// string value, empty meaning "remove".
func writeOrRemoveStringFile(path, s string) error {
	if s == "" {
		return removeIfExists(path)
	}
	return atomicfile.Write(path, []byte(s), 0o600)
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
