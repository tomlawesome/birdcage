// Package store: this file mints and matches issue #46's self-test
// commands. It deliberately adds no new table -- a selftest command's
// issued markers are already durable in canary_commands.params (written
// by MintSelfTestCommand, read back once at startup or on first use by
// SelfTestIndex) -- and it deliberately keeps the alert path off the
// database entirely: MatchSelfTest runs once per arriving alert, at a
// rate an attacker chooses, so the candidate set it checks must be
// bounded by what's currently live, not by how much self-test history a
// canary has accumulated. #57's audit-log coalescer
// (internal/ingest/auditcoalesce.go) is the same defect class -- caller-
// paced work against an ever-growing table -- fixed the same way: hold
// the bounded, currently-relevant state in memory instead of querying
// per occurrence. And, like that coalescer and internal/ingest's
// limiterRegistry, the state is owned by whoever constructs it and
// passed explicitly to what needs it, not kept in a package-level
// registry keyed on pointer identity.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/selftest"
)

// markerHash returns the sha256 hex digest of marker -- what
// self_test_targets.marker_hash stores, per that migration's own doc
// comment: the marker itself is never stored a second time outside
// canary_commands.params, so a reader of this table alone learns
// nothing an attacker could replay.
func markerHash(marker string) string {
	sum := sha256.Sum256([]byte(marker))
	return hex.EncodeToString(sum[:])
}

// SelfTestTarget is what MintSelfTestCommand needs from a caller to plant
// one probe: which service, on which port. The marker itself is never a
// caller input -- see MintSelfTestCommand -- because a marker a caller
// could choose or observe in advance is a marker an attacker could guess.
type SelfTestTarget struct {
	Service  string
	DestPort int
}

// MintSelfTestCommand builds one selftest.Params for canaryID -- a fresh
// crypto/rand marker per target, never reused, never derived from
// anything predictable (#46 settled decision 4: a guessable marker would
// let an attacker's own traffic be classified as a test and so kept off
// the dashboard, which inverts the product) -- queues it through
// MintCanaryCommand, the one door into canary_commands, and registers its
// markers in idx, so a matching alert arriving moments later finds it
// without waiting on idx's own lazy load.
// MintSelfTestCommand mints the canary_commands row, the owning
// self_test_runs row and one self_test_targets row per target, all in
// one transaction (issue #46 item 4: "MintSelfTestCommand writes both
// (same transaction as the command)") -- a caller never sees a command
// with no run/target bookkeeping to match against, and a failure at any
// point rolls the whole mint back rather than leaving a command queued
// for an agent that birdcage itself can never resolve.
// HasRecentSelfTestRun reports whether canaryID has a self_test_runs row
// issued at or after since -- internal/selftestsched's double-mint guard
// (issue #46 item 5b: "never mint twice in the same minute for the same
// canary"), shared by both the per-minute tick and the rotation-coupled
// hook so neither path can race the other into minting twice.
func HasRecentSelfTestRun(ctx context.Context, database *db.DB, canaryID string, since time.Time) (bool, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*) FROM self_test_runs WHERE canary_id = ? AND %s`,
		timeCompare(database.Engine, "issued_at", ">="))
	var n int
	if err := database.QueryRowContext(ctx, query, canaryID, since.UTC().Format(receivedAtLayout)).Scan(&n); err != nil {
		return false, fmt.Errorf("count recent self_test_runs for %s: %w", canaryID, err)
	}
	return n > 0, nil
}

func MintSelfTestCommand(ctx context.Context, database *db.DB, idx *SelfTestIndex, canaryID, address string, targets []SelfTestTarget, createdAt, expiresAt time.Time) (CanaryCommand, error) {
	if len(targets) == 0 {
		return CanaryCommand{}, selftest.ErrNoTargets
	}
	runID, err := randomHex(commandIDBytes)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("generate selftest run id: %w", err)
	}
	params := selftest.Params{
		RunID:   runID,
		Address: address,
		Targets: make([]selftest.Target, len(targets)),
	}
	for i, tgt := range targets {
		// selftest.MarkerBytes of crypto/rand entropy, hex-encoded --
		// randomHex is the same primitive canary_tokens and
		// canary_commands ids already trust for unguessable values.
		marker, err := randomHex(selftest.MarkerBytes)
		if err != nil {
			return CanaryCommand{}, fmt.Errorf("generate selftest marker: %w", err)
		}
		params.Targets[i] = selftest.Target{
			Service:  tgt.Service,
			DestPort: tgt.DestPort,
			Marker:   marker,
		}
	}
	if err := params.Validate(); err != nil {
		// selftest.Validate is the wire contract's own gate; failing it
		// here is this function's bug (e.g. a caller-supplied empty
		// Service), not a condition worth minting a command the agent
		// will just refuse.
		return CanaryCommand{}, fmt.Errorf("selftest: built invalid params: %w", err)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("marshal selftest params: %w", err)
	}

	tx, err := database.Begin(ctx)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("begin selftest mint transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = tx.Rollback() // best-effort; the error already returned above stands regardless
	}()

	cmd, err := MintCanaryCommand(ctx, tx, canaryID, CommandSelfTest, string(raw), createdAt, expiresAt)
	if err != nil {
		return CanaryCommand{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO self_test_runs (command_id, canary_id, run_id, issued_at, deadline_at)
		VALUES (?, ?, ?, ?, ?)`,
		cmd.ID, canaryID, runID, cmd.CreatedAt.Format(receivedAtLayout), cmd.ExpiresAt.Format(receivedAtLayout)); err != nil {
		return CanaryCommand{}, fmt.Errorf("insert self_test_runs: %w", err)
	}

	for _, tgt := range params.Targets {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO self_test_targets (command_id, service, dest_port, marker_hash, grade)
			VALUES (?, ?, ?, ?, ?)`,
			cmd.ID, tgt.Service, tgt.DestPort, markerHash(tgt.Marker), string(gradeForService(tgt.Service))); err != nil {
			return CanaryCommand{}, fmt.Errorf("insert self_test_targets: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return CanaryCommand{}, fmt.Errorf("commit selftest mint transaction: %w", err)
	}
	committed = true

	// cmd.ExpiresAt, not the caller's expiresAt, is the value actually
	// stored (MintCanaryCommand normalizes to UTC) -- idx's expiry must
	// agree with the row's or the two could disagree about whether a
	// marker is still live.
	idx.add(canaryID, params.Targets, cmd.ExpiresAt)
	return cmd, nil
}

// MatchSelfTest decides whether alert is a hit birdcage's own self-test
// planted, never whether it merely looks like one. This is #46's whole
// security property: "anything test-shaped that does not match an issued
// command is a real alert, not a test", so every unmatched, unparseable
// or doubtful path here returns false -- fail closed, same as
// selftest.DecodeParams does on the wire.
//
// It never queries canary_commands itself: the candidate set comes from
// idx, loaded from the database at most once for idx's lifetime, and
// from there on updated only by MintSelfTestCommand and by this
// function's own expiry cleanup. That is what keeps this bounded on the
// alert path -- see this file's package doc comment.
func MatchSelfTest(ctx context.Context, database *db.DB, idx *SelfTestIndex, alert AlertInsert, now time.Time) (bool, error) {
	if err := idx.ensureLoaded(ctx, database); err != nil {
		return false, fmt.Errorf("load selftest index: %w", err)
	}
	matched, marker := idx.match(alert.InstanceID, alert.Raw, now.UTC())
	if !matched && alert.Service == "vnc" {
		// Challenge-marked grade (#46 slice 2, notes 19854/19855/19897):
		// vnc's carrier never puts the marker in raw where idx.match's
		// substring check could find it -- see selftest_vnc.go's own
		// doc comment for why a challenge-response verification is a
		// different check, not a variant of the same one.
		matched, marker = idx.matchVNCChallenge(alert.InstanceID, alert.Raw, now.UTC())
	}
	if !matched {
		return false, nil
	}
	// Record the hit against self_test_targets/self_test_runs (issue
	// #46 item 4) now that idx has already made the security decision
	// in memory -- a failure here still returns an error, per this
	// function's caller (internal/ingest/batch.go): "on any error from
	// MatchSelfTest: log, store the alert as real, continue. Never
	// drop." That is a deliberately conservative choice: a self-test
	// birdcage cannot finish recording is treated the same as one it
	// never issued, rather than trusting the in-memory match alone.
	if err := recordSelfTestMatch(ctx, database, markerHash(marker), now.UTC()); err != nil {
		return false, fmt.Errorf("record selftest match: %w", err)
	}
	return true, nil
}

// recordSelfTestMatch sets self_test_targets.matched_at for the target
// hash identifies, then -- if every target of that target's run is now
// matched -- marks the owning self_test_runs row completed_at/passed=1.
// Idempotent: a duplicate event carrying the same marker (retried by the
// agent, or the same raw payload seen twice) updates zero rows on its
// second pass (the "AND matched_at IS NULL" guard) and this function
// simply returns without touching self_test_runs again.
func recordSelfTestMatch(ctx context.Context, database *db.DB, hash string, now time.Time) error {
	var commandID string
	err := database.QueryRowContext(ctx, `
		SELECT command_id FROM self_test_targets WHERE marker_hash = ? AND matched_at IS NULL`, hash).Scan(&commandID)
	if errors.Is(err, sql.ErrNoRows) {
		// Either this marker already matched (a duplicate/retried
		// event -- see doc comment above) or, in principle, a hash
		// collision with nothing this package ever minted; either way
		// there is nothing left to record.
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up self_test_targets by marker hash: %w", err)
	}

	nowStr := now.Format(receivedAtLayout)
	res, err := database.ExecContext(ctx, `
		UPDATE self_test_targets SET matched_at = ?
		WHERE marker_hash = ? AND matched_at IS NULL`, nowStr, hash)
	if err != nil {
		return fmt.Errorf("update self_test_targets: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		// Lost a race with another concurrent match on the same
		// marker (should never happen -- markers are per-target and
		// unique -- but the guard is the same belt-and-braces the rest
		// of this package's claim/update statements use).
		return nil
	}

	var remaining int64
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM self_test_targets WHERE command_id = ? AND matched_at IS NULL`, commandID).Scan(&remaining); err != nil {
		return fmt.Errorf("count unmatched self_test_targets: %w", err)
	}
	if remaining > 0 {
		return nil
	}
	if _, err := database.ExecContext(ctx, `
		UPDATE self_test_runs SET completed_at = ?, passed = 1
		WHERE command_id = ? AND completed_at IS NULL`, nowStr, commandID); err != nil {
		return fmt.Errorf("mark self_test_runs passed: %w", err)
	}
	if err := settlePendingForCommand(ctx, database, commandID, now); err != nil { // issue #47 step 9
		return fmt.Errorf("settle pending canary: %w", err)
	}
	return nil
}

// SweepExpiredSelfTestRuns marks every run past its deadline_at with
// completed_at still NULL as completed and failed (issue #46 item 5d):
// a canary that never finishes answering every target is exactly as
// bad as one that answers none, so a run birdcage stops waiting on must
// resolve to passed=false, not linger "still running" forever. Returns
// how many runs it swept, for the scheduler's own log line.
//
// This does not resolve attributed-grade targets (ntp, portscan): note
// 19897's ratified design has the agent claim an attributed event
// before it ever leaves the container, so it arrives at birdcage
// already synthetic -- there is nothing here for the deadline sweep to
// do for that grade. That agent-side claim depends on #47's wire and
// sender changes and is not built yet (#46 slice 3); until it lands, an
// attributed target simply stays unmatched and its run fails, the same
// as any other target that never answers.
func SweepExpiredSelfTestRuns(ctx context.Context, database *db.DB, now time.Time) (int, error) {
	query := fmt.Sprintf(`
		UPDATE self_test_runs SET completed_at = ?, passed = 0
		WHERE completed_at IS NULL AND %s`,
		timeCompare(database.Engine, "deadline_at", "<="))
	res, err := database.ExecContext(ctx, query, now.UTC().Format(receivedAtLayout), now.UTC().Format(receivedAtLayout))
	if err != nil {
		return 0, fmt.Errorf("sweep expired selftest runs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	return int(n), nil
}

// SelfTestRun is one self_test_runs row, as read back by
// applySelfTestState (health.go's StateTestFailed) and
// internal/selftestsched's double-mint guard.
type SelfTestRun struct {
	CommandID   string
	CanaryID    string
	RunID       string
	IssuedAt    time.Time
	DeadlineAt  time.Time
	CompletedAt *time.Time
	Passed      *bool
}

// LatestCompletedSelfTestRun returns canaryID's most recently completed
// self-test run (by completed_at), or ok=false when none has ever
// completed. Loaded and compared in Go rather than by an SQL ORDER BY on
// the TEXT completed_at column, for the same trimmed-fractional-second
// reason timeCompare's own doc comment gives -- one canary's self-test
// history is small (at most a handful a day), so loading it whole here
// costs nothing worth avoiding.
func LatestCompletedSelfTestRun(ctx context.Context, database *db.DB, canaryID string) (run SelfTestRun, ok bool, err error) {
	rows, err := database.QueryContext(ctx, `
		SELECT command_id, canary_id, run_id, issued_at, deadline_at, completed_at, passed
		FROM self_test_runs WHERE canary_id = ? AND completed_at IS NOT NULL`, canaryID)
	if err != nil {
		return SelfTestRun{}, false, fmt.Errorf("query self_test_runs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var latest *SelfTestRun
	for rows.Next() {
		r, err := scanSelfTestRun(rows)
		if err != nil {
			return SelfTestRun{}, false, err
		}
		if latest == nil || r.CompletedAt.After(*latest.CompletedAt) {
			cp := r
			latest = &cp
		}
	}
	if err := rows.Err(); err != nil {
		return SelfTestRun{}, false, fmt.Errorf("iterate self_test_runs: %w", err)
	}
	if latest == nil {
		return SelfTestRun{}, false, nil
	}
	return *latest, true, nil
}

// scanSelfTestRun reads one self_test_runs row selected in the exact
// column order LatestCompletedSelfTestRun's query uses.
func scanSelfTestRun(row rowScanner) (SelfTestRun, error) {
	var (
		r           SelfTestRun
		issuedAt    string
		deadlineAt  string
		completedAt *string
		passed      *int64
	)
	if err := row.Scan(&r.CommandID, &r.CanaryID, &r.RunID, &issuedAt, &deadlineAt, &completedAt, &passed); err != nil {
		return SelfTestRun{}, fmt.Errorf("scan self_test_run: %w", err)
	}
	var err error
	if r.IssuedAt, err = time.Parse(receivedAtLayout, issuedAt); err != nil {
		return SelfTestRun{}, fmt.Errorf("parse issued_at %q: %w", issuedAt, err)
	}
	if r.DeadlineAt, err = time.Parse(receivedAtLayout, deadlineAt); err != nil {
		return SelfTestRun{}, fmt.Errorf("parse deadline_at %q: %w", deadlineAt, err)
	}
	if completedAt != nil {
		t, err := time.Parse(receivedAtLayout, *completedAt)
		if err != nil {
			return SelfTestRun{}, fmt.Errorf("parse completed_at %q: %w", *completedAt, err)
		}
		r.CompletedAt = &t
	}
	if passed != nil {
		p := *passed != 0
		r.Passed = &p
	}
	return r, nil
}

// SelfTestTargetsUnmatched returns "service dest_port" strings (e.g.
// "ssh 22") for every target of commandID that never matched, ordered by
// service then dest_port for a deterministic display -- health.go's
// SelfTestFailedServices and the canary detail page's own failure line
// (issue #46 item 6).
func SelfTestTargetsUnmatched(ctx context.Context, database *db.DB, commandID string) ([]string, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT service, dest_port FROM self_test_targets
		WHERE command_id = ? AND matched_at IS NULL
		ORDER BY service, dest_port`, commandID)
	if err != nil {
		return nil, fmt.Errorf("query unmatched self_test_targets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var (
			service string
			port    int
		)
		if err := rows.Scan(&service, &port); err != nil {
			return nil, fmt.Errorf("scan unmatched self_test_target: %w", err)
		}
		out = append(out, fmt.Sprintf("%s %d", service, port))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unmatched self_test_targets: %w", err)
	}
	return out, nil
}

// applySelfTestState fills c.LastSelfTestAt, c.LastSelfTestPassed and
// (when the run failed) c.SelfTestFailedServices from canaryID's most
// recently completed self-test run, and reports whether c should carry
// StateTestFailed -- ListCanaries' own per-canary self-test section
// (issue #46 item 6). A canary with no completed run at all reports
// false ("never run" is not a failure).
func applySelfTestState(ctx context.Context, database *db.DB, c *Canary) (testFailed bool, err error) {
	run, ok, err := LatestCompletedSelfTestRun(ctx, database, c.ID)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	c.LastSelfTestAt = run.CompletedAt
	c.LastSelfTestPassed = run.Passed
	if run.Passed == nil || *run.Passed {
		return false, nil
	}
	failed, err := SelfTestTargetsUnmatched(ctx, database, run.CommandID)
	if err != nil {
		return false, err
	}
	c.SelfTestFailedServices = failed
	return true, nil
}

// SelfTestIndex is the bounded, in-memory index of markers birdcage has
// issued and not yet seen expire: byCanary[canaryID][marker] is that
// marker's expiry. Nested by canary, rather than one flat
// marker-to-canary map, so a lookup for one canary's alert only ever
// walks that canary's own currently-live markers -- bounded by targets
// per run, not by the size of the fleet or of history.
//
// Constructed once by whatever owns the ingest path's dependencies --
// mirroring auditCoalescer and limiterRegistry in internal/ingest, both
// built once and held as fields, never a process-wide registry keyed on
// a *db.DB pointer -- and passed explicitly to MintSelfTestCommand and
// MatchSelfTest.
//
// A canary with no live self-test has no entry in byCanary at all, not
// an empty inner map: match deletes the inner map once it empties, so
// the index's size tracks "canaries with a currently-live self-test",
// which shrinks back down on its own as runs expire.
type SelfTestIndex struct {
	mu       sync.Mutex
	loaded   bool
	byCanary map[string]map[string]time.Time
}

// NewSelfTestIndex returns an empty, unloaded index.
func NewSelfTestIndex() *SelfTestIndex {
	return &SelfTestIndex{byCanary: make(map[string]map[string]time.Time)}
}

// ensureLoaded performs the one-time (per index) full scan of
// canary_commands that rebuilds byCanary from whatever selftest commands
// were already live when this process started -- the "rebuild once at
// startup, or lazily on first use" this index needs so a restart doesn't
// forget commands minted by a previous run. Already-expired rows are
// discarded here rather than loaded and immediately dropped later.
func (idx *SelfTestIndex) ensureLoaded(ctx context.Context, database *db.DB) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	if idx.loaded {
		return nil
	}
	now := time.Now().UTC()
	rows, err := database.QueryContext(ctx, `
		SELECT canary_id, params, expires_at
		FROM canary_commands
		WHERE kind = ?`, string(CommandSelfTest))
	if err != nil {
		return fmt.Errorf("query selftest commands: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			canaryID     string
			params       sql.NullString
			expiresAtStr string
		)
		if err := rows.Scan(&canaryID, &params, &expiresAtStr); err != nil {
			return fmt.Errorf("scan selftest command: %w", err)
		}
		if !params.Valid {
			continue
		}
		// Expiry is judged here in Go on parsed RFC3339Nano, never in
		// SQL -- ClaimNextCanaryCommand's own doc comment has the
		// trimmed-fractional-second trap this avoids.
		expiresAt, err := time.Parse(receivedAtLayout, expiresAtStr)
		if err != nil {
			continue // a row this package itself wrote should always parse; skip rather than fail the whole load
		}
		if !expiresAt.After(now) {
			continue // already dead: never worth holding in memory
		}
		p, err := selftest.DecodeParams(json.RawMessage(params.String))
		if err != nil {
			continue // corrupt row; fail closed the same way MatchSelfTest itself does
		}
		idx.addLocked(canaryID, p.Targets, expiresAt)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate selftest commands: %w", err)
	}
	idx.loaded = true
	return nil
}

// add registers one run's markers -- called by MintSelfTestCommand
// immediately after the command is durably stored, so a matching alert
// arriving before ensureLoaded's first run still finds it.
func (idx *SelfTestIndex) add(canaryID string, targets []selftest.Target, expiresAt time.Time) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.addLocked(canaryID, targets, expiresAt)
}

func (idx *SelfTestIndex) addLocked(canaryID string, targets []selftest.Target, expiresAt time.Time) {
	m := idx.byCanary[canaryID]
	if m == nil {
		m = make(map[string]time.Time)
		idx.byCanary[canaryID] = m
	}
	for _, tgt := range targets {
		m[tgt.Marker] = expiresAt
	}
}

// match reports whether raw contains any of canaryID's still-live
// markers as of now, dropping every expired one it passes along the way
// -- the index's only pruning, and enough on its own: a canary that
// keeps self-testing keeps visiting its own bucket and keeps it small,
// and one that stops leaves behind only its last run's targets, not its
// whole history. When found is true, marker is the matched value itself
// (issue #46 item 3/4), so MatchSelfTest can hash it and record which
// self_test_targets row to mark matched_at on.
func (idx *SelfTestIndex) match(canaryID, raw string, now time.Time) (found bool, marker string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	markers := idx.byCanary[canaryID]
	for m, expiresAt := range markers {
		if !expiresAt.After(now) {
			delete(markers, m)
			continue
		}
		if strings.Contains(raw, m) {
			found = true
			marker = m
		}
	}
	if len(markers) == 0 {
		delete(idx.byCanary, canaryID)
	}
	return found, marker
}
