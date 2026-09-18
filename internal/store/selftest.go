// Package store: this file mints and matches issue #46's self-test
// commands. It deliberately adds no new table -- a selftest command's
// issued markers are already durable in canary_commands.params (written
// by MintSelfTestCommand, read back once at startup or on first use by
// selfTestIndex) -- and it deliberately keeps the alert path off the
// database entirely: MatchSelfTest runs once per arriving alert, at a
// rate an attacker chooses, so the candidate set it checks must be
// bounded by what's currently live, not by how much self-test history a
// canary has accumulated. #57's audit-log coalescer
// (internal/ingest/auditcoalesce.go) is the same defect class -- caller-
// paced work against an ever-growing table -- fixed the same way: hold
// the bounded, currently-relevant state in memory instead of querying
// per occurrence.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/selftest"
)

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
// markers in the in-memory index MatchSelfTest reads, so a matching alert
// arriving moments later never has to wait on that index's own lazy load.
func MintSelfTestCommand(ctx context.Context, database *db.DB, canaryID, address string, targets []SelfTestTarget, createdAt, expiresAt time.Time) (CanaryCommand, error) {
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
	cmd, err := MintCanaryCommand(ctx, database, canaryID, CommandSelfTest, string(raw), createdAt, expiresAt)
	if err != nil {
		return CanaryCommand{}, err
	}
	// cmd.ExpiresAt, not the caller's expiresAt, is the value actually
	// stored (MintCanaryCommand normalizes to UTC) -- the index's expiry
	// must agree with the row's or the two could disagree about whether a
	// marker is still live.
	indexFor(database).add(canaryID, params.Targets, cmd.ExpiresAt)
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
// the in-memory index (selfTestIndex), loaded from the database at most
// once per *db.DB, and from there on updated only by MintSelfTestCommand
// and by this function's own expiry cleanup. That is what keeps this
// bounded on the alert path -- see this file's package doc comment.
func MatchSelfTest(ctx context.Context, database *db.DB, alert AlertInsert, now time.Time) (bool, error) {
	idx := indexFor(database)
	if err := idx.ensureLoaded(ctx, database); err != nil {
		return false, fmt.Errorf("load selftest index: %w", err)
	}
	return idx.match(alert.InstanceID, alert.Raw, now.UTC()), nil
}

// selfTestIndexes maps a *db.DB to the live-marker index built for it.
// Keyed by the database handle rather than held as one process-wide
// global so tests using forEachEngine -- a fresh *db.DB per subtest, per
// engine -- never see another subtest's markers; production has exactly
// one long-lived *db.DB, so it gets exactly one index for the process'
// life.
var (
	selfTestIndexesMu sync.Mutex
	selfTestIndexes   = map[*db.DB]*selfTestIndex{}
)

// indexFor returns database's index, creating it empty and unloaded on
// first call.
func indexFor(database *db.DB) *selfTestIndex {
	selfTestIndexesMu.Lock()
	defer selfTestIndexesMu.Unlock()
	idx, ok := selfTestIndexes[database]
	if !ok {
		idx = &selfTestIndex{byCanary: make(map[string]map[string]time.Time)}
		selfTestIndexes[database] = idx
	}
	return idx
}

// selfTestIndex is the bounded, in-memory answer to "which markers has
// birdcage issued and not yet seen expire": byCanary[canaryID][marker] is
// that marker's expiry. Nested by canary, rather than one flat
// marker-to-canary map, so a lookup for one canary's alert only ever
// walks that canary's own currently-live markers -- bounded by targets
// per run, not by the size of the fleet or of history.
//
// A canary with no live self-test has no entry in byCanary at all, not
// an empty inner map: match deletes the inner map once it empties, so
// the index's size tracks "canaries with a currently-live self-test",
// which shrinks back down on its own as runs expire.
type selfTestIndex struct {
	mu       sync.Mutex
	loaded   bool
	byCanary map[string]map[string]time.Time
}

// ensureLoaded performs the one-time (per *db.DB) full scan of
// canary_commands that rebuilds byCanary from whatever selftest commands
// were already live when this process started -- the "rebuild once at
// startup, or lazily on first use" this index needs so a restart doesn't
// forget commands minted by a previous run. Already-expired rows are
// discarded here rather than loaded and immediately dropped later.
func (idx *selfTestIndex) ensureLoaded(ctx context.Context, database *db.DB) error {
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
func (idx *selfTestIndex) add(canaryID string, targets []selftest.Target, expiresAt time.Time) {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.addLocked(canaryID, targets, expiresAt)
}

func (idx *selfTestIndex) addLocked(canaryID string, targets []selftest.Target, expiresAt time.Time) {
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
// whole history.
func (idx *selfTestIndex) match(canaryID, raw string, now time.Time) bool {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	markers := idx.byCanary[canaryID]
	found := false
	for marker, expiresAt := range markers {
		if !expiresAt.After(now) {
			delete(markers, marker)
			continue
		}
		if strings.Contains(raw, marker) {
			found = true
		}
	}
	if len(markers) == 0 {
		delete(idx.byCanary, canaryID)
	}
	return found
}
