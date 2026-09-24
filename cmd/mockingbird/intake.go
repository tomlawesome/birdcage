package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/event"
	"github.com/tomlawesome/birdcage/internal/agent/ledger"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
	"github.com/tomlawesome/birdcage/internal/agent/receiver"
	"github.com/tomlawesome/birdcage/internal/agent/tailer"
	"github.com/tomlawesome/birdcage/internal/logging"
	"github.com/tomlawesome/birdcage/internal/opencanary"
)

var intakeLog = logging.New("intake")

// Backpressure numbers from #48's process-composition note, decision 2,
// all marked [contested] there -- documented, tunable implementation
// choices per docs/security-by-design.md, not settled facts.
const (
	// lowWaterNumerator/lowWaterDenominator express the low-water mark
	// the tailer's intake gate releases at, as a fraction of queue
	// capacity: "blocks ... until depth falls below the low-water mark
	// (3/4 capacity [contested])." A fraction rather than a fixed count
	// so it scales with whatever MaxEvents a caller configures.
	lowWaterNumerator   = 3
	lowWaterDenominator = 4

	// backpressurePollInterval is how often a blocked tailer intake gate
	// rechecks queue depth. Short enough that the tailer resumes
	// promptly once the sender drains room, long enough not to spin.
	backpressurePollInterval = 100 * time.Millisecond

	// restartCheckInterval is how often runLogRoadOnce checks whether an
	// eviction has occurred and the queue has since drained enough to
	// justify restarting tailer.Follow (#48 decision 2: "Recovery
	// without a restart").
	restartCheckInterval = 250 * time.Millisecond
)

// IntakeConfig configures a fresh Intake. Zero-valued Queue fields get
// queue.NewMemQueue's own defaults (queue.DefaultMaxEvents /
// DefaultMaxQueueBytes); LowWaterNumerator/Denominator default to 3/4
// when Denominator is left at zero. Tests pass a small Queue.MaxEvents
// so backpressure is reachable without pushing thousands of events.
type IntakeConfig struct {
	LogPath      string
	PositionPath string
	Listen       string

	Queue                                  queue.Config
	Tailer                                 tailer.Config
	LowWaterNumerator, LowWaterDenominator int
}

// Intake owns both of #48's intake roads (the webhook receiver and the
// log tailer) and the shared queue, ledger and acknowledged-position
// state they feed -- #48's process-composition note, "the process at a
// glance": "receiver.Serve webhook road: body -> id -> queue.Push" and
// "tailer.Follow log road: line -> id -> ledger record -> queue.Push".
//
// The ledger is held behind an atomic pointer rather than a fixed field
// because it is rebuilt from scratch on every (re)start of the log
// road, process start or eviction-triggered restart alike (decision 3:
// "On re-read recovery the ledger is rebuilt from scratch"), so nothing
// that reads it -- the sender, the heartbeat -- can hold a reference
// across a restart.
type Intake struct {
	Queue    *queue.MemQueue
	Receiver *receiver.Receiver

	tailer   *tailer.Tailer
	posStore *queue.PositionStore

	maxEvents int
	lowWater  int

	ledgerPtr      atomic.Pointer[ledger.Ledger]
	collisionsBase atomic.Uint64 // sum of Collisions() from every discarded ledger

	lastEventID atomic.Pointer[string]

	// claims is #46 slice 3's attributed-grade claim window (claim.go):
	// every road that pushes an event notes it here first (see
	// observeClaim below), so the sender can tell a still-undecided
	// candidate apart from an ordinary event before it ever ships.
	claims *claimTracker
}

// NewIntake builds the queue, tailer and webhook receiver from cfg, and
// binds the receiver's loopback listener. It does not start anything --
// call Run for the log road and let the caller Serve the receiver, the
// same "construct, then start" split every other loop in this binary
// follows.
func NewIntake(cfg IntakeConfig) (*Intake, error) {
	if cfg.Queue.MaxEvents <= 0 {
		cfg.Queue.MaxEvents = queue.DefaultMaxEvents
	}
	if cfg.Queue.MaxBytes <= 0 {
		cfg.Queue.MaxBytes = queue.DefaultMaxQueueBytes
	}
	num, den := cfg.LowWaterNumerator, cfg.LowWaterDenominator
	if den == 0 {
		num, den = lowWaterNumerator, lowWaterDenominator
	}

	in := &Intake{
		Queue:     queue.NewMemQueue(cfg.Queue),
		tailer:    tailer.New(cfg.LogPath, cfg.Tailer),
		posStore:  queue.NewPositionStore(cfg.PositionPath),
		maxEvents: cfg.Queue.MaxEvents,
		lowWater:  cfg.Queue.MaxEvents * num / den,
		claims:    newClaimTracker(),
	}
	// A placeholder ledger so LastEventID/Collisions/heartbeat callers
	// never see a nil pointer before runLogRoad's first real one is in
	// place -- New(0) costs nothing (an empty Ledger) and is replaced on
	// the first iteration of runLogRoadOnce.
	in.ledgerPtr.Store(ledger.New(0))

	recv, err := receiver.New(receiver.Config{Addr: cfg.Listen}, in.webhookHandler)
	if err != nil {
		return nil, err
	}
	in.Receiver = recv
	return in, nil
}

// webhookHandler is the receiver.Handler for the webhook road (#48,
// "What it does" #1). It computes the event id, queues it, and returns
// -- never blocking on backpressure the way the log road's emit does,
// since "Never blocks OpenCanary" applies here without exception; the
// receiver's own HandlerTimeout is this function's only real bound.
// Webhook-road events never get a ledger entry (decision 3): only the
// log road advances the acknowledged position.
func (in *Intake) webhookHandler(body []byte) error {
	id, message, err := event.IDFromWebhookBody(body)
	if err != nil {
		return err
	}
	in.observeClaim(id, message)
	in.Queue.Push(queue.Event{ID: id, Payload: message})
	return nil
}

// observeClaim hands (id, the fields decoded from message) to the claim
// tracker (#46 slice 3, claim.go) before the event is queued, so a
// candidate for a currently open attributed-grade window is on record
// before the sender's next Peek could possibly reach it. A no-op --
// including the ExtractFields decode itself -- whenever no window is
// open, which is every moment outside the few seconds around a daily
// self-test: claims.active() is one mutex lock and a length check,
// cheaper than decoding JSON on every ordinary event this agent forwards.
func (in *Intake) observeClaim(id string, message []byte) {
	if !in.claims.active() {
		return
	}
	fields, err := event.ExtractFields(message)
	if err != nil {
		// Not decodable as the fields ExtractFields wants: cannot be a
		// candidate for anything (the two attributed carriers' own
		// events always are), so there is nothing to observe.
		return
	}
	in.claims.observe(id, fields.Service, fields.SourceIP)
}

// SubmitPortscanEvent is the third road into the queue (#65): a port
// scan this agent detected itself, from the raw capture socket in
// internal/agent/portscan, rather than one OpenCanary reported.
//
// It mints the id exactly as the webhook road does -- SHA-256 of the
// emitted bytes, verbatim, never re-serialised -- so an id computed here
// is the same kind of value, in the same format, as one computed on
// either of the other two roads, and Push's deduplication works across
// all three without knowing which produced a given event.
//
// Like the webhook road, and unlike the log road, it appends no ledger
// entry (#48 decision 3: "only the log road advances the acknowledged
// position"). The ledger maps event ids to positions in OpenCanary's log
// file; this event was never in that file, so it has no position to
// record, and giving it one would stall the acknowledged frontier on an
// entry that can never resolve.
func (in *Intake) SubmitPortscanEvent(message []byte) error {
	id, err := event.IDFromEmittedMessage(message)
	if err != nil {
		return err
	}
	in.observeClaim(id, message)
	in.Queue.Push(queue.Event{ID: id, Payload: message})
	return nil
}

// SubmitSNMPEvent is the fourth road into the queue (#88): an SNMP
// v1/v2c request internal/agent/snmp read and decoded itself, rather
// than one OpenCanary reported -- its own snmp module stays disabled
// (build/mockingbird/opencanary.conf, "snmp.enabled": false) because it
// needs scapy, which #85 keeps out of this image.
//
// Same id scheme as the webhook and port-scan roads -- SHA-256 of the
// emitted bytes, verbatim -- so Push's deduplication works across all
// four roads without knowing which produced a given event. Like the
// port-scan road, it appends no ledger entry: this event was never a
// line in OpenCanary's log file, so it has no log position to record.
func (in *Intake) SubmitSNMPEvent(message []byte) error {
	id, err := event.IDFromEmittedMessage(message)
	if err != nil {
		return err
	}
	in.Queue.Push(queue.Event{ID: id, Payload: message})
	return nil
}

// SubmitSMBEvent is the fifth road into the queue (#87): a line the SMB
// lure wrote into the audit file it shares with this container, read by
// the tailer in smbaudit.go and parsed by internal/agent/smbaudit.
// OpenCanary's own smb module stays disabled -- docs/opencanary.md's
// table records why -- so, like the port-scan and snmp roads, this is our
// own reader and not a wrapper around theirs.
//
// Same id scheme as every other road: SHA-256 of the emitted bytes,
// verbatim. Those bytes are derived only from the audit line (see
// smbaudit.Encode, which takes no clock), so re-reading a line -- which
// is exactly what happens when the process restarts before its saved
// position caught up -- mints the same id and Push drops the second copy.
//
// Unlike the port-scan and snmp roads, and like the log road, this one
// waits for queue room before pushing: the audit file is a durable store
// that will still hold the line in a moment, so blocking costs nothing
// and dropping would cost the event. It appends no ledger entry, because
// the ledger tracks positions in OpenCanary's log file and this line was
// never in it; the audit file's own position is kept by smbaudit.go.
func (in *Intake) SubmitSMBEvent(ctx context.Context, message []byte) error {
	if err := in.waitForRoom(ctx); err != nil {
		return err
	}
	id, err := event.IDFromEmittedMessage(message)
	if err != nil {
		return err
	}
	in.Queue.Push(queue.Event{ID: id, Payload: message})
	return nil
}

// RunLogRoad runs the log road until ctx is done: load the saved
// position, run a fresh ledger and a fresh tailer.Follow session, and
// -- per #48 decision 2's "Recovery without a restart" -- restart that
// whole session, fresh ledger included, whenever an eviction has
// occurred and the queue has since drained under the low-water mark.
func (in *Intake) RunLogRoad(ctx context.Context) {
	for ctx.Err() == nil {
		in.runLogRoadOnce(ctx)
	}
}

// runLogRoadOnce runs one tailer.Follow session to completion: either
// ctx (the whole agent's shutdown) ends it, or this function's own
// eviction-drain monitor decides to restart it.
func (in *Intake) runLogRoadOnce(ctx context.Context) {
	pos, hasResume, err := in.posStore.Load()
	if err != nil {
		// safeErr: PositionStore.Load's own error wraps the position
		// file's path, which lives inside StateDir -- one of the values
		// this agent must never log (see safelog.go).
		intakeLog.Warn(fmt.Sprintf("load saved position failed, replaying the log from the start: %s", safeErr(err)))
		hasResume = false
	}

	// #48 decision 3: "On re-read recovery the ledger is rebuilt from
	// scratch" -- otherwise Append would mistake re-reading the same
	// physical line (because we restarted) for a genuine same-id-at-
	// two-log-positions collision. The discarded ledger's own count is
	// folded into collisionsBase first, so Collisions() stays a true
	// cumulative total across restarts rather than resetting to zero.
	if prev := in.ledgerPtr.Load(); prev != nil {
		in.collisionsBase.Add(prev.Collisions())
	}
	ldg := ledger.New(ledger.DefaultCollisionWindow)
	in.ledgerPtr.Store(ldg)

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	emit := func(line tailer.Line) { in.handleLogLine(sessionCtx, ldg, line) }

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := in.tailer.Follow(sessionCtx, pos, hasResume, emit); err != nil && sessionCtx.Err() == nil {
			// safeErr: a tailer.Follow error can wrap LogPath, which
			// this agent must never log (see safelog.go).
			intakeLog.Warn(fmt.Sprintf("tailer.Follow returned unexpectedly: %s", safeErr(err)))
		}
	}()

	baseline := in.Queue.Dropped()
	ticker := time.NewTicker(restartCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			cancel()
			<-done
			return
		case <-done:
			// Follow ended on its own -- today that only happens via
			// sessionCtx cancellation (ctx.Done above), since the
			// tailer's own setup never returns a non-nil error; RunLogRoad's
			// loop covers a future change to that without this function
			// needing to know about it.
			return
		case <-ticker.C:
			if in.Queue.Dropped() != baseline && in.Queue.Depth() <= in.lowWater {
				// #48 decision 2: an evicted event's ledger entry never
				// resolves, stalling the frontier at or before it; the
				// only way to recover it is to re-read the log from the
				// saved position, which the acknowledged frontier still
				// points at. Restarting is exactly re-running this same
				// function.
				cancel()
				<-done
				return
			}
		}
	}
}

// handleLogLine is the log road's emit callback (#48: "line -> id ->
// ledger record -> queue.Push"). It waits for queue room (the
// backpressure gate below), pushes the event, and appends a ledger
// entry unconditionally -- every log-road line gets an entry in log
// order regardless of whether Push actually queued a new copy, because
// the ledger tracks this log position's id, not one Push call's outcome
// (decision 3).
func (in *Intake) handleLogLine(ctx context.Context, ldg *ledger.Ledger, line tailer.Line) {
	id, message, err := event.IDFromLogLine(line.Data)
	if err != nil {
		// No '{' anywhere in the line: not an OpenCanary event at all
		// (the tailer's own MaxLineBytes cap already keeps a merely
		// oversize line from ever reaching emit). Nothing computable to
		// queue or append; #48 never interprets a line beyond locating
		// this byte.
		intakeLog.Warn(fmt.Sprintf("log line produced no event id, skipping: %v", err))
		return
	}

	if err := in.waitForRoom(ctx); err != nil {
		// This session is ending -- shutdown or an eviction-triggered
		// restart, either way. The line is not acknowledged, so it is
		// read again: on restart by the fresh catch-up scan, on
		// shutdown by the next process start.
		return
	}

	in.observeClaim(id, message)
	in.Queue.Push(queue.Event{ID: id, Payload: message})
	ldg.Append(id, line.Pos)
}

// waitForRoom is #48 decision 2's tailer intake gate: "When queue depth
// reaches capacity ... blocks inside the tailer's emit callback until
// depth falls below the low-water mark." It returns ctx's error if ctx
// ends while blocked, and does nothing (no wait at all) when the queue
// was not at capacity to begin with, so the ordinary, unthrottled case
// costs one Depth() call.
func (in *Intake) waitForRoom(ctx context.Context) error {
	if in.Queue.Depth() < in.maxEvents {
		return nil
	}
	for in.Queue.Depth() >= in.lowWater {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backpressurePollInterval):
		}
	}
	return nil
}

// Ledger returns the currently-live ledger. Exposed for the sender (to
// Resolve/Advance against it) and the heartbeat builder (Collisions);
// both must always read whatever is current, never a reference cached
// across a restart.
func (in *Intake) Ledger() *ledger.Ledger { return in.ledgerPtr.Load() }

// Collisions is the cumulative event-id collision count across every
// ledger this Intake has ever run, restart included -- see
// runLogRoadOnce's comment on collisionsBase for why a plain
// Ledger.Collisions() call alone would understate it after a
// backpressure restart.
func (in *Intake) Collisions() uint64 {
	total := in.collisionsBase.Load()
	if ldg := in.Ledger(); ldg != nil {
		total += ldg.Collisions()
	}
	return total
}

// LogReadOK reports the tailer's live log-read status (#48 gap 2).
func (in *Intake) LogReadOK() bool { return in.tailer.LogReadOK() }

// PositionFound reports whether the most recent catch-up scan located
// the acknowledged position (#48 gap: Tailer.ResumeFound).
func (in *Intake) PositionFound() bool { return in.tailer.ResumeFound() }

// LastEventID is the id of the most recently birdcage-acknowledged
// (stored) event, empty until the first one. Set by the sender's
// applyVerdicts.
func (in *Intake) LastEventID() string {
	if p := in.lastEventID.Load(); p != nil {
		return *p
	}
	return ""
}

func (in *Intake) setLastEventID(id string) { in.lastEventID.Store(&id) }

// PositionStore exposes the acknowledged-position store for the sender.
func (in *Intake) PositionStore() *queue.PositionStore { return in.posStore }

// fieldsOrFallback is #48's process-composition note, gap 5:
// "ExtractFields failure on a log-road payload -- id computable, JSON
// not decodable: forward anyway with SourceIP:"", DestPort:-1,
// Service:"", and the verbatim raw. The agent never judges evidence;
// rejection is birdcage's call, and its verdict is counted like any
// other." Used by the sender when building the wire event for a queued
// payload.
func fieldsOrFallback(payload []byte) event.Fields {
	fields, err := event.ExtractFields(payload)
	if err != nil {
		return event.Fields{DestPort: opencanary.NoDestPort}
	}
	return fields
}
