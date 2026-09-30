package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
	"github.com/tomlawesome/birdcage/internal/agent/smbaudit"
	"github.com/tomlawesome/birdcage/internal/agent/tailer"
)

// Environment variables the SMB audit road reads.
const (
	// envSMBAuditPath is the file the SMB lure (build/smb-lure) writes
	// its audit lines into, as this container sees it -- the read-only
	// mount of the volume the lure writes. Unset means the road is off,
	// which is how a canary deployed without the lure behaves: no
	// warning, nothing running, because there is nothing missing.
	//
	// Off-when-unset rather than a default path, unlike the port-scan and
	// snmp roads: those have something to detect on every canary, and
	// this one only has something to read when a second container is
	// deployed beside this one.
	envSMBAuditPath = "MOCKINGBIRD_SMB_AUDIT_PATH"
)

// smbPositionFileName is where this road keeps its read position, inside
// StateDir alongside the names config.go lists. Separate from
// positionFileName because it is a position in a different file: the two
// roads read different logs and neither one's offset means anything in
// the other's.
const smbPositionFileName = "smb-position"

// smbTickInterval is how often the road, with no new line to react to,
// releases a visit that has gone quiet (#123) and persists its read
// position. Well under the collapse window, so a single access becomes an
// alert promptly rather than waiting out a whole tick after its window;
// and not per line, because queue.PositionStore.Save writes, fsyncs and
// renames, while one audited file fetch is five lines.
//
// Everything between the last save and a crash is read again, which costs
// nothing: the collapser groups a re-read stretch exactly as it grouped it
// the first time and smbaudit.Encode derives the event bytes from the
// lines alone, so the re-read mints ids the queue already knows.
const smbTickInterval = 500 * time.Millisecond

// smbAuditInventory is the one startup fact this road states about
// itself, the same shape as agentInventory in portscan.go and
// snmpInventory in snmp.go, and for the same reason: a single boolean
// about whether a defence is running, never the path it is reading (see
// this package's doc comment on what must never be logged).
type smbAuditInventory struct {
	// Active is whether the road is running. False means no audit file
	// was configured, which on a canary without the SMB lure is the
	// ordinary case and not a fault.
	Active bool
}

// line renders the inventory as the single startup line main prints.
func (inv smbAuditInventory) line() string {
	if !inv.Active {
		return "smb audit road off"
	}
	return "smb audit road active"
}

// smbAuditRoad follows the lure's audit file: one tailer.Tailer instance
// (a second one, beside the log road's), the parse in
// internal/agent/smbaudit, and this road's own saved position.
type smbAuditRoad struct {
	tailer    *tailer.Tailer
	positions *queue.PositionStore
	submit    func(context.Context, []byte) error
	nodeID    string
	log       *slog.Logger

	// mu guards collapser and lastPos. The tailer calls handle on its own
	// goroutine while this road's timer releases quiet visits on another,
	// and smbaudit.Collapser is deliberately not safe for both at once --
	// serialising them is the caller's job, and this is the caller.
	mu        sync.Mutex
	collapser *smbaudit.Collapser
	// lastPos is the position after the most recently handled line,
	// whether or not it has become an event yet.
	lastPos queue.Position

	// pending is the position it is safe to save -- after the last line
	// for which nothing is still held -- and saved is what has actually
	// reached disk. Split so the periodic save can skip writing a
	// position that has not moved.
	pending      atomic.Uint64
	pendingInode atomic.Uint64
	saved        queue.Position

	events     atomic.Uint64
	unreadable atomic.Uint64
}

// newSMBAuditRoad builds the road, or returns nil when no audit file is
// configured. It opens nothing -- the tailer's own retry-open loop copes
// with the file not existing yet, which it will not on a canary whose
// lure container starts after this one -- so unlike newPortscanRoad and
// newSNMPRoad there is no failure here to report at startup.
func newSMBAuditRoad(cfg Config, in *Intake, log *slog.Logger) (*smbAuditRoad, smbAuditInventory) {
	path := os.Getenv(envSMBAuditPath)
	if path == "" {
		return nil, smbAuditInventory{Active: false}
	}

	confPath := os.Getenv(envOpenCanaryConf)
	if confPath == "" {
		confPath = smbaudit.DefaultConfPath
	}
	nodeID, err := smbaudit.ReadNodeID(confPath)
	if err != nil {
		nodeID = smbaudit.DefaultNodeID
		// safeErr: the reader's error wraps the configuration file's
		// path, and this is the honeypot's own stdout (safelog.go).
		log.Warn(fmt.Sprintf("OpenCanary configuration unreadable, using the fallback node id: %s", safeErr(err)))
	}

	return &smbAuditRoad{
		tailer:    tailer.New(path, tailer.Config{}),
		positions: queue.NewPositionStore(filepath.Join(cfg.StateDir, smbPositionFileName)),
		submit:    in.SubmitSMBEvent,
		nodeID:    nodeID,
		log:       log,
		collapser: smbaudit.NewCollapser(smbaudit.CollapseConfig{}),
	}, smbAuditInventory{Active: true}
}

// runSMBAuditRoad follows the audit file until ctx is done. A nil road --
// no audit file configured -- makes this a no-op, so main starts the same
// goroutine either way rather than branching around it, exactly as it does
// for the port-scan and snmp roads.
func runSMBAuditRoad(ctx context.Context, road *smbAuditRoad, log *slog.Logger) {
	if road == nil {
		return
	}
	road.run(ctx, log)
}

func (r *smbAuditRoad) run(ctx context.Context, log *slog.Logger) {
	pos, hasResume, err := r.positions.Load()
	if err != nil {
		// The same call #48 makes for the log road's position: an
		// unreadable position is a reason to re-read from the start, not
		// to stop reading. safeErr because the error wraps a path inside
		// StateDir.
		log.Warn(fmt.Sprintf("load saved smb position failed, reading the audit file from the start: %s", safeErr(err)))
		hasResume = false
	}
	if hasResume {
		r.saved = pos
		r.note(pos)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		emit := func(line tailer.Line) { r.handle(ctx, line) }
		if _, err := r.tailer.Follow(ctx, pos, hasResume, emit); err != nil && ctx.Err() == nil {
			// safeErr: a Follow error can wrap the audit file's path.
			log.Warn(fmt.Sprintf("smb audit tailer stopped unexpectedly: %s", safeErr(err)))
		}
	}()

	ticker := time.NewTicker(smbTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			<-done
			// Nothing the collapser still holds is flushed here. The
			// context is already cancelled, so a push would be refused
			// anyway, and the read position never advanced past those
			// lines -- so the next start reads them again and groups them
			// the same way. Abandoning them is #48 decision 1's
			// "queued-but-unsent events are abandoned rather than
			// flushed", one level down.
			r.savePosition(log)
			return
		case <-done:
			r.savePosition(log)
			return
		case <-ticker.C:
			r.release(ctx)
			r.savePosition(log)
		}
	}
}

// handle is the tailer's emit callback: parse one line and hand it to the
// collapser, which decides whether it is an alert on its own, part of one
// already being assembled, or the last piece of one now ready to go
// (#123).
//
// A line the parse has nothing to say about -- Samba's own start-up
// banner, say -- still settles the read position. Otherwise an audit file
// whose last line is not an event would be re-read from the same offset on
// every start for the life of the canary.
func (r *smbAuditRoad) handle(ctx context.Context, line tailer.Line) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.lastPos = line.Pos
	ev, ok := smbaudit.Parse(line.Data)
	if !ok {
		r.settle()
		return
	}
	r.dispatch(ctx, r.collapser.Offer(ev, time.Now()))
}

// release queues whatever the collapser has been holding long enough
// (#123): a single access nobody followed becomes an alert a tick after
// its window closes, rather than waiting for the next visitor.
func (r *smbAuditRoad) release(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dispatch(ctx, r.collapser.Due(time.Now()))
}

// dispatch encodes and queues a batch of events, then settles the read
// position. Called with mu held.
func (r *smbAuditRoad) dispatch(ctx context.Context, events []smbaudit.Event) {
	for _, ev := range events {
		body, err := smbaudit.Encode(ev, r.nodeID)
		if err != nil {
			// Encoding a fixed-shape struct can only fail on something
			// unencodable, which none of these fields is; counted rather
			// than dropped silently, and not retried, because reading the
			// line again would fail the same way for ever.
			r.unreadable.Add(1)
			r.log.Warn(fmt.Sprintf("could not encode an smb audit event: %v", err))
			continue
		}

		if err := r.submit(ctx, body); err != nil {
			if ctx.Err() != nil {
				// Shutting down. Deliberately nothing settled: these
				// lines are read again on the next start.
				return
			}
			r.log.Warn(fmt.Sprintf("could not queue an smb audit event: %v", err))
			continue
		}
		if ev.Kind == smbaudit.KindUnparseable {
			r.unreadable.Add(1)
		}
		r.events.Add(1)
	}
	r.settle()
}

// settle records the read position, but only while the collapser is
// holding nothing. A held line has been read and has not become an event
// yet, so a position past it would let a crash lose it; waiting until the
// collapser is empty means the position only ever names a point with
// nothing outstanding behind it. Called with mu held.
func (r *smbAuditRoad) settle() {
	if r.collapser.Len() != 0 {
		return
	}
	r.note(r.lastPos)
}

// note records the position after a handled line, for the periodic save
// to pick up. Two atomics rather than a mutex or an atomic.Pointer: the
// writer is the single tailer callback and the reader is the single save
// loop, so the only thing that matters is that neither blocks the other.
func (r *smbAuditRoad) note(pos queue.Position) {
	r.pendingInode.Store(pos.Inode)
	r.pending.Store(uint64(pos.Offset))
}

// savePosition persists the pending position if it has moved since the
// last write.
func (r *smbAuditRoad) savePosition(log *slog.Logger) {
	pos := queue.Position{Inode: r.pendingInode.Load(), Offset: int64(r.pending.Load())}
	if pos == r.saved || (pos == queue.Position{}) {
		return
	}
	if err := r.positions.Save(pos); err != nil {
		// #48's fail-closed rule for an unwritable position: keep
		// forwarding, report it, and re-read from the last written
		// position on restart. safeErr -- the error wraps a StateDir path.
		log.Warn(fmt.Sprintf("could not save the smb read position: %s", safeErr(err)))
		return
	}
	r.saved = pos
}

// Events is how many audit events this road has queued, Unreadable how
// many of them were lines it could not make sense of, and Collapsed how
// many lines were folded into another event rather than becoming one
// (#123). Read by the tests; not heartbeat fields yet, the same caveat
// portscan.Detected and snmp.Logged carry.
func (r *smbAuditRoad) Events() uint64     { return r.events.Load() }
func (r *smbAuditRoad) Unreadable() uint64 { return r.unreadable.Load() }
func (r *smbAuditRoad) Collapsed() uint64  { return r.collapser.Collapsed() }
