package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

// smbPositionSaveInterval is how often the read position is persisted
// while lines are arriving. Not once per line: queue.PositionStore.Save
// writes, fsyncs and renames, and one audited file fetch is several lines
// (a real `get` of one file produced five). Not much longer either: this
// interval is how far behind the saved position can be when the process
// dies, and every line before it is read again on the next start -- which
// costs nothing but a repeat parse, because a re-read line mints the same
// event id and the queue drops the duplicate.
const smbPositionSaveInterval = 2 * time.Second

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

	// pending is the position after the most recently handled line, and
	// saved is what has actually reached disk. Split so the periodic save
	// can skip writing a position that has not moved.
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

	ticker := time.NewTicker(smbPositionSaveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			<-done
			r.savePosition(log)
			return
		case <-done:
			r.savePosition(log)
			return
		case <-ticker.C:
			r.savePosition(log)
		}
	}
}

// handle is the tailer's emit callback: parse one line, queue whatever it
// turned out to be, and record the position after it.
//
// The position is recorded for every line, including one the parse has
// nothing to say about -- Samba's own start-up banner, say. Otherwise an
// audit file whose last line is not an event would be re-read from the
// same offset on every start for the life of the canary.
//
// It is not recorded when the queue push was abandoned: that only happens
// when ctx ends while waiting for queue room, and the line then has to be
// read again next start, which is #48's fail-closed rule (uncertainty
// resolves to re-reading, never to skipping) applied to this road.
func (r *smbAuditRoad) handle(ctx context.Context, line tailer.Line) {
	ev, ok := smbaudit.Parse(line.Data)
	if !ok {
		r.note(line.Pos)
		return
	}

	body, err := smbaudit.Encode(ev, r.nodeID)
	if err != nil {
		// Encoding a fixed-shape struct can only fail on something
		// unencodable, which none of these fields is; counted rather
		// than dropped silently, and the line is still acknowledged
		// because reading it again would fail the same way for ever.
		r.unreadable.Add(1)
		r.log.Warn(fmt.Sprintf("could not encode an smb audit event: %v", err))
		r.note(line.Pos)
		return
	}

	if err := r.submit(ctx, body); err != nil {
		if ctx.Err() != nil {
			// Shutting down. Deliberately no position record: the line
			// is read again on the next start.
			return
		}
		r.log.Warn(fmt.Sprintf("could not queue an smb audit event: %v", err))
		r.note(line.Pos)
		return
	}
	if ev.Kind == smbaudit.KindUnparseable {
		r.unreadable.Add(1)
	}
	r.events.Add(1)
	r.note(line.Pos)
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

// Events is how many audit events this road has queued, and Unreadable
// how many of them were lines it could not make sense of. Read by the
// tests; not heartbeat fields yet, the same caveat portscan.Detected and
// snmp.Logged carry.
func (r *smbAuditRoad) Events() uint64     { return r.events.Load() }
func (r *smbAuditRoad) Unreadable() uint64 { return r.unreadable.Load() }
