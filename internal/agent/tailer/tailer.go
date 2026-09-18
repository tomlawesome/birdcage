package tailer

import (
	"sync/atomic"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/event"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// Line is one complete, newline-terminated line read from OpenCanary's
// log, paired with the queue.Position that follows it -- the position the
// caller should persist (via queue.PositionStore.Save) once birdcage has
// acknowledged whatever event this line produced. Data is the line's raw
// bytes, without the trailing newline, and is never interpreted here
// beyond finding that newline (#48: "the agent never interprets an event
// beyond locating the first `{` and hashing verbatim" -- locating the `{`
// and hashing are event.IDFromLogLine's job, a peer package, not this
// one's).
type Line struct {
	Data []byte
	Pos  queue.Position
}

// ResumeResult reports how the initial catch-up scan went.
type ResumeResult struct {
	// PositionFound is true when the resume Position handed to Follow was
	// located among the live file or an available rotated sibling, and
	// every line between it and the live file's then-current end was
	// read. False means some history may have been skipped: either the
	// position's file no longer exists among what MaxRotatedFiles /
	// MaxRotatedBytes allow the scan to reach (it rotated beyond the
	// recovery window), or there was no resume position to find in the
	// first place. Either way Follow already fell back to the oldest
	// sibling it could still afford to read, per #48's fail-closed rule
	// that uncertainty resolves to re-reading, never to skipping.
	//
	// Surfacing this on the heartbeat's log-read status is a future
	// caller's job, not this package's.
	PositionFound bool
}

// Config bounds the tailer's resource use. #48, "What the research
// changed" #3: "the rotation scan is bounded in file count and bytes,
// with #47's rotation policy setting the real numbers" -- the values here
// are this package's defaults pending that; New accepts an override for
// any field left at its zero value.
type Config struct {
	// MaxLineBytes caps one log line. A line whose content would exceed
	// this is a permanently rejected event: counted, never queued, never
	// able to pin the tailer.
	MaxLineBytes int
	// MaxRotatedFiles caps how many rotated siblings the initial catch-up
	// scan will read.
	MaxRotatedFiles int
	// MaxRotatedBytes caps the total size of rotated siblings the initial
	// catch-up scan will read.
	MaxRotatedBytes int64
	// PollInterval is how often the tailer checks a quiescent live file
	// for growth or rotation.
	PollInterval time.Duration
}

// Default bounds used by New for any Config field left at its zero
// value.
const (
	// defaultMaxRotatedFiles and defaultMaxRotatedBytes are placeholder
	// defaults, generous enough for a modest recovery window, pending
	// #47's actual rotation policy and its "real numbers" (#48, "What the
	// research changed" #3). A caller that knows those numbers should set
	// them explicitly in Config rather than rely on these.
	defaultMaxRotatedFiles = 64
	defaultMaxRotatedBytes = 256 * 1024 * 1024
	defaultPollInterval    = 500 * time.Millisecond
)

// Tailer reads one OpenCanary log file: New(path, cfg) then Follow.
type Tailer struct {
	path string
	cfg  Config

	oversizeLines    atomic.Uint64
	discardedPartial atomic.Uint64
	logReadOK        atomic.Bool
	resumeFound      atomic.Bool
}

// New returns a Tailer for the log at path. path's directory is where
// listCandidates looks for rotated siblings; it need not exist yet (#48
// requires tolerating the log being briefly absent).
//
// Zero-valued fields in cfg are filled with this package's defaults;
// MaxLineBytes defaults to event.MaxLogLineBytes -- the same cap
// event.IDFromLogLine enforces on the same line, per that package's own
// doc comment ("the tailer uses the same number"), so the two never
// disagree about what "too long" means for the same input.
//
// New panics if any explicitly-set numeric field is negative: that is a
// caller programming error, not a runtime condition to recover from,
// matching queue.NewMemQueue's convention for the same class of mistake.
func New(path string, cfg Config) *Tailer {
	if cfg.MaxLineBytes < 0 || cfg.MaxRotatedFiles < 0 || cfg.MaxRotatedBytes < 0 || cfg.PollInterval < 0 {
		panic("tailer: Config fields must not be negative")
	}
	if cfg.MaxLineBytes == 0 {
		cfg.MaxLineBytes = event.MaxLogLineBytes
	}
	if cfg.MaxRotatedFiles == 0 {
		cfg.MaxRotatedFiles = defaultMaxRotatedFiles
	}
	if cfg.MaxRotatedBytes == 0 {
		cfg.MaxRotatedBytes = defaultMaxRotatedBytes
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = defaultPollInterval
	}
	t := &Tailer{path: path, cfg: cfg}
	// logReadOK starts true: see LogReadOK's doc comment for why "no
	// attempt yet" must resolve the same direction as internal/store
	// /health.go's notDelivering resolves a nil self-report -- never as
	// failing.
	t.logReadOK.Store(true)
	// resumeFound starts true for the identical reason: before Follow's
	// first catch-up has finished, there is no resume outcome yet to
	// report, and a caller building a heartbeat in that brief window
	// must not read the log road as having lost the acknowledged
	// position when nothing has actually been searched for yet.
	t.resumeFound.Store(true)
	return t
}

// OversizeLines is the number of lines rejected for exceeding
// Config.MaxLineBytes since this Tailer was created. Exposed for a future
// heartbeat self-report (#48 item 6); building that report is out of this
// package's scope.
func (t *Tailer) OversizeLines() uint64 { return t.oversizeLines.Load() }

// DiscardedPartialLines is the number of unterminated final lines
// discarded since this Tailer was created, because the file they belonged
// to turned out to be dead -- rotated away or truncated -- before a
// newline ever arrived. These are never complete events (nothing hashes
// an unterminated line), so nothing was dropped that could have been
// stored; this counts how often it happened, for the same future
// heartbeat self-report.
func (t *Tailer) DiscardedPartialLines() uint64 { return t.discardedPartial.Load() }

// LogReadOK reports whether this Tailer is reading the log successfully
// right now -- live status, not a cumulative count like OversizeLines and
// DiscardedPartialLines above. This is what the agent's heartbeat needs
// for its log_read_ok field (#48 gap 2), which #45's "not delivering"
// dashboard state reads directly.
//
// Before Follow has made its first read attempt, LogReadOK reports true.
// This is deliberate, not an oversight: internal/store/health.go's
// notDelivering comment explains why a nil self-report must never read
// as failing -- "a canary that has simply never sent a self-report yet
// ... has nothing to say yet" -- and the same trap applies one level
// down here. A heartbeat built in the brief window between process start
// and the tailer's first open attempt must not report the log road
// broken when nothing has actually failed yet.
//
// It flips to false the moment a concrete read attempt fails (the log
// is absent, unreadable, or any other condition that sends Follow's
// loop into its retry path instead of successfully reading), and back
// to true the moment a read attempt succeeds again -- so a caller
// polling this alongside the heartbeat cadence always sees the tailer's
// current state, never a stale one.
func (t *Tailer) LogReadOK() bool { return t.logReadOK.Load() }

// ResumeFound reports whether the most recently completed catch-up scan
// located the resume Position it was given -- the live value behind
// #48's process-composition note, gap in the heartbeat self-report:
// "position_found ... whether the last resume found the acknowledged
// position." It is ResumeResult.PositionFound from Follow's own most
// recent catch-up, made available to a caller (the heartbeat builder)
// that cannot otherwise see it without waiting for Follow itself to
// return -- which it does not do until shutdown or a forced restart.
//
// Before Follow's first catch-up has finished, ResumeFound reports
// true, for the same reason New seeds it that way: nothing has been
// searched for yet, so there is nothing to report as lost.
func (t *Tailer) ResumeFound() bool { return t.resumeFound.Load() }
