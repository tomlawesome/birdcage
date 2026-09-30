package smbaudit

import (
	"strings"
	"sync/atomic"
	"time"
)

// One visit to one file writes several audit lines. A real `get` of
// /srv/shares/public/IT/vpn-setup.pdf, captured from the image on
// 2026-09-23, wrote five:
//
//	root|172.21.0.3|public|close|ok|/srv/shares/public
//	root|172.21.0.3|public|close|ok|/srv/shares/public/IT
//	root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf
//	root|172.21.0.3|public|close|ok|/srv/shares/public/IT
//	root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf
//
// Five alerts for one thing somebody did is five times the noise and no
// extra information: the first two are the directories SMB had to walk to
// reach the file, and the last two are the same file again. Issue #123
// settles what to do about it, and this file is that decision:
//
//   - closes from the same user, address and share within a two-second
//     window are one visit;
//   - inside that window, a path that is a prefix of another path in it
//     is dropped -- it is the walk, not the destination;
//   - what survives is emitted, one event per surviving path. For the
//     capture above that is one event, naming the .pdf.
//   - listing a directory and opening nothing leaves the directory as the
//     longest path, so it is still one event, naming the directory.
//   - two files opened in the same second are two surviving paths, so
//     they stay two alerts. Collapsing is about the walk to a file, never
//     about how much a visitor did.
//   - unexpected operations and panics are never collapsed. They are the
//     lines that say something is wrong, and one of them is not noise
//     however many arrive.
//
// # Why the window is measured on the line's clock
//
// Which lines fall in a window is decided by the timestamps in the lines
// themselves, not by when this process read them. Re-reading a stretch of
// the file -- which is what a restart does, from the saved position --
// then groups it exactly as the first pass did, produces the same events,
// and so mints the same ids, and the queue drops the duplicates. Grouping
// on the agent's own clock would make a re-read produce differently
// grouped events with new ids, and birdcage would store the same visit
// twice.
//
// The agent's clock is used for one thing only: deciding that no more
// lines are coming, so a window that nothing has closed can be let go
// (Due). A group flushed that way could in principle be grouped
// differently on a re-read -- it takes the lure's clock jumping, or its
// writes stalling mid-window for longer than the window itself -- and the
// cost is a duplicate alert, never a missed one.

// DefaultCollapseWindow is issue #123's two seconds: long enough to cover
// the directory walk and the repeat close of one open, short enough that
// a second visit is a second alert.
const DefaultCollapseWindow = 2 * time.Second

// Bounds on what one Collapser holds. Everything here is written by a
// process built to be attacked, and the group key contains two
// client-chosen fields, so the number of groups is attacker-influenced
// and has to be capped rather than trusted.
const (
	// DefaultMaxGroups is how many visits may be open at once. A group
	// over the cap flushes the oldest rather than refusing the new one:
	// dropping the newest would lose exactly the visitor who was trying
	// to hide behind the others.
	DefaultMaxGroups = 64
	// DefaultMaxPathsPerGroup is how many distinct paths one visit may
	// hold. Reaching it flushes the visit and starts another, so a
	// visitor who opens a thousand files gets a run of alerts rather
	// than one unbounded one.
	DefaultMaxPathsPerGroup = 64
)

// CollapseConfig configures a Collapser. Every field has a working
// default, so a caller that wants issue #123's behaviour passes the zero
// value.
type CollapseConfig struct {
	// Window is how long one visit lasts. Zero means
	// DefaultCollapseWindow.
	Window time.Duration
	// MaxGroups and MaxPathsPerGroup bound the state. Zero means the
	// defaults above.
	MaxGroups        int
	MaxPathsPerGroup int
}

// Collapser folds the several audit lines of one visit into the events
// worth alerting on. It is not safe for concurrent use: the caller is the
// single tailer callback plus its own timer, and serialising those two is
// the caller's job (cmd/mockingbird/smbaudit.go holds them on one mutex).
type Collapser struct {
	cfg CollapseConfig

	// open holds the visits still being assembled, in arrival order, so
	// "the oldest" is the first element and nothing has to be sorted.
	//
	// A slice and a linear scan rather than a map: MaxGroups caps it at a
	// few dozen, a scan of that is nothing next to reading the line in the
	// first place, and one structure cannot fall out of step with itself
	// the way a map plus an ordering slice can.
	open []*visit

	collapsed atomic.Uint64
}

// visit is one group: the lines of one user, from one address, on one
// share, inside one window.
type visit struct {
	// key is user|address|share, the three fields that make one visitor
	// on one share.
	key string
	// start is the timestamp of the visit's first line -- the line's own
	// clock, which is what decides the window.
	start time.Time
	// seen is the agent's own clock at the last line added. Only Due
	// reads it -- see this file's comment on which clock decides what.
	seen time.Time
	// events are the visit's lines in arrival order, already
	// deduplicated by path.
	events []Event
}

// NewCollapser returns a Collapser. Negative configuration values are a
// caller programming error and panic, matching queue.NewMemQueue's and
// tailer.New's convention for the same class of mistake.
func NewCollapser(cfg CollapseConfig) *Collapser {
	if cfg.Window < 0 || cfg.MaxGroups < 0 || cfg.MaxPathsPerGroup < 0 {
		panic("smbaudit: CollapseConfig fields must not be negative")
	}
	if cfg.Window == 0 {
		cfg.Window = DefaultCollapseWindow
	}
	if cfg.MaxGroups == 0 {
		cfg.MaxGroups = DefaultMaxGroups
	}
	if cfg.MaxPathsPerGroup == 0 {
		cfg.MaxPathsPerGroup = DefaultMaxPathsPerGroup
	}
	return &Collapser{cfg: cfg}
}

// Collapsed is how many audit lines have been folded into another event
// rather than becoming one of their own. The difference between the lines
// read and the alerts raised, for a caller that wants to report it.
func (c *Collapser) Collapsed() uint64 { return c.collapsed.Load() }

// Len is how many visits are currently open. The caller uses it to decide
// whether it is safe to record a read position: while anything is held,
// the lines behind it have not been turned into events yet.
func (c *Collapser) Len() int { return len(c.open) }

// Offer takes one parsed event and returns the events ready to queue,
// oldest first. now is the agent's clock, recorded so Due can later tell
// that a window has gone quiet; it is never used to decide which lines
// group together.
//
// An event that is not an ordinary access -- an unexpected operation, a
// line that would not parse, a panic -- passes straight through. So does
// an access whose line carried no readable timestamp: a window that
// cannot be measured is not a window, and emitting it immediately is the
// answer that cannot lose it.
func (c *Collapser) Offer(ev Event, now time.Time) []Event {
	if ev.Kind != KindAccess || ev.At.IsZero() {
		return []Event{ev}
	}

	// Anything whose window the new line has already passed is finished,
	// whichever group it belongs to: time moving on in the file is what
	// closes a window, and it costs nothing to notice here.
	out := c.flushElapsed(ev.At)

	key := ev.User + "|" + ev.SourceIP + "|" + ev.Share
	g := c.find(key)
	if g != nil && (ev.At.Before(g.start) || !ev.At.Before(g.start.Add(c.cfg.Window))) {
		// Outside this visit's window, or before its start, which is the
		// lure's clock having gone backwards. Either way the old visit is
		// over and this line begins another.
		out = append(out, c.take(g)...)
		g = nil
	}
	if g == nil {
		g = &visit{key: key, start: ev.At}
		c.open = append(c.open, g)
	}

	g.seen = now
	if !g.addPath(ev) {
		// The same file closed twice in one visit, which the capture
		// above shows happens on every open.
		c.collapsed.Add(1)
	} else if len(g.events) >= c.cfg.MaxPathsPerGroup {
		// This visit has held as much as it may. Emit it now; the next
		// line from the same client starts a fresh one.
		out = append(out, c.take(g)...)
	}

	for len(c.open) > c.cfg.MaxGroups {
		out = append(out, c.take(c.open[0])...)
	}
	return out
}

// find returns the open visit with this key, or nil.
func (c *Collapser) find(key string) *visit {
	for _, g := range c.open {
		if g.key == key {
			return g
		}
	}
	return nil
}

// Due returns the events of every visit that has gone quiet -- nothing
// added to it for a whole window of the agent's own clock. This is what
// gets the last visit in a quiet file out of the buffer and into an
// alert; without it, an access nobody followed would sit here until the
// next one arrived.
func (c *Collapser) Due(now time.Time) []Event {
	var out []Event
	for _, g := range c.snapshot() {
		if now.Sub(g.seen) >= c.cfg.Window {
			out = append(out, c.take(g)...)
		}
	}
	return out
}

// Flush returns everything held and empties the Collapser. For shutdown:
// a queued event is worth more than a tidy window, and the caller only
// records its read position once this has returned nothing.
func (c *Collapser) Flush() []Event {
	var out []Event
	for _, g := range c.snapshot() {
		out = append(out, c.take(g)...)
	}
	return out
}

// flushElapsed emits every visit whose window closed at or before at.
func (c *Collapser) flushElapsed(at time.Time) []Event {
	var out []Event
	for _, g := range c.snapshot() {
		if !at.Before(g.start.Add(c.cfg.Window)) {
			out = append(out, c.take(g)...)
		}
	}
	return out
}

// snapshot copies the open list, so a loop may take visits out of it
// while iterating.
func (c *Collapser) snapshot() []*visit { return append([]*visit(nil), c.open...) }

// take removes one visit and returns the events worth alerting on: the
// paths that are not a prefix of another path in the same visit, in
// arrival order.
func (c *Collapser) take(g *visit) []Event {
	for i, held := range c.open {
		if held == g {
			c.open = append(c.open[:i], c.open[i+1:]...)
			break
		}
	}

	out := make([]Event, 0, len(g.events))
	for _, ev := range g.events {
		covered := false
		for _, other := range g.events {
			if isPathPrefix(ev.Path, other.Path) {
				covered = true
				break
			}
		}
		if covered {
			c.collapsed.Add(1)
			continue
		}
		out = append(out, ev)
	}
	return out
}

// addPath adds ev to the visit unless its path is already there, and
// reports whether it was added. The caller counts a rejection towards
// Collapsed, which is what makes that number the true difference between
// the lines read and the alerts raised.
func (g *visit) addPath(ev Event) bool {
	for _, held := range g.events {
		if held.Path == ev.Path {
			return false
		}
	}
	g.events = append(g.events, ev)
	return true
}

// isPathPrefix reports whether a names a directory on the way to b. It
// compares whole path components, so /srv/shares/pub is not a prefix of
// /srv/shares/public -- a share called `pub` beside one called `public`
// would otherwise silently swallow the other's alerts.
func isPathPrefix(a, b string) bool {
	if a == "" || len(a) >= len(b) || !strings.HasPrefix(b, a) {
		return false
	}
	if strings.HasSuffix(a, "/") {
		return true
	}
	return b[len(a)] == '/'
}
