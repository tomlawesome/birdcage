package smbaudit

import (
	"bytes"
	"strconv"
	"strings"
	"time"
)

// Kind is what one line of the lure's log turned out to be. Every kind
// but KindNone becomes an event; the wording an operator reads is
// Kind.Wording.
type Kind int

const (
	// KindNone is a line this package has nothing to say about: Samba's
	// own start-up banner, the continuation line of a multi-line debug
	// record, a blank line. Parse returns ok=false with it, and the
	// caller queues nothing.
	KindNone Kind = iota

	// KindAccess is an audited operation from the expected set: somebody
	// opened something on the share. The ordinary case, and the only one
	// a healthy canary ever produces.
	KindAccess

	// KindUnexpectedOperation is a well-formed audit line whose operation
	// is not one the shipped configuration audits. The line parsed; what
	// it describes is not what this deployment asked to be told about,
	// which means either the configuration in the container is not the
	// one shipped with it, or something is doing more to that filesystem
	// than reading it (issue #87, decision 9).
	KindUnexpectedOperation

	// KindUnparseable is a line that claims to be an audit line -- it
	// carries the separator -- and is not the shape this package knows.
	// It is deliberately an event and not a skipped line: see the
	// package comment on the shifted openat shape.
	KindUnparseable

	// KindPanic is smbd's own panic or internal-error line. Its own
	// alert wording (decision 9): a canary whose SMB server has fallen
	// over is a different thing from one somebody visited.
	KindPanic
)

// Wording is the phrase that describes this kind to an operator. It goes
// into the emitted event, so the words an alert is read with are decided
// here, once, rather than at each call site.
func (k Kind) Wording() string {
	switch k {
	case KindAccess:
		return "file access"
	case KindUnexpectedOperation:
		return "unexpected operation"
	case KindUnparseable:
		return "unparseable audit line"
	case KindPanic:
		return "server panic"
	default:
		return ""
	}
}

// Field length caps. Every field is a sub-slice of a line the tailer has
// already bounded (internal/agent/tailer, Config.MaxLineBytes), so these
// are not what stops an unbounded read -- they stop one long field from
// travelling any further than it has to, and keep an event's size
// predictable whatever is in the file.
const (
	// MaxPathLen bounds the path field. Generous against the longest
	// path the image could possibly hold, and still far short of the
	// line cap.
	MaxPathLen = 4096
	// MaxFieldLen bounds every other field: the user name, the source
	// address, the share name, the operation, the result.
	MaxFieldLen = 256
	// MaxMessageLen bounds the text kept from a panic line or the
	// excerpt kept from a line that would not parse.
	MaxMessageLen = 512
)

// minAuditFields is how many separator-delimited fields a well-formed
// audit line has: user, source address, share, operation, result, path.
const minAuditFields = 6

// claimThreshold is how many fields a line needs before this package
// treats it as *claiming* to be an audit line rather than being ordinary
// Samba output. Two separators: fewer than that and a level-0 message
// mentioning a pipe character would be reported as a broken audit line,
// which is a false alarm; more than that and a genuinely truncated audit
// line would be skipped in silence, which is the worse mistake.
const claimThreshold = 3

// expectedOperations is the set of VFS operations the shipped smb.conf
// asks for: `full_audit:success = close`, and nothing else. An operation
// outside this set is not a parse failure -- the line read perfectly --
// it is a line describing something this deployment did not ask to hear
// about, which is why it gets its own wording rather than being dropped.
var expectedOperations = map[string]bool{"close": true}

// Event is one line, read.
type Event struct {
	// Kind is what the line was. Never KindNone in an Event a caller
	// receives: Parse returns ok=false for those.
	Kind Kind

	// User is the user name the client asked for. Client-chosen, so
	// evidence about the visitor and nothing else. Empty for a panic.
	User string
	// SourceIP is the client address Samba recorded. Empty for a panic,
	// which has no client.
	SourceIP string
	// Share is the share name the operation happened on, as the operator
	// named it at start-up.
	Share string
	// Operation is the audited VFS operation ("close").
	Operation string
	// Result is the operation's result as Samba wrote it: "ok" or
	// "fail", and nothing else -- a third value is what makes a line
	// KindUnparseable.
	Result string
	// Path is the path the operation touched, as the lure's own
	// filesystem sees it (/srv/shares/<dir>/...). Not rewritten into a
	// share-relative path: the mapping from share name to directory
	// lives in the container's configuration, not in the line, and a
	// reader that guessed at it would be inventing evidence.
	Path string

	// Message carries the panic text for KindPanic, and for
	// KindUnparseable a short reason naming what was wrong. Bounded by
	// MaxMessageLen.
	Message string

	// Timestamp is the line's own debug-header timestamp, rewritten into
	// the layout OpenCanary uses in its events, or "" when the header
	// carried nothing readable.
	//
	// The line's clock, not the agent's, and that is deliberate. Every
	// byte of an emitted event has to be derived from the line alone,
	// because the event id is the SHA-256 of those bytes and the saved
	// position is what makes a restart re-read a line it had not yet
	// confirmed: with the agent's own clock in the event, a re-read of
	// one line would mint a second id and birdcage would store the same
	// access twice. The cost is that a lure with a wrong clock puts a
	// wrong time in the alert body -- and it is only the body, because
	// birdcage timestamps what it receives itself.
	Timestamp string

	// At is the same moment as Timestamp, decoded, and the zero time
	// when the header carried nothing readable. Only the collapser
	// (collapse.go) reads it, for deciding which closes belong to one
	// visit; nothing encodes it, so it is not part of the wire form.
	At time.Time
}

// Parse reads one line from the lure's log. ok is false for a line this
// package has nothing to say about (KindNone); every other outcome,
// including a line it could not make sense of, is an Event.
//
// line is the tailer's Line.Data: one complete line, without its
// newline. It is not modified, and every string in the returned Event is
// a fresh copy, so the caller may reuse the buffer.
func Parse(line []byte) (Event, bool) {
	msg, stamp, at, ok := stripDebugHeader(line)
	if !ok {
		// No debug header: a continuation line of a multi-line record, a
		// blank line, or something else smbd wrote straight to the file
		// descriptor. Nothing this package reports on.
		return Event{}, false
	}

	if isPanic(msg) {
		return Event{Kind: KindPanic, Timestamp: stamp, At: at, Message: clip(string(msg), MaxMessageLen)}, true
	}

	fields := strings.Split(string(msg), "|")
	if len(fields) < claimThreshold {
		// Ordinary Samba output. Not claiming to be an audit line.
		return Event{}, false
	}
	if len(fields) < minAuditFields {
		return Event{
			Kind:      KindUnparseable,
			Timestamp: stamp,
			At:        at,
			Message:   "audit line has " + strconv.Itoa(len(fields)) + " fields, expected at least " + strconv.Itoa(minAuditFields),
		}, true
	}

	// Counted from the right, so a separator inside the client-chosen
	// user name cannot move any of these: see the package comment.
	n := len(fields)
	path := fields[n-1]
	result := fields[n-2]
	operation := fields[n-3]
	share := fields[n-4]
	sourceIP := fields[n-5]
	user := strings.Join(fields[:n-5], "|")

	if result != "ok" && result != "fail" {
		// The shifted openat shape lands here: its "r"/"w" flag sits
		// where the result belongs. Reported, never read as a path.
		return Event{
			Kind:      KindUnparseable,
			Timestamp: stamp,
			At:        at,
			Message: "audit line has " + quote(clip(result, 32)) +
				" where the result belongs, expected \"ok\" or \"fail\"",
		}, true
	}
	if !plausibleOperation(operation) {
		return Event{
			Kind:      KindUnparseable,
			Timestamp: stamp,
			At:        at,
			Message: "audit line has " + quote(clip(operation, 32)) +
				" where the operation belongs",
		}, true
	}

	ev := Event{
		Kind:      KindAccess,
		Timestamp: stamp,
		At:        at,
		User:      clip(user, MaxFieldLen),
		SourceIP:  clip(sourceIP, MaxFieldLen),
		Share:     clip(share, MaxFieldLen),
		Operation: clip(operation, MaxFieldLen),
		Result:    result,
		Path:      clip(path, MaxPathLen),
	}
	if !expectedOperations[operation] {
		ev.Kind = KindUnexpectedOperation
	}
	return ev, true
}

// stripDebugHeader splits Samba's `[date time, level]` prefix off a line,
// returning the message and the header's timestamp in OpenCanary's own
// layout. `debug prefix timestamp = yes` in the lure's smb.conf is what
// keeps the header and its message on one line; a line arriving without
// one is not a record this package reads, so ok is false.
//
// Hand-parsed rather than matched with a regular expression: the check is
// "starts with '[', has a ']' within the first few dozen bytes", which is
// two scans over a short prefix, in a function on the hot path of a file
// a hostile process writes.
func stripDebugHeader(line []byte) (msg []byte, stamp string, at time.Time, ok bool) {
	if len(line) == 0 || line[0] != '[' {
		return nil, "", time.Time{}, false
	}
	// The header Samba writes is `[2026/09/23 22:01:53.987124,  1]` --
	// 32 bytes. The cap is generous against a wider level number or a
	// different timestamp precision without letting a hostile line make
	// this a scan of the whole buffer.
	const maxHeaderLen = 64
	end := bytes.IndexByte(line[:min(len(line), maxHeaderLen)], ']')
	if end < 0 {
		return nil, "", time.Time{}, false
	}
	at = headerTime(line[1:end])
	if !at.IsZero() {
		stamp = at.Format(openCanaryTimeLayout)
	}
	return bytes.TrimLeft(line[end+1:], " \t"), stamp, at, true
}

// sambaTimeLayout is the timestamp Samba writes into a debug header.
const sambaTimeLayout = "2006/01/02 15:04:05.000000"

// headerTime decodes the timestamp out of a debug header. header is
// everything between the brackets, timestamp first and the debug level
// after a comma.
//
// An unreadable timestamp gives the zero time, never the current time:
// see Event.Timestamp for why every byte of an emitted event has to come
// from the line and not from the agent's own clock.
func headerTime(header []byte) time.Time {
	comma := bytes.IndexByte(header, ',')
	if comma < 0 {
		comma = len(header)
	}
	t, err := time.Parse(sambaTimeLayout, string(bytes.TrimSpace(header[:comma])))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// isPanic reports whether msg is smbd's own panic or internal-error
// line. All three shapes this Samba build can write start with one of
// these two words -- verified against the format strings in the 4.23.8
// binary the image installs (`PANIC (pid %llu): %s in 4.23.8`,
// `PANIC: assert failed at %s(%d): %s`, `INTERNAL ERROR: %s in %s (%s)
// (%s) pid %lld (%s)`) and seen live, as:
//
//	[2026/09/23 22:06:57.659859,  0]   INTERNAL ERROR: sys_setgroups failed in smbd () () pid 1 (4.23.8)
//	[2026/09/23 22:06:57.659891,  0]   PANIC (pid 1): sys_setgroups failed in 4.23.8
//
// A panic writes several lines (the banner, the internal error, the
// panic, the stack-trace note). Each that begins this way is its own
// event: collapsing them would mean holding state across lines, and a
// duplicate alert about a server falling over is a much smaller problem
// than a missed one.
func isPanic(msg []byte) bool {
	return bytes.HasPrefix(msg, []byte("PANIC")) ||
		bytes.HasPrefix(msg, []byte("INTERNAL ERROR:"))
}

// plausibleOperation reports whether s could be a VFS operation name.
// Samba's own names are short, lower-case and underscored (close,
// openat, renameat, unlinkat); anything else in that position means the
// line is not the shape this package knows, whatever else it might be.
func plausibleOperation(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return false
	}
	return true
}

// clip bounds a field, marking a value it had to shorten so a reader can
// tell a long value from a truncated one.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// quote wraps s in double quotes for a Message. Not strconv.Quote: the
// message is embedded in JSON by the caller, which does its own
// escaping, and Quote's escaping on top of that turns an unreadable
// field into an unreadable field wrapped in backslashes.
func quote(s string) string { return "\"" + s + "\"" }
