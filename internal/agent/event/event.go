// Package event computes the durable identity of one OpenCanary event and
// extracts the fields birdcage's ingest endpoint needs, from either of the
// two roads issue #48's agent receives an event by: the webhook body
// OpenCanary's WebhookHandler posts over loopback, or a line tailed from
// OpenCanary's log file.
//
// OpenCanary serialises each event exactly once -- json.dumps(logdata,
// sort_keys=True) in opencanary/logger.py -- and hands that one string to
// every handler. The webhook wrapper JSON-string-escapes it; the log file
// carries it verbatim after whatever formatter prefix the operator has
// configured. Both roads therefore carry the same emitted JSON string, and
// this package never parses-and-reserialises it before hashing: Go's key
// order, float formatting and unicode escaping differ from Python's and
// would re-mint ids for the whole outstanding queue on an upgrade (issue
// #48, "The event id").
//
// Everything this package reads is attacker-writable: every string typed
// at an emulated service lands inside the event OpenCanary emits, in both
// the log line and the webhook body. Nothing here interprets that content
// beyond locating the first '{' and decoding the handful of fields the
// ingest endpoint needs -- and every entry point is bounded before it does
// even that (issue #48, threat model: "the tailer is an untrusted-input
// parser in the hot path on a healthy fleet, not just after a
// compromise").
package event

const (
	// MaxLogLineBytes bounds one line read from OpenCanary's log file.
	// The emitted JSON is the same size class internal/ingest/parse.go's
	// MaxDatagramSize already treats as a generous ceiling for one event
	// (64 KiB); the tailer uses the same number so a hostile or corrupted
	// log line can't force an unbounded read into memory (issue #48,
	// "What the research changed" #3: "A log line over a fixed cap ...
	// sized generously above any real OpenCanary event").
	MaxLogLineBytes = 64 * 1024

	// MaxWebhookBodyBytes bounds one webhook POST body. The wrapper
	// JSON-string-escapes the emitted message -- quotes, backslashes and
	// control bytes each become two to six output bytes -- so the wrapper
	// can run several times the size of the log line it carries for the
	// same event; the cap leaves headroom for that inflation while still
	// refusing an unbounded body (issue #48, "The loopback listener is
	// data-only, with connection and body caps").
	MaxWebhookBodyBytes = 256 * 1024
)
