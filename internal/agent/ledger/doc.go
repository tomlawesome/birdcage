// Package ledger tracks, for the canary agent's log-road intake, which
// OpenCanary log lines birdcage has acknowledged, and computes the one
// position that is ever safe to persist across a restart (#48 decision
// 3, "ownership of the acknowledged position").
//
// The design's own words for why this is the whole crash-recovery story:
// "The sender loop is the only writer of the position file, and it
// advances the position through a ledger the intake side feeds. The
// ledger is an ordered list of (event id, position-after-line) records,
// one per line the tailer emits, appended by the log-road intake in log
// order." Getting the direction of a mistake wrong here is not
// symmetric: advancing too far silently loses events forever; advancing
// too little only costs a harmless re-send (the event id makes replay
// free, per the issue's "0 dropped silently" rule). Every choice in this
// package is made to protect the first direction absolutely, even at the
// cost of the second.
//
// This package holds no file I/O and starts no goroutines: it is pure,
// in-memory bookkeeping, safe for one intake goroutine calling Append and
// one sender goroutine calling Resolve and Advance concurrently (the
// same one-producer-one-consumer shape as MemQueue in the sibling queue
// package). Persisting the position Advance returns, and rebuilding a
// fresh Ledger from the tailer's re-read on restart, are the caller's
// job -- slice 3b's sender loop and cmd/birdcage-agent's wiring, not this
// package.
//
// Webhook-road events never appear here at all: only the tailer's
// log-road intake calls Append, so a webhook-only event can never
// advance the frontier, exactly as #48 requires ("Webhook-road events
// have no ledger entry; they cannot advance the position, only dedup
// against the queue").
package ledger
