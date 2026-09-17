// Package queue holds the canary agent's restart-safe in-memory state for
// events awaiting delivery to birdcage: the capped send queue itself, and
// the last acknowledged log position. MemQueue is capped by both event
// count and total queued payload bytes (#48 gap 4), so a flood of
// large-but-individually-valid events cannot exhaust memory merely by
// staying under the count cap.
//
// Deliberately absent: a disk-backed event spool. Issue #48 rules that out
// explicitly -- "The queue is memory only and capped. No spool; the disk
// state is the token file and the acknowledged position" -- and lists "a
// disk spool for the queue" under "Deliberately not done", because
// OpenCanary's own log file is already the durable store, and a second
// on-disk copy of hostile event content would be one more untrusted-input
// store to cap, fsync and re-parse on the one box built to attract floods.
//
// What crashes safely here is metadata only: the acknowledged Position
// (inode plus byte offset), persisted atomically and never on mere read.
// Event content survives a restart because it is re-read from OpenCanary's
// log starting at that position -- replay is free, since the event id (a
// peer package's job, not this one) makes re-delivery a same-id no-op
// through MemQueue's dedup.
package queue
