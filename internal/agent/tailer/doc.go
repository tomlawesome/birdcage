// Package tailer reads OpenCanary's log file for the canary agent (issue
// #48): it resumes from the acknowledged queue.Position, catches up on
// whatever rotated siblings still hold unacknowledged lines, then follows
// the live file as it grows.
//
// The log file is the durable store; the memory queue is not (#48,
// "Durability: the saved position is the acknowledged position"). This
// package never advances past the offset it is handed -- it only reads,
// never writes to the log -- and it advances internally only as far as it
// has actually handed a line to the caller. Whether to treat that line as
// acknowledged, and when to persist the resulting queue.Position, is the
// caller's decision (via queue.PositionStore), made only once birdcage has
// confirmed the event stored.
//
// Everything this package reads is attacker-writable content on the one
// machine built to attract attackers (#48, threat model: "the tailer is an
// untrusted-input parser in the hot path on a healthy fleet, not just
// after a compromise"). Accordingly this package never interprets a line
// beyond finding its terminating newline: it does not decode JSON, does
// not validate UTF-8, and rejects -- without buffering it all -- any line
// longer than a fixed cap (#48, "What the research changed" #3). Log files
// and rotated siblings are opened O_NOFOLLOW, and the rotation scan is
// bounded in file count and bytes, per the same section.
package tailer
