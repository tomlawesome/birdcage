// Package receiver implements the loopback listener that receives
// OpenCanary's webhook posts -- the first of the agent's two intake roads
// (issue #48, "What it does" #1). The second road, tailing OpenCanary's log
// file, is a separate package (internal/agent/tailer); this one exists only
// because OpenCanary's WebhookHandler makes one synchronous attempt per
// event and drops it on failure, so the receive path one millimetre away
// must never be the reason that attempt is slow or fails.
//
// Two constraints from issue #48 shape everything here, and neither is
// negotiable:
//
//   - "Listens on loopback only, and runs unprivileged. This runs on the
//     machine we expect to be attacked." Every local uid can dial a
//     loopback listener -- loopback is not authentication -- so this
//     package treats every request as hostile input from the first byte,
//     the same posture issue #48's threat model states explicitly: "the
//     tailer is an untrusted-input parser in the hot path on a healthy
//     fleet, not just after a compromise." That applies here too; this is
//     the other untrusted-input entry point.
//
//   - "Never blocks OpenCanary. The loopback receive path returns
//     immediately; everything slow happens behind it." OpenCanary's own
//     webhook timeout is 1-2 seconds (issue #47), and its emit is
//     synchronous even to loopback, so a listener that ever waits -- on a
//     slow client, a stalled body, or a downstream that cannot keep up --
//     turns into OpenCanary silently dropping the event on timeout. This
//     package never waits past a bound it owns.
//
// Consequently this package is "data only": one route, one method, no
// command, control, status or health surface an attacker on the box could
// query or influence beyond posting an event (issue #48, "What the research
// changed" #4, citing Fluent Bit CVE-2024-4323 -- "the agent's own listener
// is its attack surface, so it does exactly one thing"). It hands each
// accepted body to a caller-supplied Handler unparsed: no JSON decoding, no
// event id (a peer package's job -- internal/agent/event), no queueing, no
// further network I/O. The only interpretation this package performs is
// locating '{' -- it doesn't even do that; it doesn't look inside the body
// at all.
package receiver
