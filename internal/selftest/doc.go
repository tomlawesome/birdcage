// Package selftest carries the wire contract for #46's scheduled
// self-test: the schema of a selftest command's params, and the rules
// both ends must agree on for planting and recognising markers.
//
// It is deliberately tiny and dependency-free. Both the server
// (internal/store, internal/ingest) and the agent
// (cmd/birdcage-agent, internal/agent/probe) import it, and the agent
// must never acquire a path to internal/ingest, internal/store,
// internal/db, internal/api or internal/stream through it (#48: the
// server must not be linked into the binary that ships to canary
// boxes). Nothing here may import anything outside the standard
// library.
//
// The split of responsibility:
//
//   - Birdcage mints the markers, because it must know what it issued
//     in order to tell a self-test from an intruder imitating one
//     (#46: "anything that looks like a test but does not match an
//     issued command is not a test").
//   - The agent decides how a marker is planted, because that is
//     protocol mechanics per service and has no business on the wire.
//   - Birdcage matches by looking for the marker it issued in the raw
//     event, which keeps the matcher carrier-agnostic: it never has to
//     model where in an SSH handshake or an HTTP request the value
//     ended up.
package selftest
