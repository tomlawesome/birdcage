// Package probe is the self-test sweep's probe engine (#46): given a
// decoded selftest.Params, it opens a connection to each target's
// service on the canary's own address and plants that target's marker
// wherever the service's OpenCanary module records attacker-supplied
// data -- the SSH username, the FTP USER argument, the HTTP path, and so
// on, one carrier per service (see carrier.go for the table).
//
// This package never reports a result into the event path. A probe's
// only externally visible effect is the ordinary OpenCanary log line the
// target service writes -- which reaches birdcage by the normal two
// roads and is matched there against the marker birdcage minted, per
// internal/selftest's own doc comment. Sweep's return value exists
// purely for cmd/birdcage-agent to log and, eventually, fold into the
// heartbeat's counters; it is not sent anywhere itself.
//
// Every probe is protocol mechanics only: enough of a handshake to reach
// the point where a real client would present a username, password or
// equivalent, and no further. None of it depends on the target
// accepting the credential -- a rejected login is exactly the outcome
// OpenCanary needs to see, since it logs the attempt, not the session.
//
// A service with no entry in the carrier table -- because its protocol
// has no field that can carry an arbitrary attacker-chosen marker
// without already knowing a real credential (vnc, see its comment in
// carrier.go), or because #46 ruled it out of scope entirely (smb,
// portscan, llmnr, ntp) -- is reported rather than guessed at: see
// StatusNoCarrier and StatusNotProbeable.
//
// This package must never import internal/ingest, internal/store,
// internal/db, internal/api or internal/stream (#48: the agent binary
// shipped to canary boxes must not link the server). It imports
// internal/selftest only, per that package's own doc comment.
package probe
