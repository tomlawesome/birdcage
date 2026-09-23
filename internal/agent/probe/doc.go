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
// purely for cmd/mockingbird to log and, eventually, fold into the
// heartbeat's counters; it is not sent anywhere itself.
//
// Every probe is protocol mechanics only: enough of a handshake to reach
// the point where a real client would present a username, password or
// equivalent, and no further. None of it depends on the target
// accepting the credential -- a rejected login is exactly the outcome
// OpenCanary needs to see, since it logs the attempt, not the session.
//
// A service with no entry in the carrier table -- because #46 slice 2
// rules it out of scope for this build (smb, llmnr; see carrier.go's
// notProbeable) -- is reported rather than guessed at: see
// StatusNoCarrier and StatusNotProbeable. vnc, ntp and portscan do have
// carriers (vnc.go, attribution.go), but their carriers are not all
// marker-planting: see each one's own doc comment.
//
// This package must never import internal/ingest, internal/store,
// internal/db, internal/api or internal/stream (#48: the agent binary
// shipped to canary boxes must not link the server). It imports
// internal/selftest only, per that package's own doc comment.
package probe
