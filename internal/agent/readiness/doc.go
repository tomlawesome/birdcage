// Package readiness independently verifies that the OpenCanary modules
// opencanary.conf enables are actually accepting connections, rather than
// inferring it from configuration or trusting OpenCanary's own startup
// log (#65).
//
// OpenCanary's own module loader (opencanary.tac's start_mod, in the
// pinned 0.9.9 release build/mockingbird/requirements.txt installs) wraps
// each module's instantiation and startup in a try/except: a module that
// raises there -- the original report on this issue was the portscan
// module refusing to run without iptables-legacy, since superseded by
// #65's own raw-socket detector; verified live here on 2026-09-22 with the
// https module, which fails the same way when it cannot create
// /etc/ssl/opencanary -- is logged and skipped, and every other module
// keeps running. The failure and a successful "Added service from class
// ... to fake" both log through the same helper, at the same logtype
// (LOG_BASE_MSG), in the same shape. Nothing in the emitted JSON
// distinguishes the two, and OpenCanary itself never stops: "Canary
// running!!!" is logged regardless of how many modules actually started.
//
// This package does not parse that log text to tell them apart. See
// internal/agent/event's own doc comment: everything OpenCanary logs is
// attacker-writable, because it is built from data a network client sent,
// and the agent deliberately never interprets message content beyond
// locating fixed structural fields. Instead this package reads the same
// configuration file OpenCanary itself loaded -- the same file and the
// same "<module>.port" / "<module>.enabled" parsing rule
// internal/agent/portscan already established for its own ignore list --
// and dials every port an enabled module claims, on the canary's own
// loopback address. A module that never accepted a connection during the
// check window is reported, by name and port, independent of whatever
// OpenCanary itself said about it.
package readiness
