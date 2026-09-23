package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

// AttributionFact records the exact network facts of one attributed-grade
// probe (ntp, portscan): what the agent itself sent, since neither
// service logs anything attacker-supplied a marker could ride in (see
// this file's other doc comments). cmd/mockingbird's claim window uses
// Service and FiredAt to watch its own intake for the single candidate
// event that could only be this probe's own traffic (note 19897); the
// wire never carries this struct itself -- only the marker the claim
// window attaches once it decides.
type AttributionFact struct {
	// Service is the target's service name ("ntp" or "portscan"),
	// echoed back so a caller juggling several outcomes does not need to
	// re-pair this fact with its target by slice index.
	Service string

	// DestPorts is every destination port this probe touched -- one for
	// ntp, portscanTouchCount consecutive (wrapped) ports for portscan.
	// Recorded for the operator log line and for a future stricter
	// match; the claim window's own candidate rule (note 19897, "same
	// service, source_ip equal to the canary's own address") does not
	// key on it today.
	DestPorts []int

	// SourcePort is the local port this probe's connection(s) used.
	// portscan binds it explicitly and reuses it across every touch so
	// one probe always has exactly one source port to report; ntp makes
	// one connection and reports whichever port the OS assigned it.
	SourcePort int

	// FiredAt is when this probe put its first byte on the wire -- the
	// start of the claim window's bounded watch, not when Sweep happened
	// to schedule it.
	FiredAt time.Time
}

// attributionCarrierFunc is carrierFunc's counterpart for the two
// attributed-grade services (carrier.go's attributionCarriers table): no
// marker to plant, so the signature differs by dropping it, and by
// returning what it sent so the caller (probe.go's probeOne) can hand it
// on to the claim window. A non-nil error means the probe never reached
// the wire at all -- the same "network or protocol failure" meaning
// carrierFunc's own error carries.
type attributionCarrierFunc func(ctx context.Context, address string, port int) (AttributionFact, error)

// probeNTP triggers OpenCanary's ntp module by sending the classic mode-7
// "monlist" request -- the only thing that module logs at all (#46 slice
// 2/3, "attributed" grade: nothing attacker-supplied survives into its
// fixed logdata, `{"NTP CMD": "monlist"}`, ntp.py). Its own check is
// `len(data) >= 4 and d[3] == '*'`: byte 3 (request code 42, historic
// "ntpdc monlist") happens to equal ASCII '*' (0x2A), which is what that
// check is actually testing. This carrier plants nothing; attribution
// never works by content -- see note 19897's ratified agent-side claim,
// built in cmd/mockingbird (#46 slice 3).
func probeNTP(ctx context.Context, address string, port int) (AttributionFact, error) {
	conn, err := dialUDP(ctx, address, port)
	if err != nil {
		return AttributionFact{}, err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	fact := AttributionFact{
		Service:   "ntp",
		DestPorts: []int{port},
		FiredAt:   time.Now(),
	}

	// Mode 7 (private), version 2, implementation 3 ("ntpdc"), request
	// code 0x2A (MON_GETLIST_1) -- the classic monlist amplification
	// request ntp.py's own check exists to catch.
	if _, err := conn.Write([]byte{0x17, 0x00, 0x03, 0x2A}); err != nil {
		return AttributionFact{}, err
	}

	if lp, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		fact.SourcePort = lp.Port
	}
	return fact, nil
}

// portscanTouchCount is internal/agent/portscan.DefaultThreshold's own
// value, duplicated here rather than imported: this package may import
// internal/selftest only (doc.go), and portscan's five-distinct-ports
// rule is what "shaped like a scan" means for that detector.
const portscanTouchCount = 5

// portscanBasePort is the first of portscanTouchCount consecutive ports
// probePortscan touches. selftest.Target carries DestPort 0 for a
// portscan target -- it names no real socket (#46 slice 3:
// internal/selftestsched.mintForCanary always adds one for every
// honeypot canary, regardless of which ports OpenCanary itself listens
// on) -- so this carrier picks its own range high enough to sit clear of
// every OpenCanary module's own default port, rather than trusting a
// caller-supplied port that was never meant to name one.
const portscanBasePort = 54321

// probePortscan touches portscanTouchCount consecutive ports starting at
// portscanBasePort, each almost certainly unlistened, from a single dial
// apiece, all bound to the same explicit local source port -- #46 slice
// 2/3's "attributed" grade for portscan. Birdcage's own detector
// (internal/agent/portscan, issue #65) fires once it sees a source touch
// that many distinct destination ports inside thirty seconds; nothing
// about the resulting event is attacker-chosen the way a marker needs,
// so this carrier's only job is to shape a scan and report the facts of
// it, not carry a payload.
//
// The explicit source port -- reserved once, then reused for every touch
// rather than left to a fresh ephemeral port per dial -- is what makes
// "the source port it bound" (note 19897) a single fact to report rather
// than five. Reusing one local port across sequential connections to
// different destination ports is ordinary: each dial completes (refused
// or briefly established, then closed) before the next begins, so no two
// touches ever share a live 4-tuple.
//
// port is accepted only so this function's signature matches
// attributionCarrierFunc, the same shape probeNTP uses; it is otherwise
// unused; see portscanBasePort's own doc comment for why.
//
// A refused connection is the expected, successful outcome here -- it is
// exactly what "not listening" looks like, the opposite of every other
// carrier in this package (carrier.go's doc: elsewhere a dial refusal
// means the target service isn't listening, a real failure). Only ctx
// itself giving up -- the sweep's own deadline, not a per-port refusal --
// is treated as this probe failing.
func probePortscan(ctx context.Context, address string, port int) (AttributionFact, error) {
	sourcePort, err := reserveEphemeralPort()
	if err != nil {
		return AttributionFact{}, fmt.Errorf("portscan: reserve source port: %w", err)
	}

	fact := AttributionFact{
		Service:    "portscan",
		SourcePort: sourcePort,
		FiredAt:    time.Now(),
	}

	for i := 0; i < portscanTouchCount; i++ {
		if ctx.Err() != nil {
			return AttributionFact{}, ctx.Err()
		}
		// No wraparound needed the way a caller-supplied base once
		// needed: portscanBasePort is a fixed constant well clear of
		// 65535, so portscanBasePort+portscanTouchCount-1 is always a
		// valid port.
		p := portscanBasePort + i
		fact.DestPorts = append(fact.DestPorts, p)

		conn, err := dialTCPFromPort(ctx, address, p, sourcePort)
		if err == nil {
			_ = conn.Close()
		}
		// Anything else -- almost always "connection refused" -- is the
		// scan signature working as intended, not a probe failure; see
		// this function's own doc comment.
	}
	return fact, nil
}

// reserveEphemeralPort asks the OS for one currently-free TCP port by
// briefly listening on port 0 and closing again, so probePortscan has a
// concrete local port to bind every one of its touches to. A small race
// (something else claims the port between close and probePortscan's
// first dial) is possible but not worth guarding against here: a losing
// dial reports an ordinary error, which this carrier already treats as
// ctx.Err() alone deciding failure -- see probePortscan's own doc.
func reserveEphemeralPort() (int, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		return 0, err
	}
	return port, nil
}
