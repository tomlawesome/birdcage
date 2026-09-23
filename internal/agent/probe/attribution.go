package probe

import "context"

// probeNTP triggers OpenCanary's ntp module by sending the classic mode-7
// "monlist" request -- the only thing that module logs at all (#46 slice
// 2, "attributed" grade: nothing attacker-supplied survives into its
// fixed logdata, `{"NTP CMD": "monlist"}`, ntp.py). Its own check is
// `len(data) >= 4 and d[3] == '*'`: byte 3 (request code 42, historic
// "ntpdc monlist") happens to equal ASCII '*' (0x2A), which is what that
// check is actually testing. This carrier plants nothing; marker exists
// only to satisfy carrierFunc's shared signature -- attribution never
// works by content. The other half, claiming the resulting event, is
// note 19897's ratified agent-side match against this probe's own
// network facts, not built yet (#47's wire and sender changes gate it;
// #46 slice 3). Until then this carrier fires the trigger and nothing
// downstream can yet claim what it produces.
func probeNTP(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialUDP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	// Mode 7 (private), version 2, implementation 3 ("ntpdc"), request
	// code 0x2A (MON_GETLIST_1) -- the classic monlist amplification
	// request ntp.py's own check exists to catch.
	_, err = conn.Write([]byte{0x17, 0x00, 0x03, 0x2A})
	return err
}

// portscanTouchCount is internal/agent/portscan.DefaultThreshold's own
// value, duplicated here rather than imported: this package may import
// internal/selftest only (doc.go), and portscan's five-distinct-ports
// rule is what "shaped like a scan" means for that detector.
const portscanTouchCount = 5

// probePortscan touches portscanTouchCount consecutive ports starting at
// port, each almost certainly unlistened, from a single dial apiece --
// #46 slice 2's "attributed" grade for portscan. Birdcage's own detector
// (internal/agent/portscan, issue #65) fires once it sees a source touch
// that many distinct destination ports inside thirty seconds; nothing
// about the resulting event is attacker-chosen the way a marker needs,
// so this carrier's only job is to shape a scan, not carry a payload.
//
// A refused connection is the expected, successful outcome here -- it is
// exactly what "not listening" looks like, the opposite of every other
// carrier in this package (carrier.go's doc: elsewhere a dial refusal
// means the target service isn't listening, a real failure). Only ctx
// itself giving up -- the sweep's own deadline, not a per-port refusal --
// is treated as this probe failing.
func probePortscan(ctx context.Context, address string, port int, marker string) error {
	for i := 0; i < portscanTouchCount; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p := port + i
		if p > 65535 {
			// Wrap rather than dial an invalid port number -- port is
			// caller-supplied (selftest.Target.DestPort, 1-65535) and
			// only within portscanTouchCount-1 of the ceiling in
			// practice, but wrapping costs nothing and keeps every
			// attempt a valid port regardless.
			p -= 65535
		}
		conn, err := dialTCP(ctx, address, p)
		if err == nil {
			_ = conn.Close()
		}
		// Anything else -- almost always "connection refused" -- is the
		// scan signature working as intended, not a probe failure; see
		// this function's own doc comment.
	}
	return nil
}
