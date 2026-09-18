package probe

import (
	"context"
	"net"
	"strconv"
	"time"
)

// dialTCP and dialUDP open a connection to address:port bound to ctx's
// deadline (its cancellation is not otherwise observed once dialing
// returns -- callers are expected to also pass ctx into whatever they
// read or write next, and probeTimeout's own deadline is what actually
// bounds the conn via SetDeadline below).
func dialTCP(ctx context.Context, address string, port int) (net.Conn, error) {
	return dial(ctx, "tcp", address, port)
}

func dialUDP(ctx context.Context, address string, port int) (net.Conn, error) {
	return dial(ctx, "udp", address, port)
}

func dial(ctx context.Context, network, address string, port int) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	// probeOne's context carries the deadline that matters (its own
	// probeTimeout, capped by the sweep's own); applying it to the
	// connection itself is what actually bounds the reads and writes a
	// carrier does next, since net.Conn has no ctx-aware I/O of its own.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	return conn, nil
}

// drainBriefly discards up to budget's worth of whatever conn sends
// first (a banner, a login prompt, telnet option negotiation), so a
// carrier's following write lands after it rather than racing it. The
// read's outcome -- success, timeout, EOF -- is deliberately ignored:
// OpenCanary logs the credential from the packet it parses once the
// greeting is done, not from the greeting's own bytes, so nothing here
// needs to succeed for the write that follows to be well-formed.
//
// This only narrows the read deadline; the write deadline conn already
// carries (set by dial, above) is untouched, since SetReadDeadline
// governs the read half independently of SetDeadline's combined one.
func drainBriefly(conn net.Conn, budget time.Duration) {
	_ = conn.SetReadDeadline(time.Now().Add(budget))
	buf := make([]byte, 512)
	_, _ = conn.Read(buf)
}
