package probe

import (
	"context"
	"time"
)

// greetingBudget is how long probeFTP and probeTelnet wait for the
// service's own banner or prompt before writing the credential line
// regardless. It is a small slice of probeTimeout, not a protocol
// guarantee: both carriers write their credential even if nothing was
// read, since OpenCanary's own parser reads the credential from the
// line it receives next, not from having seen a specific prompt first.
const greetingBudget = 500 * time.Millisecond

// probeFTP plants marker as the USER command's argument -- the first
// credential-shaped thing an FTP client sends, and the field
// OpenCanary's ftp module logs (#46 carrier table).
func probeFTP(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	drainBriefly(conn, greetingBudget)
	_, err = conn.Write([]byte("USER " + marker + "\r\n"))
	return err
}

// probeTelnet plants marker as the username at the login prompt.
// Real telnet negotiates IAC options before showing that prompt; this
// carrier does not model that negotiation, only waits it out for
// greetingBudget and then sends the line a client would send once the
// prompt appears. OpenCanary's telnet module logs the line it reads as
// the username regardless of what, if anything, preceded it.
func probeTelnet(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	drainBriefly(conn, greetingBudget)
	_, err = conn.Write([]byte(marker + "\r\n"))
	return err
}
