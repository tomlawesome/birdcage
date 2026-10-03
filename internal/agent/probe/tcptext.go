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

// selfTestPassword is the fixed, obviously-fake password every
// credential-shaped carrier sends alongside its marker, for the modules
// that only log once a password arrives (ftp, telnet, http). It carries
// no meaning of its own: the marker is the proof, this is the second
// field OpenCanary's own parser waits for. ssh.go uses the same word.
const selfTestPassword = "birdcage-selftest"

// probeFTP plants marker as the USER command's argument -- the first
// credential-shaped thing an FTP client sends, and the field
// OpenCanary's ftp module logs (#46 carrier table). The PASS that
// follows is what makes the module log at all: opencanary/modules/ftp.py
// logs USERNAME and PASSWORD together from ftp_PASS, never from ftp_USER
// alone (MR !60 pipeline 1524: a USER-only probe produced no event).
func probeFTP(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	drainBriefly(conn, greetingBudget)
	_, err = conn.Write([]byte("USER " + marker + "\r\nPASS " + selfTestPassword + "\r\n"))
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
	_, err = conn.Write([]byte(marker + "\r\n" + selfTestPassword + "\r\n"))
	return err
}
