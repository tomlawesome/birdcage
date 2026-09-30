package probe

import (
	"context"
	"errors"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// probeSSH plants marker as the username in a real SSH authentication
// attempt (#46 carrier table). Unlike every other carrier in this
// package, reaching the point where a username is transmitted requires
// a full key exchange -- SSH encrypts from just after the version
// banner, so there is no shortcut that stops short of a real handshake.
// This uses golang.org/x/crypto/ssh, the standard extended library for
// exactly this, rather than reimplementing SSH's transport and key
// exchange by hand.
//
// A rejected password is the expected, successful outcome: the point
// of this probe is that OpenCanary's ssh module logs the username from
// the authentication request it receives, not that this probe obtains
// a session. golang.org/x/crypto/ssh only reaches that rejection --
// and so only sends the marker username -- once the transport-level
// handshake (key exchange) has completed; every error from before or
// during that handshake (version mismatch, no common algorithm, a
// reset) never sent it, so those are treated as StatusFailed too, not
// just a timeout.
func probeSSH(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	cfg := &ssh.ClientConfig{
		User: marker,
		Auth: []ssh.AuthMethod{ssh.Password("birdcage-selftest")},
		// The probe is not trying to identify who it is talking to --
		// only to reach OpenCanary's own listener on this canary's own
		// address -- so there is no host key to have pinned in advance.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, cfg)
	if err == nil {
		// Unexpected (this probe's password is not a real credential),
		// but a connected client is still a fully successful probe.
		client := ssh.NewClient(sshConn, chans, reqs)
		_ = client.Close()
		return nil
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// "unable to authenticate" is the one error clientAuthenticate
	// itself produces once every offered method (here, just the
	// password) has been tried and rejected -- the only path that sent
	// the marker username. Any other error came from before or during
	// the handshake, so the username never reached the server.
	if strings.Contains(err.Error(), "unable to authenticate") {
		return nil
	}
	return err
}
