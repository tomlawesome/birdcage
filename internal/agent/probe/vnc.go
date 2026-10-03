package probe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// vncChallengeLen is RFC 6143 section 7.2.2's own constant: VNC
// Authentication's challenge and response are each exactly 16 bytes.
const vncChallengeLen = 16

// probeVNC completes just enough of the RFB handshake to reach VNC
// Authentication, then answers OpenCanary's 16-byte challenge with
// HMAC-SHA256(marker, challenge), truncated to vncChallengeLen bytes
// (#46 slice 2, "challenge-marked" grade -- notes 19854/19855/19897).
//
// Classic RFB authentication is a DES challenge keyed on the real VNC
// password, so unlike every other carrier in this package there is no
// attacker-chosen plaintext field to plant a marker in. But OpenCanary's
// own module logs both halves verbatim and validates neither (vnc.py's
// _recv_auth: it decrypts the response only afterward, against a short
// list of common passwords, purely to fill in a cosmetic field) -- so an
// HMAC of the marker over that connection's own random challenge lands
// in the log instead. Unlike a plaintext marker, this is not replayable:
// the server draws a fresh challenge every connection, so a response
// captured from an earlier run answers nothing on this one.
// internal/store/selftest_vnc.go recomputes the same HMAC server-side.
func probeVNC(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's handshake; a failed close here
	// can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	// ProtocolVersion handshake (RFC 6143 7.1.1): the server sends
	// "RFB xxx.yyy\n", exactly 12 bytes. Echoed back verbatim rather
	// than hardcoding a version: OpenCanary's own module only ever
	// offers 3.3, 3.7 or 3.8 (vnc.py's RFB_33/37/38 checked in
	// _recv_handshake), so echoing whatever it actually sent always
	// agrees with it regardless of which one a deployment configures.
	serverVersion := make([]byte, 12)
	if _, err := io.ReadFull(conn, serverVersion); err != nil {
		return fmt.Errorf("vnc: read protocol version: %w", err)
	}
	if string(serverVersion[:3]) != "RFB" {
		return errors.New("vnc: not an RFB server")
	}
	if _, err := conn.Write(serverVersion); err != nil {
		return fmt.Errorf("vnc: send protocol version: %w", err)
	}

	// Security handshake (RFC 6143 7.1.2, the 3.7-onwards shape --
	// OpenCanary's else-branch takes it once it has accepted any
	// version 3.7 or 3.8 client, which this probe always claims to be):
	// one length byte, then that many one-byte security-type codes.
	// OpenCanary's own _recv_security accepts any single-byte reply
	// (its length check only rejects anything other than exactly one
	// byte), so this selects whichever type it listed first, the same
	// as a real client would when only one type is on offer.
	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil {
		return fmt.Errorf("vnc: read security type count: %w", err)
	}
	n := int(count[0])
	if n == 0 {
		return errors.New("vnc: server offered no security types")
	}
	types := make([]byte, n)
	if _, err := io.ReadFull(conn, types); err != nil {
		return fmt.Errorf("vnc: read security types: %w", err)
	}
	if _, err := conn.Write(types[:1]); err != nil {
		return fmt.Errorf("vnc: select security type: %w", err)
	}

	// VNC Authentication (RFC 6143 7.2.2): the server's own 16-byte
	// challenge, answered with this run's marker HMACed over it.
	challenge := make([]byte, vncChallengeLen)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return fmt.Errorf("vnc: read challenge: %w", err)
	}
	markerBytes, err := hex.DecodeString(marker)
	if err != nil {
		return fmt.Errorf("vnc: marker is not valid hex: %w", err)
	}
	mac := hmac.New(sha256.New, markerBytes)
	mac.Write(challenge)
	response := mac.Sum(nil)[:vncChallengeLen]
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("vnc: send challenge response: %w", err)
	}

	// OpenCanary logs the attempt the instant it has the response --
	// vnc.py's _recv_auth calls factory.log before it ever writes the
	// "authentication failure" reply -- so this probe's job is done the
	// moment the response is on the wire. Reading that reply is not
	// needed to know the marker landed, and the server closes the
	// connection right after sending it regardless.
	return nil
}
