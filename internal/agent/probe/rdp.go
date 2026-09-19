package probe

import "context"

// probeRDP plants marker in the X.224 Connection Request's routing
// cookie, "Cookie: mstshash=<marker>\r\n" (#46 carrier table: "the
// username or equivalent first-credential field"). This is the same
// field RDP load balancers and, per public write-ups, most RDP scanning
// and fingerprinting tools use to carry a client-chosen username hint:
// it rides in cleartext on the very first TPKT/X.224 packet, well
// before any TLS or CredSSP negotiation, so no further handshake is
// needed to deliver it.
func probeRDP(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	cookie := []byte("Cookie: mstshash=" + marker + "\r\n")

	// X.224 Connection Request TDPU: CR-CDT, DST-REF, SRC-REF, CLASS
	// OPTION (6 fixed bytes), then the cookie as call user data.
	x224 := concat([]byte{0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}, cookie)

	// TPKT header: version 3, reserved 0, then the big-endian total
	// length (header + length-indicator byte + the X.224 TPDU).
	li := len(x224)
	total := 4 + 1 + li
	tpkt := concat(
		[]byte{0x03, 0x00, byte(total >> 8), byte(total), byte(li)},
		x224,
	)

	_, err = conn.Write(tpkt)
	return err
}
