package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

const smbFallbackTimeout = 5 * time.Second

// smb2Negotiate is one SMB2 NEGOTIATE request inside a NetBIOS session
// header: 64-byte SMB2 header (command 0, credit charge 1), then a
// 36-byte body offering dialect 2.0.2. Enough for any SMB2-capable server,
// the lure's Samba included, to answer with a reply starting \xfeSMB.
var smb2Negotiate = func() []byte {
	hdr := make([]byte, 64)
	copy(hdr, "\xfeSMB")
	hdr[4] = 64 // StructureSize
	hdr[6] = 1  // CreditCharge
	body := make([]byte, 36+2)
	body[0] = 36 // StructureSize
	body[2] = 1  // DialectCount
	body[4] = 1  // SecurityMode: signing enabled
	// Dialects start at offset 36: 0x0202.
	body[36] = 0x02
	body[37] = 0x02
	msg := append(hdr, body...)
	// The NetBIOS session header's 3-byte length: 64-byte header plus
	// 38-byte body, a constant, so no runtime narrowing is needed.
	const msgLen = 64 + 36 + 2
	return append([]byte{0x00, 0x00, 0x00, msgLen}, msg...)
}()

// ReachSMB dials address:port, sends one SMB2 NEGOTIATE and requires a
// reply carrying the SMB2 magic \xfeSMB (#243). It is a reachability
// check, not a marker carrier: the SMB lure logs only completed file
// closes, so nothing here can be matched in its log. Standard library
// only. ctx's deadline bounds the dial, the write and the read.
func ReachSMB(ctx context.Context, address string, port int) error {
	conn, err := dial(ctx, "tcp", address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after one request/reply; a failed close cannot
	// change the result.
	defer func() { _ = conn.Close() }()

	// dial applies ctx's deadline to the connection; set one here too for
	// a ctx with none, so a silent listener cannot hold the probe forever.
	if _, ok := ctx.Deadline(); !ok {
		_ = conn.SetDeadline(time.Now().Add(smbFallbackTimeout))
	}
	if _, err := conn.Write(smb2Negotiate); err != nil {
		return fmt.Errorf("smb: send negotiate: %w", err)
	}
	// NetBIOS header (4 bytes), then the SMB2 magic (4 bytes).
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("smb: read negotiate reply: %w", err)
	}
	if string(reply[4:8]) != "\xfeSMB" {
		return errors.New("smb: reply is not an SMB2 message")
	}
	return nil
}
