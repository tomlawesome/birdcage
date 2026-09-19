package probe

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

// probePostgres plants marker as the "user" (and, for good measure,
// "database") startup parameter -- the first thing a Postgres client
// ever sends, in cleartext, before any auth exchange (#46 carrier
// table). No response is read: the startup message alone is enough for
// OpenCanary's postgres module to log the attempted user.
func probePostgres(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	body := concat(
		[]byte{0x00, 0x03, 0x00, 0x00}, // protocol version 3.0
		[]byte("user\x00"), []byte(marker), []byte{0x00},
		[]byte("database\x00"), []byte(marker), []byte{0x00},
		[]byte{0x00}, // parameter list terminator
	)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(4+len(body)))

	_, err = conn.Write(concat(length, body))
	return err
}

// probeRedis plants marker as the password in a RESP-encoded AUTH
// command (#46 carrier table: "the username or equivalent first-
// credential field" -- Redis's own AUTH has no separate username short
// of ACL-based multi-user setups, so the password is that field here).
func probeRedis(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	cmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(marker), marker)
	_, err = conn.Write([]byte(cmd))
	return err
}

// probeMySQL plants marker as the username in a HandshakeResponse41
// packet (#46 carrier table). MySQL's username field is plaintext on
// the wire regardless of auth plugin or CLIENT_SECURE_CONNECTION, so
// this carrier reads just enough of the server's initial handshake
// packet to learn its sequence number, then answers with a minimal
// response: no requested capabilities beyond CLIENT_PROTOCOL_41, no
// database, and an empty (also plaintext, since
// CLIENT_SECURE_CONNECTION is not set) auth-response.
func probeMySQL(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	r := bufio.NewReader(conn)
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return fmt.Errorf("probe: mysql: read handshake header: %w", err)
	}
	payloadLen := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	serverSeq := header[3]
	// The handshake payload itself is not needed -- only its length, to
	// discard it and reach whatever comes next cleanly.
	if _, err := io.ReadFull(r, make([]byte, payloadLen)); err != nil {
		return fmt.Errorf("probe: mysql: read handshake payload: %w", err)
	}

	const clientProtocol41 = 0x00000200
	payload := make([]byte, 0, 32+len(marker))
	payload = appendUint32LE(payload, clientProtocol41)
	payload = appendUint32LE(payload, 0x01000000)  // max packet size
	payload = append(payload, 0x21)                // utf8_general_ci
	payload = append(payload, make([]byte, 23)...) // reserved
	payload = append(payload, []byte(marker)...)
	payload = append(payload, 0x00) // NUL-terminated username
	payload = append(payload, 0x00) // empty auth-response (no CLIENT_SECURE_CONNECTION)

	respHeader := []byte{
		byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16),
		serverSeq + 1,
	}
	_, err = conn.Write(concat(respHeader, payload))
	return err
}

// probeMSSQL plants marker as the username in a TDS LOGIN7 packet
// (#46 carrier table), after a minimal PRELOGIN exchange -- real TDS
// servers expect PRELOGIN to precede LOGIN7, and OpenCanary's mssql
// module is expected to model that same ordering.
//
// This is the carrier this build is least confident of: the LOGIN7
// fixed-length header and offset table (94 bytes total: 36 bytes fixed
// fields, then 9 offset/length pairs, a 6-byte ClientID, and 3 more
// offset/length pairs plus cbSSPILong) is reconstructed from MS-TDS
// 2.2.6.4 rather than checked against a live SQL Server or against
// OpenCanary's own mssql module, which this build has no access to.
// Flagged in the build report for #46 as worth validating separately.
func probeMSSQL(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	if err := sendTDSPacket(conn, 0x12, buildPreLogin()); err != nil {
		return fmt.Errorf("probe: mssql: prelogin: %w", err)
	}
	// The response's content is not needed -- only draining it so our
	// LOGIN7 packet does not arrive while the server is still writing
	// its own PRELOGIN response.
	drainBriefly(conn, greetingBudget)

	if err := sendTDSPacket(conn, 0x10, buildLogin7(marker)); err != nil {
		return fmt.Errorf("probe: mssql: login7: %w", err)
	}
	return nil
}

// sendTDSPacket wraps payload in one TDS packet: an 8-byte header
// (type, status=EOM, big-endian length, SPID, packet id, window), then
// the payload. Every packet this package sends fits in one TDS packet
// (no multi-packet messages).
func sendTDSPacket(conn interface{ Write([]byte) (int, error) }, packetType byte, payload []byte) error {
	total := 8 + len(payload)
	header := []byte{
		packetType,
		0x01,                          // status: EOM
		byte(total >> 8), byte(total), // length, big-endian
		0x00, 0x00, // SPID
		0x01, // packet ID
		0x00, // window
	}
	_, err := conn.Write(concat(header, payload))
	return err
}

// buildPreLogin builds a minimal TDS PRELOGIN payload: VERSION,
// ENCRYPTION (declared unsupported, so the server does not expect this
// probe to upgrade to TLS), INSTOPT, THREADID, MARS, then the
// terminator token.
func buildPreLogin() []byte {
	data := concat(
		[]byte{0, 0, 0, 0, 0, 0}, // VERSION: 4-byte version + 2-byte subbuild, all zero
		[]byte{0x02},             // ENCRYPTION: ENCRYPT_NOT_SUP
		[]byte{0x00},             // INSTOPT: empty instance name, NUL-terminated
		[]byte{0, 0, 0, 0},       // THREADID
		[]byte{0x00},             // MARS: off
	)

	type tokenSpan struct {
		token          byte
		offset, length uint16
	}
	spans := []tokenSpan{
		{0x00, 0, 6},
		{0x01, 6, 1},
		{0x02, 7, 1},
		{0x03, 8, 4},
		{0x04, 12, 1},
	}
	// Offsets are relative to the start of data, but data itself comes
	// after the token table in the packet, so every offset is shifted
	// by the table's own size: 5 tokens * 5 bytes each + 1 terminator.
	tableLen := uint16(len(spans)*5 + 1)

	var table []byte
	for _, s := range spans {
		table = append(table, s.token)
		table = appendUint16BE(table, s.offset+tableLen)
		table = appendUint16BE(table, s.length)
	}
	table = append(table, 0xFF) // terminator

	return concat(table, data)
}

// buildLogin7 builds a TDS LOGIN7 packet carrying marker as the
// username, with every other variable field empty. See probeMSSQL's
// comment for the offset table this follows (MS-TDS 2.2.6.4).
func buildLogin7(marker string) []byte {
	const headerLen = 94 // 36-byte fixed header + 58-byte offset/length table

	username := utf16LE(marker)
	appName := utf16LE("birdcage-selftest")
	varData := concat(username, appName)

	total := headerLen + len(varData)

	buf := make([]byte, 0, total)
	buf = appendUint32LE(buf, uint32(total))  // Length
	buf = appendUint32LE(buf, 0x74000004)     // TDSVersion 7.4
	buf = appendUint32LE(buf, 0x00001000)     // PacketSize
	buf = appendUint32LE(buf, 0)              // ClientProgVer
	buf = appendUint32LE(buf, 0)              // ClientPID
	buf = appendUint32LE(buf, 0)              // ConnectionID
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // OptionFlags1, OptionFlags2, TypeFlags, OptionFlags3
	buf = appendUint32LE(buf, 0)              // ClientTimeZone
	buf = appendUint32LE(buf, 0)              // ClientLCID

	pos := uint16(headerLen)
	buf = appendOffLen(buf, pos, 0) // ibHostName, cchHostName

	buf = appendOffLen(buf, pos, uint16(len([]rune(marker)))) // ibUserName, cchUserName
	pos += uint16(len(username))

	buf = appendOffLen(buf, pos, 0) // ibPassword, cchPassword

	buf = appendOffLen(buf, pos, uint16(len([]rune("birdcage-selftest")))) // ibAppName, cchAppName
	pos += uint16(len(appName))

	buf = appendOffLen(buf, pos, 0)     // ibServerName, cchServerName
	buf = appendOffLen(buf, pos, 0)     // ibExtension, cbExtension
	buf = appendOffLen(buf, pos, 0)     // ibCltIntName, cchCltIntName
	buf = appendOffLen(buf, pos, 0)     // ibLanguage, cchLanguage
	buf = appendOffLen(buf, pos, 0)     // ibDatabase, cchDatabase
	buf = append(buf, 0, 0, 0, 0, 0, 0) // ClientID
	buf = appendOffLen(buf, pos, 0)     // ibSSPI, cchSSPI
	buf = appendOffLen(buf, pos, 0)     // ibAtchDBFile, cchAtchDBFile
	buf = appendOffLen(buf, pos, 0)     // ibChangePassword, cchChangePassword
	buf = appendUint32LE(buf, 0)        // cbSSPILong

	buf = append(buf, varData...)
	return buf
}

func appendOffLen(buf []byte, offset, length uint16) []byte {
	buf = appendUint16LE(buf, offset)
	buf = appendUint16LE(buf, length)
	return buf
}

func appendUint16LE(buf []byte, v uint16) []byte {
	return append(buf, byte(v), byte(v>>8))
}

func appendUint16BE(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

func appendUint32LE(buf []byte, v uint32) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// utf16LE encodes s as TDS expects its strings: UCS-2, little-endian,
// not NUL-terminated.
func utf16LE(s string) []byte {
	codes := utf16.Encode([]rune(s))
	buf := make([]byte, len(codes)*2)
	for i, c := range codes {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}
	return buf
}
