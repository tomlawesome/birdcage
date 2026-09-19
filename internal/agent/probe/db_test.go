package probe

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"testing"
	"time"
	"unicode/utf16"
)

// acceptOneAndCapture starts a TCP listener whose handler is exchange,
// and returns the port to connect to plus a channel carrying whatever
// exchange writes as its final result.
func acceptOneAndCapture(t *testing.T, exchange func(net.Conn) []byte) (port int, resultCh <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() }) // test teardown; nothing left to act on a close error

	ch := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }() // test teardown; nothing left to act on a close error
		ch <- exchange(c)
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port, ch
}

func TestProbePostgres_PlantsMarkerAsStartupUser(t *testing.T) {
	port, resultCh := acceptOneAndCapture(t, func(c net.Conn) []byte {
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		return buf[:n]
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probePostgres(ctx, "127.0.0.1", port, "marker-pg"); err != nil {
		t.Fatalf("probePostgres: %v", err)
	}

	pkt := recvOrFail(t, resultCh)
	if !bytes.Contains(pkt, []byte("user\x00marker-pg\x00")) {
		t.Errorf("startup packet % x does not carry the marker as the user parameter", pkt)
	}
}

func TestProbeRedis_PlantsMarkerAsAUTHArgument(t *testing.T) {
	port, resultCh := acceptOneAndCapture(t, func(c net.Conn) []byte {
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		return buf[:n]
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeRedis(ctx, "127.0.0.1", port, "marker-redis"); err != nil {
		t.Fatalf("probeRedis: %v", err)
	}

	pkt := string(recvOrFail(t, resultCh))
	want := "*2\r\n$4\r\nAUTH\r\n$12\r\nmarker-redis\r\n"
	if pkt != want {
		t.Errorf("got RESP command %q, want %q", pkt, want)
	}
}

func TestProbeMySQL_PlantsMarkerAsHandshakeUsername(t *testing.T) {
	port, resultCh := acceptOneAndCapture(t, func(c net.Conn) []byte {
		// A minimal server initial handshake packet: header (length=1,
		// sequence=0) then a single payload byte. The client under
		// test only needs the length and sequence number to respond;
		// the payload's content is never interpreted.
		_, _ = c.Write([]byte{0x01, 0x00, 0x00, 0x00, 0x0A}) // fixture write; a failure surfaces as a mismatch below
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		return buf[:n]
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeMySQL(ctx, "127.0.0.1", port, "marker-mysql"); err != nil {
		t.Fatalf("probeMySQL: %v", err)
	}

	pkt := recvOrFail(t, resultCh)
	if pkt[3] != 0x01 {
		t.Errorf("response sequence number = %d, want 1 (server's 0 + 1)", pkt[3])
	}
	if !bytes.Contains(pkt, []byte("marker-mysql\x00")) {
		t.Errorf("handshake response % x does not carry the marker as a NUL-terminated username", pkt)
	}
}

func TestProbeMSSQL_PlantsMarkerAsLogin7Username(t *testing.T) {
	port, resultCh := acceptOneAndCapture(t, func(c net.Conn) []byte {
		// Drain the PRELOGIN packet, answer with a trivial PRELOGIN
		// response so the client's own drainBriefly has something to
		// consume, then capture the LOGIN7 packet that follows.
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)                                                           // fixture drain; a failure surfaces as a mismatch below
		_, _ = c.Write([]byte{0x04, 0x01, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0xFF}) // fixture write; a failure surfaces as a mismatch below
		n, _ := c.Read(buf)
		return buf[:n]
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeMSSQL(ctx, "127.0.0.1", port, "marker-mssql"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}

	pkt := recvOrFail(t, resultCh)
	if pkt[0] != 0x10 {
		t.Errorf("TDS packet type = 0x%02x, want 0x10 (LOGIN7)", pkt[0])
	}
	wantUser := utf16.Encode([]rune("marker-mssql"))
	wantBytes := make([]byte, len(wantUser)*2)
	for i, c := range wantUser {
		wantBytes[i*2] = byte(c)
		wantBytes[i*2+1] = byte(c >> 8)
	}
	if !bytes.Contains(pkt, wantBytes) {
		t.Errorf("LOGIN7 packet % x does not carry the marker as a UTF-16LE username", pkt)
	}
}
