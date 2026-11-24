package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// Tests for #254: OpenCanary's mssql module parses at most one TDS packet
// per read, so the probe must send LOGIN7 only after the whole PRELOGIN
// reply has arrived (never both packets in one read).

// closeFixture listens on 127.0.0.1, runs handle on the first connection
// and reports its result on a channel.
func closeFixture[T any](t *testing.T, handle func(net.Conn) T) (int, <-chan T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() }) // test teardown
	ch := make(chan T, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }() // test teardown
		ch <- handle(c)
	}()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(ps)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return port, ch
}

// resetClose closes c with a TCP reset instead of a normal close.
func resetClose(c net.Conn) {
	_ = c.(*net.TCPConn).SetLinger(0) // fixture; cannot fail on a live TCP conn
	_ = c.Close()
}

// tdsPacket builds a TDS packet of the given type with a payload of n bytes.
func tdsPacket(typ byte, n uint16) []byte {
	total := 8 + n
	p := make([]byte, total)
	p[0], p[1], p[6] = typ, 0x01, 0x01
	binary.BigEndian.PutUint16(p[2:4], total)
	for i := 8; i < int(total); i++ {
		p[i] = 0xAB
	}
	return p
}

type tdsResult struct {
	pkt []byte
	err error
}

// readTDS reads one whole TDS packet (by its header length) within 2 s.
func readTDS(c net.Conn) tdsResult {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	hdr := make([]byte, 8)
	if n, err := io.ReadFull(c, hdr); err != nil {
		return tdsResult{hdr[:n], err}
	}
	total := int(hdr[2])<<8 | int(hdr[3])
	if total < 8 {
		return tdsResult{hdr, io.ErrUnexpectedEOF}
	}
	body := make([]byte, total-8)
	n, err := io.ReadFull(c, body)
	return tdsResult{append(hdr, body[:n]...), err}
}

func checkLogin7(t *testing.T, r tdsResult, marker string) {
	t.Helper()
	if r.err != nil {
		t.Fatalf("server read of LOGIN7 failed after %d bytes: %v", len(r.pkt), r.err)
	}
	if r.pkt[0] != 0x10 {
		t.Errorf("packet type = %#x, want 0x10 (LOGIN7)", r.pkt[0])
	}
	u := utf16.Encode([]rune(marker))
	want := make([]byte, 0, len(u)*2)
	for _, c := range u {
		want = binary.LittleEndian.AppendUint16(want, c)
	}
	if !bytes.Contains(r.pkt, want) {
		t.Errorf("LOGIN7 does not contain the UTF-16LE marker %q", marker)
	}
}

func runMSSQL(t *testing.T, port int, marker string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return probeMSSQL(ctx, "127.0.0.1", port, marker)
}

func awaitTDS(t *testing.T, ch <-chan tdsResult) tdsResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for the server")
		return tdsResult{}
	}
}

// The server does not read until after the probe's 500 ms drain budget.
// Its first read must hold exactly the PRELOGIN packet.
func TestProbeMSSQL_FirstReadHoldsOnlyPrelogin(t *testing.T) {
	port, ch := closeFixture(t, func(c net.Conn) tdsResult {
		time.Sleep(greetingBudget + 300*time.Millisecond)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		if err != nil {
			return tdsResult{buf[:n], err}
		}
		if n < 8 {
			return tdsResult{buf[:n], io.ErrUnexpectedEOF}
		}
		if want := int(buf[2])<<8 | int(buf[3]); n != want || buf[0] != 0x12 {
			t.Errorf("first read held %d bytes (type %#x), want exactly the %d-byte PRELOGIN packet (type 0x12)", n, buf[0], want)
		}
		_, _ = c.Write(tdsPacket(0x04, 40)) // fixture write
		return readTDS(c)
	})
	if err := runMSSQL(t, port, "marker-mssql-first"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}
	checkLogin7(t, awaitTDS(t, ch), "marker-mssql-first")
}

// A server that never answers PRELOGIN: the probe must fail naming the
// PRELOGIN reply, within its bound, and never send LOGIN7.
func TestProbeMSSQL_NoPreloginReplyIsAnErrorAndSendsNoLogin7(t *testing.T) {
	port, ch := closeFixture(t, func(c net.Conn) tdsResult {
		if r := readTDS(c); r.err != nil {
			return r
		}
		_ = c.SetReadDeadline(time.Now().Add(6 * time.Second))
		b, err := io.ReadAll(c) // until the probe closes
		_ = err                 // a deadline or reset just ends the read
		return tdsResult{pkt: b}
	})
	start := time.Now()
	err := runMSSQL(t, port, "marker-mssql-silent")
	if d := time.Since(start); d > 7500*time.Millisecond {
		t.Errorf("probeMSSQL took %v, want <= 7.5 s", d)
	}
	if err == nil {
		t.Error("probeMSSQL = nil with no PRELOGIN reply, want an error")
	} else if !strings.Contains(strings.ToLower(err.Error()), "prelogin") {
		t.Errorf("error %q does not name the PRELOGIN reply", err)
	}
	if r := awaitTDS(t, ch); len(r.pkt) != 0 {
		t.Errorf("server received %d bytes after PRELOGIN, want none (no LOGIN7 without a reply)", len(r.pkt))
	}
}

// A reply split across two writes with a gap: LOGIN7 only after the
// second part.
func TestProbeMSSQL_SplitReplySendsLogin7OnlyAfterSecondPart(t *testing.T) {
	pkt := tdsPacket(0x04, 600)
	port, ch := closeFixture(t, func(c net.Conn) tdsResult {
		if r := readTDS(c); r.err != nil {
			return r
		}
		_, _ = c.Write(pkt[:100]) // fixture write
		_ = c.SetReadDeadline(time.Now().Add(900 * time.Millisecond))
		if n, _ := c.Read(make([]byte, 4096)); n > 0 {
			t.Errorf("probe sent %d bytes before the PRELOGIN reply was complete", n)
		}
		_, _ = c.Write(pkt[100:]) // fixture write
		return readTDS(c)
	})
	if err := runMSSQL(t, port, "marker-mssql-split"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}
	checkLogin7(t, awaitTDS(t, ch), "marker-mssql-split")
}

// Unchanged: a prompt reply still gets the LOGIN7 with the marker.
func TestProbeMSSQL_PromptReplyStillDeliversLogin7(t *testing.T) {
	port, ch := closeFixture(t, func(c net.Conn) tdsResult {
		if r := readTDS(c); r.err != nil {
			return r
		}
		_, _ = c.Write(tdsPacket(0x04, 40)) // fixture write
		return readTDS(c)
	})
	if err := runMSSQL(t, port, "marker-mssql-prompt"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}
	checkLogin7(t, awaitTDS(t, ch), "marker-mssql-prompt")
}

// Unchanged: a failed write is still a failure.
func TestProbeMSSQL_FailedWriteStillReturnsError(t *testing.T) {
	port, _ := closeFixture(t, func(c net.Conn) struct{} {
		resetClose(c)
		return struct{}{}
	})
	if err := runMSSQL(t, port, "marker-mssql-fail"); err == nil {
		t.Error("probeMSSQL returned nil after the server reset the connection, want an error")
	}
}
