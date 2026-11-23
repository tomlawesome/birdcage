package probe

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// Tests for #254: a probe that ends by writing its marker must not close
// with unread server data (a TCP reset can make the server's kernel drop
// the marker it has not read yet).

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
func tdsPacket(typ byte, n int) []byte {
	total := 8 + n
	p := make([]byte, total)
	p[0], p[1], p[2], p[3], p[6] = typ, 0x01, byte(total>>8), byte(total), 0x01
	for i := 8; i < total; i++ {
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
		want = append(want, byte(c), byte(c>>8))
	}
	if !bytes.Contains(r.pkt, want) {
		t.Errorf("LOGIN7 does not contain the UTF-16LE marker %q", marker)
	}
}

// mssqlServer reads PRELOGIN, sends each reply chunk after its delay,
// waits settle so the client has sent LOGIN7 and closed, then reads LOGIN7.
func mssqlServer(t *testing.T, delays []time.Duration, chunks [][]byte, settle time.Duration) (int, <-chan tdsResult) {
	return closeFixture(t, func(c net.Conn) tdsResult {
		if r := readTDS(c); r.err != nil {
			return r
		}
		for i, ch := range chunks {
			time.Sleep(delays[i])
			_, _ = c.Write(ch) // fixture write; a failure shows up as a failed read below
		}
		time.Sleep(settle)
		return readTDS(c)
	})
}

func runMSSQL(t *testing.T, port int, marker string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return probeMSSQL(ctx, "127.0.0.1", port, marker)
}

func awaitTDS(t *testing.T, ch <-chan tdsResult) tdsResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the server's read")
		return tdsResult{}
	}
}

func TestProbeMSSQL_LatePreloginReplyStillDeliversLogin7(t *testing.T) {
	late := greetingBudget + 200*time.Millisecond
	port, ch := mssqlServer(t, []time.Duration{late}, [][]byte{tdsPacket(0x04, 40)}, 150*time.Millisecond)
	if err := runMSSQL(t, port, "marker-mssql-late"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}
	checkLogin7(t, awaitTDS(t, ch), "marker-mssql-late")
}

func TestProbeMSSQL_LateLongPreloginReplyStillDeliversLogin7(t *testing.T) {
	late := greetingBudget + 200*time.Millisecond
	port, ch := mssqlServer(t, []time.Duration{late}, [][]byte{tdsPacket(0x04, 1500)}, 150*time.Millisecond)
	if err := runMSSQL(t, port, "marker-mssql-long"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}
	checkLogin7(t, awaitTDS(t, ch), "marker-mssql-long")
}

func TestProbeMSSQL_SplitPreloginReplyStillDeliversLogin7(t *testing.T) {
	pkt := tdsPacket(0x04, 40)
	port, ch := mssqlServer(t,
		[]time.Duration{50 * time.Millisecond, 200 * time.Millisecond},
		[][]byte{pkt[:20], pkt[20:]}, 150*time.Millisecond)
	if err := runMSSQL(t, port, "marker-mssql-split"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}
	checkLogin7(t, awaitTDS(t, ch), "marker-mssql-split")
}

func TestProbeMSSQL_SlowReaderGetsLogin7AfterUnreadReply(t *testing.T) {
	// Reply longer than one drain read (512 bytes) sent at once; the
	// server then reads slowly.
	port, ch := mssqlServer(t, []time.Duration{0}, [][]byte{tdsPacket(0x04, 1500)}, 400*time.Millisecond)
	if err := runMSSQL(t, port, "marker-mssql-slow"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}
	checkLogin7(t, awaitTDS(t, ch), "marker-mssql-slow")
}

// textServer sends greeting at once, then reads slowly after settle,
// returning everything up to the client's close (or 2 s).
func textServer(t *testing.T, greeting []byte, settle time.Duration) (int, <-chan string) {
	return closeFixture(t, func(c net.Conn) string {
		_, _ = c.Write(greeting) // fixture write
		time.Sleep(settle)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(c)
		return string(b)
	})
}

func runText(t *testing.T, f func(context.Context, string, int, string) error, port int, marker string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return f(ctx, "127.0.0.1", port, marker)
}

func awaitStr(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the server's read")
		return ""
	}
}

func TestProbeFTP_LateGreetingStillDeliversCredential(t *testing.T) {
	late := greetingBudget + 200*time.Millisecond
	port, ch := closeFixture(t, func(c net.Conn) string {
		time.Sleep(late)
		_, _ = c.Write([]byte("220 welcome\r\n")) // fixture write
		time.Sleep(150 * time.Millisecond)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(c)
		return string(b)
	})
	if err := runText(t, probeFTP, port, "marker-ftp-late"); err != nil {
		t.Fatalf("probeFTP: %v", err)
	}
	if got := awaitStr(t, ch); !strings.Contains(got, "USER marker-ftp-late\r\n") {
		t.Errorf("server received %q, want the USER line with the marker", got)
	}
}

func TestProbeTelnet_LateGreetingStillDeliversCredential(t *testing.T) {
	late := greetingBudget + 200*time.Millisecond
	port, ch := closeFixture(t, func(c net.Conn) string {
		time.Sleep(late)
		_, _ = c.Write([]byte("login: ")) // fixture write
		time.Sleep(150 * time.Millisecond)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(c)
		return string(b)
	})
	if err := runText(t, probeTelnet, port, "marker-telnet-late"); err != nil {
		t.Fatalf("probeTelnet: %v", err)
	}
	if got := awaitStr(t, ch); !strings.Contains(got, "marker-telnet-late\r\n") {
		t.Errorf("server received %q, want the marker line", got)
	}
}

func TestProbeFTP_SlowReaderGetsCredentialAfterUnreadGreeting(t *testing.T) {
	// Greeting longer than one drain read (512 bytes): unread data at close.
	greeting := []byte("220 " + strings.Repeat("x", 1500) + "\r\n")
	port, ch := textServer(t, greeting, 400*time.Millisecond)
	if err := runText(t, probeFTP, port, "marker-ftp-slow"); err != nil {
		t.Fatalf("probeFTP: %v", err)
	}
	want := "USER marker-ftp-slow\r\nPASS " + selfTestPassword + "\r\n"
	if got := awaitStr(t, ch); got != want {
		t.Errorf("server received %q, want %q", got, want)
	}
}

func TestProbeTelnet_SlowReaderGetsCredentialAfterUnreadGreeting(t *testing.T) {
	greeting := []byte(strings.Repeat("x", 1500) + "login: ")
	port, ch := textServer(t, greeting, 400*time.Millisecond)
	if err := runText(t, probeTelnet, port, "marker-telnet-slow"); err != nil {
		t.Fatalf("probeTelnet: %v", err)
	}
	want := "marker-telnet-slow\r\n" + selfTestPassword + "\r\n"
	if got := awaitStr(t, ch); got != want {
		t.Errorf("server received %q, want %q", got, want)
	}
}

// A server that reads everything but never closes must not hold the
// probe past its half-close wait bound (2 s) plus a small margin.
func TestProbe_NeverClosingServerIsBounded(t *testing.T) {
	const bound = 2*time.Second + 400*time.Millisecond
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })

	ftpPort, _ := closeFixture(t, func(c net.Conn) struct{} {
		_, _ = c.Write([]byte("220 hi\r\n")) // fixture write
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadFull(c, make([]byte, 8))
		<-hold
		return struct{}{}
	})
	start := time.Now()
	if err := runText(t, probeFTP, ftpPort, "marker-hold"); err != nil {
		t.Fatalf("probeFTP: %v", err)
	}
	if d := time.Since(start); d > bound {
		t.Errorf("probeFTP took %v against a server that never closes, want <= %v", d, bound)
	}

	mssqlPort, _ := closeFixture(t, func(c net.Conn) struct{} {
		if r := readTDS(c); r.err == nil {
			_, _ = c.Write(tdsPacket(0x04, 20)) // fixture write
		}
		readTDS(c)
		<-hold
		return struct{}{}
	})
	start = time.Now()
	if err := runMSSQL(t, mssqlPort, "marker-hold"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}
	if d := time.Since(start); d > bound {
		t.Errorf("probeMSSQL took %v against a server that never closes, want <= %v", d, bound)
	}
}

// A connection reset before the probe can write is still a failure.
func TestProbe_FailedWriteStillReturnsError(t *testing.T) {
	for name, run := range map[string]func(int) error{
		"ftp":   func(p int) error { return runText(t, probeFTP, p, "marker-fail") },
		"mssql": func(p int) error { return runMSSQL(t, p, "marker-fail") },
	} {
		t.Run(name, func(t *testing.T) {
			port, _ := closeFixture(t, func(c net.Conn) struct{} {
				resetClose(c)
				return struct{}{}
			})
			if err := run(port); err == nil {
				t.Error("probe returned nil after the server reset the connection before any write, want an error")
			}
		})
	}
}

// A completed exchange stays a success even if the server resets the
// connection after reading everything.
func TestProbe_SuccessSurvivesResetAfterRead(t *testing.T) {
	t.Run("ftp", func(t *testing.T) {
		port, _ := closeFixture(t, func(c net.Conn) struct{} {
			_, _ = c.Write([]byte("220 hi\r\n")) // fixture write
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			want := len("USER marker-rst\r\nPASS " + selfTestPassword + "\r\n")
			_, _ = io.ReadFull(c, make([]byte, want))
			resetClose(c)
			return struct{}{}
		})
		if err := runText(t, probeFTP, port, "marker-rst"); err != nil {
			t.Errorf("probeFTP = %v, want nil (write succeeded; reset came after)", err)
		}
	})
	t.Run("mssql", func(t *testing.T) {
		port, _ := closeFixture(t, func(c net.Conn) struct{} {
			if r := readTDS(c); r.err == nil {
				_, _ = c.Write(tdsPacket(0x04, 20)) // fixture write
			}
			readTDS(c)
			resetClose(c)
			return struct{}{}
		})
		if err := runMSSQL(t, port, "marker-rst"); err != nil {
			t.Errorf("probeMSSQL = %v, want nil (write succeeded; reset came after)", err)
		}
	})
}

func TestProbeMSSQL_LateSplitPreloginReplyStillDeliversLogin7(t *testing.T) {
	// First part inside the drain budget (so the single drain read returns
	// it and LOGIN7 goes out), the remainder after the probe has closed.
	pkt := tdsPacket(0x04, 600)
	port, ch := mssqlServer(t,
		[]time.Duration{50 * time.Millisecond, greetingBudget + 200*time.Millisecond},
		[][]byte{pkt[:100], pkt[100:]}, 150*time.Millisecond)
	if err := runMSSQL(t, port, "marker-mssql-latesplit"); err != nil {
		t.Fatalf("probeMSSQL: %v", err)
	}
	checkLogin7(t, awaitTDS(t, ch), "marker-mssql-latesplit")
}
