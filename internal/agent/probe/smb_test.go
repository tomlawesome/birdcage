package probe

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeSMBListener serves one reply to every connection after reading
// whatever the client sends first, and reports what it read. reply nil
// means close without answering.
func fakeSMBListener(t *testing.T, reply []byte) (port int, got <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() }) // test teardown; nothing left to act on a close error
	seen := make(chan []byte, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }() // test teardown; nothing left to act on a close error
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 512)
				n, _ := c.Read(buf)
				select {
				case seen <- buf[:n]:
				default:
				}
				if reply != nil {
					_, _ = c.Write(reply)
					_, _ = io.Copy(io.Discard, c)
				}
			}()
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port, seen
}

// TestReachSMB_SucceedsOnAnSMB2Reply: the lure answers a NEGOTIATE with a
// reply starting \xfeSMB, and that is all a pass needs (#243).
func TestReachSMB_SucceedsOnAnSMB2Reply(t *testing.T) {
	// A NetBIOS session header (type 0, length) then the SMB2 magic.
	reply := append([]byte{0x00, 0x00, 0x00, 0x08}, []byte("\xfeSMB\x00\x00\x00\x00")...)
	port, got := fakeSMBListener(t, reply)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := ReachSMB(ctx, "127.0.0.1", port); err != nil {
		t.Fatalf("ReachSMB against a listener that answers SMB2 = %v, want nil", err)
	}

	select {
	case first := <-got:
		// The probe sends one SMB2 NEGOTIATE: the magic is in the request.
		if !containsBytes(first, []byte("\xfeSMB")) {
			t.Errorf("the probe's first write does not carry the SMB2 magic: % x", first)
		}
	case <-time.After(2 * time.Second):
		t.Error("the listener never saw a request")
	}
}

// TestReachSMB_FailsWithoutAnSMBReply covers every way the lure can be
// listening yet not be the lure: no answer, a non-SMB answer, a reply
// that is too short, and nothing listening at all.
func TestReachSMB_FailsWithoutAnSMBReply(t *testing.T) {
	deadPort := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		_, p, _ := net.SplitHostPort(ln.Addr().String())
		_ = ln.Close() // freeing the port is the point
		n, _ := strconv.Atoi(p)
		return n
	}()

	silentPort, _ := fakeSMBListener(t, nil)
	httpPort, _ := fakeSMBListener(t, []byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	shortPort, _ := fakeSMBListener(t, []byte("\xfeSM"))

	tests := []struct {
		name string
		port int
	}{
		{"nothing listening", deadPort},
		{"listener closes without replying", silentPort},
		{"listener answers something that is not SMB", httpPort},
		{"reply too short to hold the magic", shortPort},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := ReachSMB(ctx, "127.0.0.1", tc.port); err == nil {
				t.Error("ReachSMB = nil, want an error: no \\xfeSMB reply came back")
			}
		})
	}
}

// TestReachSMB_HonorsTheDeadline: a listener that accepts and says
// nothing must not hold the probe past its context.
func TestReachSMB_HonorsTheDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }() // test teardown; nothing left to act on a close error
	go func() {
		c, err := ln.Accept()
		if err == nil {
			time.Sleep(3 * time.Second)
			_ = c.Close() // test teardown; nothing left to act on a close error
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := ReachSMB(ctx, "127.0.0.1", port); err == nil {
		t.Fatal("ReachSMB = nil against a silent listener, want an error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("ReachSMB took %s, want it bounded by the 300ms context", d)
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
