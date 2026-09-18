package probe

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestDialTCP_Connects proves dialTCP reaches a live listener. Whether
// it actually applies ctx's deadline to the connection -- there is no
// exported way to read a net.Conn's configured deadline back to check
// directly -- is pinned indirectly by
// TestSweepWithConfig_BoundsTheWholeRun, which would hang instead of
// failing if that wiring broke.
func TestDialTCP_Connects(t *testing.T) {
	port := listenTCP(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialTCP(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("dialTCP: %v", err)
	}
	conn.Close()
}

func TestDialTCP_RefusedConnectionIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close() // nothing listens here now

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := dialTCP(ctx, "127.0.0.1", port); err == nil {
		t.Fatal("dialTCP against a closed port: want an error, got nil")
	}
}

func TestDrainBriefly_ConsumesWhateverArrivesFirst(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("220 greeting\r\n"))
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialTCP(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("dialTCP: %v", err)
	}
	defer conn.Close()

	// Should return promptly once the greeting arrives, well inside the
	// budget, and must not consume the write deadline dialTCP set.
	start := time.Now()
	drainBriefly(conn, time.Second)
	if time.Since(start) >= time.Second {
		t.Error("drainBriefly waited for the full budget instead of returning once data arrived")
	}

	if _, err := conn.Write([]byte("still writable\r\n")); err != nil {
		t.Errorf("write after drainBriefly: %v (drainBriefly must not touch the write deadline)", err)
	}
}
