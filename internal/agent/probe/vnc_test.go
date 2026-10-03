package probe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestProbeVNC_AnswersChallengeWithHMACOfMarker runs a fake server that
// speaks just enough RFB to reach VNC Authentication -- the shape
// vnc.py's own state machine follows (PRE_INIT -> HANDSHAKE_SEND ->
// SECURITY_SEND -> AUTH_SEND) -- and checks that probeVNC's response is
// exactly HMAC-SHA256(marker, challenge) truncated to 16 bytes, the same
// computation internal/store/selftest_vnc.go's verifyVNCChallenge makes
// server-side.
func TestProbeVNC_AnswersChallengeWithHMACOfMarker(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }() // test teardown; nothing left to act on a close error

	challenge := make([]byte, vncChallengeLen)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatalf("generate challenge: %v", err)
	}

	gotResponse := make(chan []byte, 1)
	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer func() { _ = c.Close() }() // test teardown; nothing left to act on a close error

		if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
			serverErr <- err
			return
		}
		clientVersion := make([]byte, 12)
		if _, err := io.ReadFull(c, clientVersion); err != nil {
			serverErr <- err
			return
		}
		if _, err := c.Write([]byte{0x01, 0x02}); err != nil { // one security type: VNC Authentication
			serverErr <- err
			return
		}
		var selected [1]byte
		if _, err := io.ReadFull(c, selected[:]); err != nil {
			serverErr <- err
			return
		}
		if _, err := c.Write(challenge); err != nil {
			serverErr <- err
			return
		}
		response := make([]byte, vncChallengeLen)
		if _, err := io.ReadFull(c, response); err != nil {
			serverErr <- err
			return
		}
		gotResponse <- response
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	marker := "0123456789abcdef0123456789abcdef" // 32 hex chars, selftest.MarkerBytes-shaped
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeVNC(ctx, "127.0.0.1", port, marker); err != nil {
		t.Fatalf("probeVNC: %v", err)
	}

	select {
	case err := <-serverErr:
		t.Fatalf("fake RFB server: %v", err)
	case response := <-gotResponse:
		markerBytes, _ := hex.DecodeString(marker)
		mac := hmac.New(sha256.New, markerBytes)
		mac.Write(challenge)
		want := mac.Sum(nil)[:vncChallengeLen]
		if !bytes.Equal(response, want) {
			t.Errorf("response = %x, want HMAC-SHA256(marker, challenge)[:16] = %x", response, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fake RFB server never received a response")
	}
}

func TestProbeVNC_DialFailureIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	_ = ln.Close() // nothing listens here now

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probeVNC(ctx, "127.0.0.1", port, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("probeVNC against a closed port: want an error, got nil")
	}
}

// vncFakeServer starts a loopback listener that runs handle against the
// first accepted connection in its own goroutine, and returns the port
// to dial -- the shared shape every handshake-failure test below needs.
func vncFakeServer(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }() // test teardown; nothing left to act on a close error
		handle(c)
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

func TestProbeVNC_NotAnRFBServerIsAnError(t *testing.T) {
	port := vncFakeServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("NOTRFBxxxxx\n")) // 12 bytes, wrong prefix
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeVNC(ctx, "127.0.0.1", port, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("probeVNC against a non-RFB server: want an error, got nil")
	}
}

func TestProbeVNC_ServerClosesBeforeSecurityCountIsAnError(t *testing.T) {
	port := vncFakeServer(t, func(c net.Conn) {
		if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
			return
		}
		clientVersion := make([]byte, 12)
		_, _ = io.ReadFull(c, clientVersion)
		// Closed by the deferred c.Close() without ever sending a
		// security type count.
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeVNC(ctx, "127.0.0.1", port, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("probeVNC when the server closes before sending security types: want an error, got nil")
	}
}

func TestProbeVNC_ZeroSecurityTypesIsAnError(t *testing.T) {
	port := vncFakeServer(t, func(c net.Conn) {
		if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
			return
		}
		clientVersion := make([]byte, 12)
		if _, err := io.ReadFull(c, clientVersion); err != nil {
			return
		}
		_, _ = c.Write([]byte{0x00}) // zero security types offered
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeVNC(ctx, "127.0.0.1", port, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("probeVNC against a server offering zero security types: want an error, got nil")
	}
}

func TestProbeVNC_InvalidHexMarkerIsAnError(t *testing.T) {
	port := vncFakeServer(t, func(c net.Conn) {
		if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
			return
		}
		clientVersion := make([]byte, 12)
		if _, err := io.ReadFull(c, clientVersion); err != nil {
			return
		}
		if _, err := c.Write([]byte{0x01, 0x02}); err != nil {
			return
		}
		var selected [1]byte
		if _, err := io.ReadFull(c, selected[:]); err != nil {
			return
		}
		challenge := make([]byte, vncChallengeLen) // content is irrelevant: probeVNC fails before using it
		_, _ = c.Write(challenge)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeVNC(ctx, "127.0.0.1", port, "not-valid-hex!!"); err == nil {
		t.Fatal("probeVNC with a marker that is not valid hex: want an error, got nil")
	}
}
