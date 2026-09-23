package probe

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProbeHTTP_PostsMarkerAsLoginUsername(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }() // test teardown; nothing left to act on a close error

	reqCh := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }() // test teardown; nothing left to act on a close error
		r := bufio.NewReader(c)
		var b strings.Builder
		for {
			line, err := r.ReadString('\n')
			b.WriteString(line)
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		// The body follows the blank line; read whatever arrives before
		// the carrier closes its side.
		rest, _ := io.ReadAll(r)
		b.Write(rest)
		reqCh <- b.String()
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeHTTP(ctx, "127.0.0.1", port, "marker-http"); err != nil {
		t.Fatalf("probeHTTP: %v", err)
	}

	select {
	case req := <-reqCh:
		if !strings.HasPrefix(req, "POST /index.html HTTP/1.1\r\n") {
			t.Errorf("request %q is not a login POST to /index.html, the one request OpenCanary's http module logs a username from", req)
		}
		if !strings.HasSuffix(req, "\r\n\r\nusername=marker-http&password="+selfTestPassword) {
			t.Errorf("request %q does not carry the marker as the login form's username", req)
		}
		if !strings.Contains(req, "X-Birdcage-Selftest: marker-http") {
			t.Errorf("request %q does not carry the marker header", req)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the request")
	}
}
