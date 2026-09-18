package probe

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestProbeHTTP_PlantsMarkerInPathAndHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	reqCh := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		var b strings.Builder
		for {
			line, err := r.ReadString('\n')
			b.WriteString(line)
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
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
		if !strings.Contains(req, "GET /marker-http ") {
			t.Errorf("request %q does not carry the marker in its path", req)
		}
		if !strings.Contains(req, "X-Birdcage-Selftest: marker-http") {
			t.Errorf("request %q does not carry the marker header", req)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the request")
	}
}
