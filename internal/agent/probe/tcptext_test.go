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

// acceptOneAndRead starts a listener, sends greeting to the first
// connection it accepts (after a short delay, to exercise the
// carrier's drainBriefly rather than let it race an instant write),
// and returns a channel carrying whatever line the connection then
// writes.
func acceptOneAndRead(t *testing.T, greeting string) (port int, lineCh <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() }) // test teardown; nothing left to act on a close error

	ch := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }() // test teardown; nothing left to act on a close error
		if greeting != "" {
			time.Sleep(50 * time.Millisecond)
			_, _ = c.Write([]byte(greeting)) // fixture write; a failure surfaces as a timeout in the test below
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		ch <- line
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

func TestProbeFTP_SendsUSERWithMarker(t *testing.T) {
	port, lineCh := acceptOneAndRead(t, "220 welcome\r\n")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeFTP(ctx, "127.0.0.1", port, "marker-ftp"); err != nil {
		t.Fatalf("probeFTP: %v", err)
	}

	select {
	case line := <-lineCh:
		if strings.TrimSpace(line) != "USER marker-ftp" {
			t.Errorf("got line %q, want \"USER marker-ftp\"", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the USER line")
	}
}

func TestProbeTelnet_SendsMarkerAsUsernameLine(t *testing.T) {
	port, lineCh := acceptOneAndRead(t, "login: ")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeTelnet(ctx, "127.0.0.1", port, "marker-telnet"); err != nil {
		t.Fatalf("probeTelnet: %v", err)
	}

	select {
	case line := <-lineCh:
		if strings.TrimSpace(line) != "marker-telnet" {
			t.Errorf("got line %q, want \"marker-telnet\"", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the username line")
	}
}

func TestProbeFTP_DialFailureIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	_ = ln.Close() // nothing listens here now

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probeFTP(ctx, "127.0.0.1", port, "m"); err == nil {
		t.Fatal("probeFTP against a closed port: want an error, got nil")
	}
}
