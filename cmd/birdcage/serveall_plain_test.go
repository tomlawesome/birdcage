package main

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/tlsconfig"
)

// Plain loopback mode is unchanged by the TLS-port redirect: it still serves
// ordinary HTTP, with no redirect.
func TestServeAllPlainLoopbackStillServesPlainHTTP(t *testing.T) {
	addr := freeLoopbackAddr(t)
	dashboard := &http.Server{Addr: addr, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "plain ok")
	})}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveAll(ctx, stop, dashboard, tlsconfig.ModePlainLoopbackTCP, "", nil, nil, discardLog(), discardLog(), discardLog(), discardLog())
	}()
	t.Cleanup(func() {
		stop()
		if err := <-done; err != nil {
			t.Logf("serveAll after stop: %v", err)
		}
	})

	client := &http.Client{
		Timeout:       2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var resp *http.Response
	var err error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if resp, err = client.Get("http://" + addr + "/"); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("plain GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "plain ok" {
		t.Errorf("got %d %q, want 200 \"plain ok\"", resp.StatusCode, body)
	}
}
