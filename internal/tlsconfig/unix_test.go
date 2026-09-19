package tlsconfig

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestUnixListenerServesAndCleansUp proves the mechanism
// ModePlainUnixSocket relies on: a plain http.Server can be served over
// a unix socket UnixListener creates, a client dials and gets a real
// response over it, and the socket file is gone once the server has
// been shut down and the caller removes it (main.go's job once
// UnixListener returns -- see UnixListener's doc comment).
func TestUnixListenerServesAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "http.sock")

	ln, err := UnixListener(sockPath)
	if err != nil {
		t.Fatalf("UnixListener: %v", err)
	}

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := info.Mode().Perm(); perm != unixSocketPerm {
		t.Errorf("socket mode = %04o, want %04o", perm, unixSocketPerm)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"alerts":0}`))
	})
	server := &http.Server{Handler: mux}

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ln) }()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}

	resp, err := client.Get("http://unix/api/stats")
	if err != nil {
		t.Fatalf("GET /api/stats over unix socket: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", resp.StatusCode, body)
	}
	if string(body) != `{"alerts":0}` {
		t.Fatalf("body = %q, want %q", body, `{"alerts":0}`)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve: %v", err)
	}

	// net.UnixListener.Close (called by Shutdown above) already unlinks
	// the socket file it created; main.go's own os.Remove after
	// Shutdown (belt and braces, for a listener that for some reason
	// didn't) tolerates the file already being gone the same way this
	// assertion does.
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket file still present after shutdown: err=%v", err)
	}
}

// TestUnixListenerRemovesStaleSocket proves UnixListener recovers from
// a leftover socket file (as an unclean shutdown would leave), rather
// than failing "address already in use" against a file nothing is
// listening on.
func TestUnixListenerRemovesStaleSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "http.sock")

	ln1, err := UnixListener(sockPath)
	if err != nil {
		t.Fatalf("first UnixListener: %v", err)
	}
	// Simulate an unclean shutdown: the listener is dropped without
	// closing, and the socket file is left behind.
	ln1.Close()

	ln2, err := UnixListener(sockPath)
	if err != nil {
		t.Fatalf("second UnixListener (stale socket): %v", err)
	}
	defer ln2.Close()
}
