package ingest

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Server listens for OpenCanary UDP syslog datagrams and persists each
// one as an alert row.
type Server struct {
	addr string
	db   *sql.DB

	mu    sync.Mutex
	laddr net.Addr
}

// NewServer returns a Server that will listen on addr (a UDP address such
// as ":5514") and insert alerts into the alerts table of db.
func NewServer(addr string, db *sql.DB) *Server {
	return &Server{addr: addr, db: db}
}

// Addr reports the local address the server is bound to. It is nil until
// ListenAndServe has bound the socket, which makes it possible to test
// against an OS-assigned port (":0").
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.laddr
}

// ListenAndServe blocks reading UDP datagrams until ctx is canceled,
// parsing each one and inserting it into the alerts table. Any
// per-packet error (oversized, unparseable, failed insert) is logged and
// the loop continues: a single bad or malicious datagram must never stop
// the listener. Returns nil once ctx is canceled and the socket closed.
func (s *Server) ListenAndServe(ctx context.Context) error {
	conn, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", s.addr, err)
	}
	s.mu.Lock()
	s.laddr = conn.LocalAddr()
	s.mu.Unlock()
	// The goroutine is the single owner of the socket's close: the read
	// loop has no exit other than ctx cancellation, so closing here too
	// would double-close on the normal shutdown path.
	go func() {
		<-ctx.Done()
		if err := conn.Close(); err != nil {
			slog.Error("ingest: closing UDP socket failed", "err", err)
		}
	}()

	buf := make([]byte, MaxDatagramSize)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Error("ingest: read from UDP socket failed; continuing", "peer", peer, "err", err)
			continue
		}
		if n == 0 {
			continue
		}

		// Receipt time is birdcage's own, captured at the moment the
		// datagram arrives — never the sender's self-reported times.
		receivedAt := time.Now().UTC()

		alert, err := ParseOpenCanaryMessage(buf[:n])
		if err != nil {
			slog.Error("ingest: dropping unparseable datagram", "peer", peer, "bytes", n, "err", err)
			continue
		}
		alert.ReceivedAt = receivedAt

		if err := s.insert(ctx, alert); err != nil {
			slog.Error("ingest: dropping alert after insert failure", "peer", peer, "err", err)
			continue
		}
	}
}

const insertAlertQuery = `
INSERT INTO alerts (instance_id, source_ip, dest_port, service, raw, received_at)
VALUES (?, ?, ?, ?, ?, ?)`

func (s *Server) insert(ctx context.Context, a Alert) error {
	_, err := s.db.ExecContext(ctx, insertAlertQuery,
		a.InstanceID,
		a.SourceIP,
		a.DestPort,
		a.Service,
		a.Raw,
		a.ReceivedAt.Format(time.RFC3339Nano),
	)
	return err
}
