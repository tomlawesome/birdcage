package ingest

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

type storedAlert struct {
	InstanceID string
	SourceIP   string
	DestPort   int
	Service    string
	Raw        string
	ReceivedAt string
}

func TestServerEndToEnd(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "birdcage-test.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}

	server := NewServer("127.0.0.1:0", database)
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ListenAndServe(ctx) }()

	waitUntil := time.Now().Add(5 * time.Second)
	for server.Addr() == nil && time.Now().Before(waitUntil) {
		time.Sleep(10 * time.Millisecond)
	}
	addr := server.Addr()
	if addr == nil {
		select {
		case err := <-serveErr:
			t.Fatalf("server did not start listening within 5s; ListenAndServe returned: %v", err)
		default:
			t.Fatal("server did not start listening within 5s")
		}
	}

	client, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close client: %v", err)
		}
	})

	send := func(b []byte) {
		t.Helper()
		if _, err := client.Write(b); err != nil {
			t.Fatalf("send datagram: %v", err)
		}
	}

	sshDatagram := []byte("<14>opencanaryd[1:2]: node-1 WARNING {\"dst_host\": \"\", \"dst_port\": 22, \"logdata\": {\"attempted_username\": \"root\"}, \"logtype\": 4002, \"node_id\": \"node-1\", \"src_host\": \"203.0.113.9\", \"src_port\": 51000, \"utc_time\": \"2020-01-01 00:00:00.000000\"}\x00")
	httpDatagram := []byte("<30>opencanaryd[1:2]: node-2 WARNING {\"dst_port\": 80, \"logdata\": {\"url_path\": \"/admin\"}, \"logtype\": 3000, \"node_id\": \"node-2\", \"src_host\": \"198.51.100.8\"}\x00")
	unknownDatagram := []byte("<14>opencanaryd[1:2]: node-1 WARNING {\"dst_port\": 1234, \"logtype\": 424242, \"node_id\": \"node-1\", \"src_host\": \"203.0.113.10\"}\x00")

	send(sshDatagram)
	send(httpDatagram)
	// Malformed packets: must be dropped without stopping the listener.
	send([]byte("no json object in here at all"))
	send([]byte("<14>truncated {\"node_id\": \"node-1\", \"logtype\": 400"))
	// A large (but legal) datagram of pure noise: still must be dropped
	// cleanly, with no row and no crash.
	send(make([]byte, 65500))
	send(unknownDatagram)

	rows, err := waitForAlerts(ctx, database, 3, 10*time.Second)
	if err != nil {
		t.Fatalf("waiting for 3 alerts: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}

	expected := []storedAlert{
		{InstanceID: "node-1", SourceIP: "203.0.113.9", DestPort: 22, Service: "ssh", Raw: string(sshDatagram)},
		{InstanceID: "node-2", SourceIP: "198.51.100.8", DestPort: 80, Service: "http", Raw: string(httpDatagram)},
		{InstanceID: "node-1", SourceIP: "203.0.113.10", DestPort: 1234, Service: "unknown", Raw: string(unknownDatagram)},
	}
	now := time.Now().UTC()
	for i, want := range expected {
		got := rows[i]
		if got.InstanceID != want.InstanceID || got.SourceIP != want.SourceIP ||
			got.DestPort != want.DestPort || got.Service != want.Service || got.Raw != want.Raw {
			t.Errorf("row %d = %+v, want %+v", i, got, want)
		}
		received, err := time.Parse(time.RFC3339Nano, got.ReceivedAt)
		if err != nil {
			t.Errorf("row %d: received_at %q is not RFC3339: %v", i, got.ReceivedAt, err)
			continue
		}
		if received.Location() != time.UTC {
			t.Errorf("row %d: received_at %q is not in UTC", i, got.ReceivedAt)
		}
		// The payload's own utc_time is a 2020 value; received_at must be
		// the server's receipt time, i.e. now-ish, not 2020.
		if received.After(now.Add(time.Minute)) || received.Before(now.Add(-time.Minute)) {
			t.Errorf("row %d: received_at %v is not close to the test's current time %v", i, received, now)
		}
	}

	// The listener must still be serving after the malformed packets:
	// one more valid datagram must land as a fourth row.
	followup := []byte("<14>opencanaryd[1:2]: node-3 WARNING {\"dst_port\": 53, \"logtype\": 10000, \"node_id\": \"node-3\", \"src_host\": \"192.0.2.77\"}\x00")
	send(followup)
	rows, err = waitForAlerts(ctx, database, 4, 10*time.Second)
	if err != nil {
		t.Fatalf("waiting for 4th alert after malformed packets: %v", err)
	}
	if rows[3].InstanceID != "node-3" || rows[3].Service != "unknown" || rows[3].Raw != string(followup) {
		t.Errorf("row 3 = %+v, want the follow-up alert persisted verbatim", rows[3])
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Errorf("ListenAndServe returned %v after ctx cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not return within 5s of ctx cancel")
	}
}

func waitForAlerts(ctx context.Context, database *sql.DB, n int, timeout time.Duration) ([]storedAlert, error) {
	query := `SELECT instance_id, source_ip, dest_port, service, raw, received_at
		FROM alerts ORDER BY id`
	deadline := time.Now().Add(timeout)
	for {
		rows, err := database.QueryContext(ctx, query)
		if err != nil {
			return nil, err
		}
		var alerts []storedAlert
		for rows.Next() {
			var a storedAlert
			if err := rows.Scan(&a.InstanceID, &a.SourceIP, &a.DestPort, &a.Service, &a.Raw, &a.ReceivedAt); err != nil {
				return nil, errors.Join(err, rows.Close())
			}
			alerts = append(alerts, a)
		}
		scanErr := rows.Err()
		closeErr := rows.Close()
		if scanErr != nil {
			return nil, scanErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(alerts) >= n {
			return alerts, nil
		}
		if time.Now().After(deadline) {
			return alerts, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
