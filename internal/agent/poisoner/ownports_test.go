package poisoner

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// recordedPort is one Add call the fake recorder saw.
type recordedPort struct {
	port uint16
	at   time.Time
}

// fakeOwnPorts stands in for portscan.OwnPorts (issue #240): Config.OwnPorts
// is any value with Add(port uint16, at time.Time), so this package never
// imports the detector's.
type fakeOwnPorts struct {
	mu   sync.Mutex
	adds []recordedPort
}

func (f *fakeOwnPorts) Add(port uint16, at time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds = append(f.adds, recordedPort{port, at})
}

// TestSendingAQueryRecordsItsLocalPort: the port-scan detector can only
// skip late answers to the canary's own queries if told which ephemeral
// port each one left from, at the time it was sent.
func TestSendingAQueryRecordsItsLocalPort(t *testing.T) {
	submit, _, _ := collect()
	rec := &fakeOwnPorts{}
	sent := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	d, _ := New(Config{
		Profile:  ProfileLinux,
		ConfPath: writeConf(t, "canary"),
		Hostname: "fs-lon-05",
		OwnPorts: rec,
		Now:      func() time.Time { return sent },
	}, submit, quietLogger())
	// Pretend Open succeeded, with the loopback as the segment, so the
	// query sockets open (the multicast send itself may fail; that must
	// not matter to the record).
	d.canSend = true
	d.segment = segment{Name: "lo", IP: net.IPv4(127, 0, 0, 1)}

	if _, err := d.LookupOnce(context.Background(), ProtocolLLMNR, "fs-lon-02"); err != nil {
		t.Fatalf("LookupOnce: %v", err)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.adds) == 0 {
		t.Fatal("a lookup recorded no local port")
	}
	for _, a := range rec.adds {
		if a.port == 0 {
			t.Error("recorded port 0, not the query socket's real ephemeral port")
		}
		if !a.at.Equal(sent) {
			t.Errorf("recorded at %v, want the detector's clock %v", a.at, sent)
		}
	}
}
