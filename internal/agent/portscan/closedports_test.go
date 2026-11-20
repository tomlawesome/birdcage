package portscan

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Fake /proc/net tables. Only the columns the detector needs are
// realistic: local address, st. Port 445 (0x01BD) is LISTEN, 9000
// (0x2328) is ESTABLISHED and so is not a socket anyone can connect to
// afresh; UDP 161 (0x00A1) is bound.
const fakeTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:2328 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0
`

const fakeUDP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 00000000:00A1 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 33333 2 0000000000000000 0
`

// fakeProc serves the fake tables, tolerates absent v6 files and counts
// how often the detector goes back to read them.
type fakeProc struct {
	files map[string]string
	err   error
	calls int
}

func (f *fakeProc) read(name string) ([]byte, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	s, ok := f.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(s), nil
}

func newFakeProc() *fakeProc {
	return &fakeProc{files: map[string]string{
		"/proc/net/tcp": fakeTCP,
		"/proc/net/udp": fakeUDP,
		// tcp6 and udp6 deliberately absent.
	}}
}

func newSocketDetector(t *testing.T, clock *fakeClock, proc *fakeProc, ignore []uint16) (*Detector, *[][]byte, *bytes.Buffer) {
	t.Helper()
	var got [][]byte
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	d, _ := New(Config{
		ConfPath:         t.TempDir() + "/absent.conf",
		ExtraIgnorePorts: ignore,
		Now:              clock.Now,
		// ReadFile is the socket-table reader: the detector must call it
		// with the /proc/net/{tcp,tcp6,udp,udp6} paths instead of os.ReadFile.
		ReadFile: proc.read,
	}, func(message []byte) error {
		got = append(got, append([]byte(nil), message...))
		return nil
	}, log)
	return d, &got, &logs
}

func udpPacket(dstPort uint16) []byte {
	return ipv4Packet(ipv4Header{protocol: protoUDP}, udpDatagram(44123, dstPort))
}

func TestOneVisitToASocketPortDoesNotCountTowardsAScan(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	d, got, _ := newSocketDetector(t, clock, newFakeProc(), nil)

	for _, port := range []uint16{445, 25, 110, 143, 5900} {
		d.handle(scanPacket(port))
		clock.Advance(200 * time.Millisecond)
	}
	if len(*got) != 0 {
		t.Fatalf("one SMB visit plus four closed ports alerted: %s", (*got)[0])
	}
	// The fifth closed port is the real threshold.
	d.handle(scanPacket(8080))
	if len(*got) != 1 {
		t.Fatalf("five closed ports gave %d events, want 1", len(*got))
	}
}

func TestFiveClosedPortsStillAlert(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	d, got, _ := newSocketDetector(t, clock, newFakeProc(), nil)

	// 9000 is only ESTABLISHED in the fake table, so it is closed.
	for _, port := range []uint16{25, 110, 143, 5900, 9000} {
		d.handle(scanPacket(port))
		clock.Advance(200 * time.Millisecond)
	}
	if len(*got) != 1 {
		t.Fatalf("five closed ports gave %d events, want 1", len(*got))
	}
}

func TestBoundUDPPortIsSkipped(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	d, got, _ := newSocketDetector(t, clock, newFakeProc(), nil)

	// 161/udp is bound, so four other UDP ports plus 161 is only four.
	for _, port := range []uint16{161, 5000, 5001, 5002, 5003} {
		d.handle(udpPacket(port))
		clock.Advance(200 * time.Millisecond)
	}
	if len(*got) != 0 {
		t.Fatalf("a datagram to a bound UDP port counted: %s", (*got)[0])
	}
}

func TestUnreadableSocketTableFallsBackAndWarnsOnce(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	proc := newFakeProc()
	proc.err = errors.New("permission denied")
	d, got, logs := newSocketDetector(t, clock, proc, []uint16{22})

	// Many packets to a config port from many sources, spread over time
	// well beyond any refresh interval, so a per-refresh warning would
	// also show up as more than one.
	for i := 0; i < 50; i++ {
		p := scanPacket(22)
		copy(p[12:16], []byte{198, 51, 100, byte(i + 1)}) // vary the source
		d.handle(p)
		clock.Advance(time.Second)
	}
	if len(*got) != 0 {
		t.Fatalf("config port was not skipped: %s", (*got)[0])
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Fatalf("logged %d warnings, want exactly 1:\n%s", n, logs.String())
	}
}

func TestSocketTableReadIsRateLimited(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	proc := newFakeProc()
	d, _, _ := newSocketDetector(t, clock, proc, nil)

	for i := 0; i < 100; i++ {
		d.handle(scanPacket(uint16(2000 + i%3)))
		clock.Advance(10 * time.Millisecond)
	}
	first := proc.calls
	if first == 0 {
		t.Fatal("socket table was never read")
	}
	if first > 4 {
		t.Fatalf("one refresh read %d files, want at most the four /proc/net tables", first)
	}

	for i := 0; i < 100; i++ {
		d.handle(scanPacket(uint16(2000 + i%3)))
		clock.Advance(10 * time.Millisecond)
	}
	if proc.calls != first {
		t.Fatalf("re-read within the interval: %d calls, want %d", proc.calls, first)
	}

	clock.Advance(time.Minute)
	d.handle(scanPacket(2000))
	if proc.calls <= first {
		t.Fatalf("no re-read after the interval: %d calls, still %d", proc.calls, first)
	}
}
