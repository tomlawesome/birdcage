package readiness

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// Seam the fix must expose (issue #238):
//
//	type ListeningFunc func() (map[int]bool, error)
//	func ListeningPorts(readFile func(name string) ([]byte, error)) (map[int]bool, error)
//	func CheckWith(ctx, dial DialFunc, listening ListeningFunc, host string,
//	    ports map[string]int, timeout time.Duration) []Result
//	var ConnectLoggingModules = map[string]bool{"ssh": true}
//
// ListeningPorts reads /proc/net/tcp and /proc/net/tcp6 through readFile and
// returns the local ports in LISTEN state (st == 0A). CheckWith dials every
// module except those in ConnectLoggingModules, which are confirmed from the
// listening set instead and never dialled.

const procHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

const tcpTable = procHeader +
	"   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0\n" +
	"   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0\n" +
	"   2: 0100007F:1F90 0100007F:0016 01 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000 100 0 0 10 0\n"

const tcp6TableSSH = procHeader +
	"   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 0000000000000000 100 0 0 10 0\n"

func fakeReadFile(files map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		s, ok := files[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(s), nil
	}
}

func TestListeningPortsParsesLoopbackAndWildcardListeners(t *testing.T) {
	t.Parallel()
	got, err := ListeningPorts(fakeReadFile(map[string]string{
		"/proc/net/tcp":  tcpTable,
		"/proc/net/tcp6": procHeader,
	}))
	if err != nil {
		t.Fatalf("ListeningPorts: %v", err)
	}
	if !got[22] || !got[80] {
		t.Errorf("want 22 and 80 listening, got %v", got)
	}
	if got[0x1F90] {
		t.Errorf("port 8080 is ESTABLISHED, not LISTEN, got %v", got)
	}
}

func TestListeningPortsIgnoresNonListenStateAndRemotePort(t *testing.T) {
	t.Parallel()
	// Only a connection in state 01 whose *remote* port is 22: ssh is not listening.
	table := procHeader +
		"   0: 0100007F:1F90 0100007F:0016 01 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:0016 0100007F:9999 06 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0\n"
	got, err := ListeningPorts(fakeReadFile(map[string]string{
		"/proc/net/tcp":  table,
		"/proc/net/tcp6": procHeader,
	}))
	if err != nil {
		t.Fatalf("ListeningPorts: %v", err)
	}
	if got[22] {
		t.Errorf("port 22 must not count (remote port / TIME_WAIT only), got %v", got)
	}
}

func TestListeningPortsIncludesTCP6Listeners(t *testing.T) {
	t.Parallel()
	got, err := ListeningPorts(fakeReadFile(map[string]string{
		"/proc/net/tcp":  procHeader,
		"/proc/net/tcp6": tcp6TableSSH,
	}))
	if err != nil {
		t.Fatalf("ListeningPorts: %v", err)
	}
	if !got[22] {
		t.Errorf("tcp6 LISTEN on 22 must count, got %v", got)
	}
}

// recordingDial fails the test if the ssh port (22) is ever dialled.
type recordingDial struct {
	mu     sync.Mutex
	dialed []string
}

func (r *recordingDial) dial(_ context.Context, _, address string) (net.Conn, error) {
	r.mu.Lock()
	r.dialed = append(r.dialed, address)
	r.mu.Unlock()
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func (r *recordingDial) saw(address string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.dialed {
		if a == address {
			return true
		}
	}
	return false
}

func listeningOf(ports ...int) ListeningFunc {
	return func() (map[int]bool, error) {
		m := map[int]bool{}
		for _, p := range ports {
			m[p] = true
		}
		return m, nil
	}
}

func byModule(rs []Result) map[string]Result {
	m := map[string]Result{}
	for _, r := range rs {
		m[r.Module] = r
	}
	return m
}

func TestCheckWithSSHListeningIsUpAndNeverDialled(t *testing.T) {
	t.Parallel()
	rd := &recordingDial{}
	res := byModule(CheckWith(context.Background(), rd.dial, listeningOf(22), "127.0.0.1",
		map[string]int{"ssh": 22}, time.Second))
	if !res["ssh"].Up {
		t.Errorf("ssh listening must be Up, got %+v", res["ssh"])
	}
	if rd.saw("127.0.0.1:22") {
		t.Fatal("ssh port was dialled; a connect makes OpenCanary log a visitor (#238)")
	}
}

func TestCheckWithSSHAbsentIsDownAndNeverDialled(t *testing.T) {
	t.Parallel()
	rd := &recordingDial{}
	res := byModule(CheckWith(context.Background(), rd.dial, listeningOf(80), "127.0.0.1",
		map[string]int{"ssh": 22}, time.Second))
	if res["ssh"].Up {
		t.Errorf("ssh absent from the socket table must be down, got %+v", res["ssh"])
	}
	if rd.saw("127.0.0.1:22") {
		t.Fatal("ssh port was dialled")
	}
}

func TestCheckWithSocketTableErrorIsDownForSSH(t *testing.T) {
	t.Parallel()
	rd := &recordingDial{}
	failing := func() (map[int]bool, error) { return nil, errors.New("boom") }
	res := byModule(CheckWith(context.Background(), rd.dial, failing, "127.0.0.1",
		map[string]int{"ssh": 22}, time.Second))
	if res["ssh"].Up {
		t.Errorf("unreadable socket table must not report ssh up, got %+v", res["ssh"])
	}
	if rd.saw("127.0.0.1:22") {
		t.Fatal("ssh port was dialled")
	}
}

func TestCheckWithStillDialsOtherModules(t *testing.T) {
	t.Parallel()
	rd := &recordingDial{}
	// ftp is not in the listening set on purpose: it must be judged by the dial.
	res := byModule(CheckWith(context.Background(), rd.dial, listeningOf(22), "127.0.0.1",
		map[string]int{"ssh": 22, "ftp": 21, "http": 80}, time.Second))
	if !rd.saw("127.0.0.1:21") || !rd.saw("127.0.0.1:80") {
		t.Errorf("ftp and http must be dialled, dialled %v", rd.dialed)
	}
	if rd.saw("127.0.0.1:22") {
		t.Fatal("ssh port was dialled")
	}
	if !res["ftp"].Up || !res["http"].Up || !res["ssh"].Up {
		t.Errorf("all three should be up, got %+v", res)
	}
}

func TestConnectLoggingModulesNamesSSH(t *testing.T) {
	t.Parallel()
	if !ConnectLoggingModules["ssh"] {
		t.Error("ConnectLoggingModules must contain ssh")
	}
	if ConnectLoggingModules["ftp"] {
		t.Error("ftp logs only on login attempts and must still be dialled")
	}
}

func TestListeningPortsToleratesMissingTCP6(t *testing.T) {
	t.Parallel()
	got, err := ListeningPorts(fakeReadFile(map[string]string{"/proc/net/tcp": tcpTable}))
	if err != nil {
		t.Fatalf("a host with IPv6 disabled must still read: %v", err)
	}
	if !got[22] || !got[80] || len(got) != 2 {
		t.Errorf("want exactly 22 and 80 from tcp, got %v", got)
	}
}

func TestListeningPortsFailsOnUnreadableTable(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failed")
	// A missing tcp is an error, not "nothing listening".
	if got, err := ListeningPorts(fakeReadFile(map[string]string{"/proc/net/tcp6": procHeader})); !errors.Is(err, os.ErrNotExist) || got != nil {
		t.Errorf("missing tcp: got %v, %v, want nil and ErrNotExist", got, err)
	}
	// tcp6 failing for any reason other than not-existing is an error too.
	rf := func(name string) ([]byte, error) {
		if name == "/proc/net/tcp6" {
			return nil, boom
		}
		return []byte(tcpTable), nil
	}
	if got, err := ListeningPorts(rf); !errors.Is(err, boom) || got != nil {
		t.Errorf("unreadable tcp6: got %v, %v, want nil and the read error", got, err)
	}
}

func TestListeningPortsSkipsMalformedRows(t *testing.T) {
	t.Parallel()
	const listen = " 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1 0 100 0 0 10 0\n"
	table := procHeader +
		"   0: NOCOLON" + listen + // local address without a port separator
		"   1: 00000000:ZZZZ" + listen + // port is not hex
		"   2: 00000000:10000" + listen + // port overflows 16 bits
		"   3: 00000000:0050" + listen // the only good row
	got, err := ListeningPorts(fakeReadFile(map[string]string{"/proc/net/tcp": table, "/proc/net/tcp6": procHeader}))
	if err != nil {
		t.Fatalf("ListeningPorts: %v", err)
	}
	if len(got) != 1 || !got[80] {
		t.Errorf("want only port 80, got %v", got)
	}
}

// With no socket-table reader, a connect-logging module is reported down
// with an error and still never dialled; other modules are dialled as usual.
func TestCheckWithNilListeningReportsSSHDownWithoutDialling(t *testing.T) {
	t.Parallel()
	rd := &recordingDial{}
	res := byModule(CheckWith(context.Background(), rd.dial, nil, "192.0.2.1",
		map[string]int{"ssh": 22, "http": 80}, time.Second))
	if res["ssh"].Up || res["ssh"].Err == nil {
		t.Errorf("ssh without a reader must be down with an error, got %+v", res["ssh"])
	}
	if rd.saw("192.0.2.1:22") {
		t.Error("ssh port was dialled (#238)")
	}
	if !res["http"].Up || !rd.saw("192.0.2.1:80") {
		t.Errorf("http must still be dialled and up, got %+v", res["http"])
	}
}
