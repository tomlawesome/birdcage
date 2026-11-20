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
