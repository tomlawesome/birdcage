package readiness

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result is one module's readiness outcome: whether a TCP dial to its
// configured port, on the canary's own address, succeeded.
type Result struct {
	Module string
	Port   int
	Up     bool
	Err    error
}

// DialFunc opens a connection to address (host:port form). Production
// passes Dial; a test substitutes a fake to control what "up" and "down"
// look like without needing a real socket for every case.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Dial is the production DialFunc: a plain TCP dial with no special
// handling, matching how any real client -- or an attacker -- would find
// out whether a port is answering.
func Dial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Check dials host:port for every module in ports and reports whether
// each one accepted a connection within timeout. Modules are dialed
// concurrently: a boot with a dozen enabled modules must not take a dozen
// timeouts in sequence just to report one that never started, and the
// common case -- everything up -- returns as soon as the slowest module
// answers rather than the sum of them.
//
// Results are returned in a stable, module-name-sorted order so a caller
// logging them produces the same order run to run, which matters for a
// human reading container logs more than it does for anything that parses
// them.
func Check(ctx context.Context, dial DialFunc, host string, ports map[string]int, timeout time.Duration) []Result {
	return CheckWith(ctx, dial, nil, host, ports, timeout)
}

// ListeningFunc returns the set of local TCP ports in LISTEN state.
type ListeningFunc func() (map[int]bool, error)

// ConnectLoggingModules are the OpenCanary modules that log an event on a
// bare TCP connect (ssh logs logtype 4000 "connection made"). A readiness
// check that dialled them would show up as a visitor on every pass (#238),
// so CheckWith confirms them from the socket table instead and never
// connects. Other modules log only on a login attempt.
var ConnectLoggingModules = map[string]bool{"ssh": true}

// ListeningPorts returns the local ports in LISTEN state (st 0A) from
// /proc/net/tcp and /proc/net/tcp6, read through readFile. A missing tcp6
// file (IPv6 disabled) is tolerated; a missing or unparsable tcp is not.
func ListeningPorts(readFile func(name string) ([]byte, error)) (map[int]bool, error) {
	out := map[int]bool{}
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := readFile(name)
		if err != nil {
			if name == "/proc/net/tcp6" && errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		lines := strings.Split(string(b), "\n")
		for _, line := range lines[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "0A" {
				continue
			}
			i := strings.LastIndexByte(f[1], ':')
			if i < 0 {
				continue
			}
			port, err := strconv.ParseUint(f[1][i+1:], 16, 16)
			if err != nil {
				continue
			}
			out[int(port)] = true
		}
	}
	return out, nil
}

// CheckWith is Check, except that modules in ConnectLoggingModules are
// judged by the listening set rather than a dial. If listening is nil or
// fails, those modules are reported down (with the error) and still not
// dialled.
func CheckWith(ctx context.Context, dial DialFunc, listening ListeningFunc, host string, ports map[string]int, timeout time.Duration) []Result {
	var listenSet map[int]bool
	var listenErr error
	for m := range ports {
		if ConnectLoggingModules[m] {
			if listening == nil {
				listenErr = errors.New("no socket table reader")
			} else {
				listenSet, listenErr = listening()
			}
			break
		}
	}
	modules := make([]string, 0, len(ports))
	for m := range ports {
		modules = append(modules, m)
	}
	sort.Strings(modules)

	out := make([]Result, len(modules))
	var wg sync.WaitGroup
	for i, module := range modules {
		wg.Add(1)
		go func(i int, module string, port int) {
			defer wg.Done()
			if ConnectLoggingModules[module] {
				switch {
				case listenErr != nil:
					out[i] = Result{Module: module, Port: port, Err: listenErr}
				case listenSet[port]:
					out[i] = Result{Module: module, Port: port, Up: true}
				default:
					out[i] = Result{Module: module, Port: port, Err: errors.New("not in LISTEN state")}
				}
				return
			}
			dialCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			conn, err := dial(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				out[i] = Result{Module: module, Port: port, Err: err}
				return
			}
			_ = conn.Close()
			out[i] = Result{Module: module, Port: port, Up: true}
		}(i, module, ports[module])
	}
	wg.Wait()
	return out
}
