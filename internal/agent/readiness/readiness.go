package readiness

import (
	"context"
	"net"
	"sort"
	"strconv"
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
