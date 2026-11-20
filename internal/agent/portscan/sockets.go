package portscan

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// socketRefreshInterval is how long a read of the socket tables is reused
// before the next packet triggers a new one. A service started on the
// canary becomes invisible to the detector for at most this long.
const socketRefreshInterval = 5 * time.Second

// procNetTables are the kernel's per-namespace socket tables.
var procNetTables = []struct {
	path  string
	proto string
	// listenOnly keeps only st 0A (LISTEN); UDP has no such state, so any
	// bound socket counts.
	listenOnly bool
}{
	{"/proc/net/tcp", ProtoTCP, true},
	{"/proc/net/tcp6", ProtoTCP, true},
	{"/proc/net/udp", ProtoUDP, false},
	{"/proc/net/udp6", ProtoUDP, false},
}

type socketKey struct {
	proto string
	port  uint16
}

type socketSet map[socketKey]struct{}

// socketTable caches the set of ports something in this network
// namespace is listening on. get is safe for concurrent use; the hot path
// is one atomic load and a clock comparison.
type socketTable struct {
	read func(string) ([]byte, error)
	now  func() time.Time
	warn func(string)

	next   atomic.Int64 // unix nanos before which the cached set is reused
	set    atomic.Pointer[socketSet]
	mu     sync.Mutex
	warned bool
}

func newSocketTable(read func(string) ([]byte, error), now func() time.Time, warn func(string)) *socketTable {
	if read == nil {
		read = os.ReadFile
	}
	return &socketTable{read: read, now: now, warn: warn}
}

// has reports whether something listens on port for proto. When the
// tables are unreadable it reports false, leaving the config ignore list
// as the only exemption.
func (t *socketTable) has(proto string, port uint16) bool {
	now := t.now()
	if now.UnixNano() >= t.next.Load() {
		t.refresh(now)
	}
	s := t.set.Load()
	if s == nil {
		return false
	}
	_, ok := (*s)[socketKey{proto, port}]
	return ok
}

func (t *socketTable) refresh(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.UnixNano() < t.next.Load() {
		return // another goroutine just refreshed
	}
	t.next.Store(now.Add(socketRefreshInterval).UnixNano())

	set, err := t.load()
	if err != nil {
		if !t.warned {
			t.warned = true
			t.warn(fmt.Sprintf("socket table unreadable, ports are ignored only if configured: %v", err))
		}
		t.set.Store(nil)
		return
	}
	t.set.Store(&set)
}

func (t *socketTable) load() (socketSet, error) {
	set := socketSet{}
	for _, tb := range procNetTables {
		data, err := t.read(tb.path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && tb.path[len(tb.path)-1] == '6' {
				continue // IPv6 absent from this namespace
			}
			return nil, err
		}
		parseSocketTable(data, tb.proto, tb.listenOnly, set)
	}
	return set, nil
}

// parseSocketTable adds the local ports of one /proc/net table to set.
// Lines that do not parse are skipped, header included.
func parseSocketTable(data []byte, proto string, listenOnly bool, set socketSet) {
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		f := bytes.Fields(line)
		if len(f) < 4 {
			continue
		}
		if listenOnly && string(f[3]) != "0A" {
			continue
		}
		local := f[1]
		i := bytes.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		port, err := strconv.ParseUint(string(local[i+1:]), 16, 16)
		if err != nil {
			continue
		}
		set[socketKey{proto, uint16(port)}] = struct{}{}
	}
}
