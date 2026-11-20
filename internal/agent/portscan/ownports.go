package portscan

import (
	"sync"
	"time"
)

// ownPortWindow is how long after a query a datagram to its source port
// is still taken for the answer to it (issue #240). It is the scan window:
// an answer older than that could not have been part of a sweep the
// tracker would still be counting anyway.
const ownPortWindow = DefaultWindow

// OwnPorts remembers the ephemeral UDP ports the canary's own poisoner
// sent its LLMNR and mDNS questions from. The poisoner closes each socket
// when its lookup ends, so a late answer is a datagram to a closed port
// and would otherwise count towards a scan. Safe for concurrent use; a nil
// *OwnPorts records nothing and knows nothing.
type OwnPorts struct {
	mu    sync.Mutex
	ports map[uint16]time.Time
}

// NewOwnPorts returns an empty record.
func NewOwnPorts() *OwnPorts {
	return &OwnPorts{ports: make(map[uint16]time.Time)}
}

// Add records that a query left from port at the given time. Entries
// older than the window are dropped on the way, so the map is bounded by
// the number of queries in one window.
func (o *OwnPorts) Add(port uint16, at time.Time) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for p, t := range o.ports {
		if at.Sub(t) > ownPortWindow {
			delete(o.ports, p)
		}
	}
	if prev, ok := o.ports[port]; !ok || at.After(prev) {
		o.ports[port] = at
	}
}

// Recent reports whether port was added no more than the window before now.
func (o *OwnPorts) Recent(port uint16, now time.Time) bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	t, ok := o.ports[port]
	return ok && now.Sub(t) <= ownPortWindow
}
