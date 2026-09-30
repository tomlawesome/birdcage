package main

import (
	"net"
	"strings"
	"testing"
)

// TestSafeErrRedactsNetworkAddress proves safeErr's second redaction
// branch: a *net.OpError's own Addr, which the standard library embeds
// verbatim in Error() text the same way *fs.PathError embeds a
// filesystem path -- a dial or listen failure against the birdcage
// origin must not leak that address into a log line either.
func TestSafeErrRedactsNetworkAddress(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("10.20.30.40"), Port: 8443}
	err := &net.OpError{Op: "dial", Net: "tcp", Addr: addr, Err: errNoSuchHost}

	got := safeErr(err)
	if strings.Contains(got, addr.String()) {
		t.Fatalf("safeErr(%v) = %q, still contains the address %q", err, got, addr.String())
	}
	if !strings.Contains(got, "<address redacted>") {
		t.Errorf("safeErr(%v) = %q, want it to say <address redacted>", err, got)
	}
}

// TestSafeErrNilIsEmpty proves the nil-error short circuit.
func TestSafeErrNilIsEmpty(t *testing.T) {
	if got := safeErr(nil); got != "" {
		t.Errorf("safeErr(nil) = %q, want empty", got)
	}
}

// errNoSuchHost is a stand-in wrapped error, just needing a stable
// Error() string -- safeErr never inspects it beyond formatting the
// outer *net.OpError.
type errNoSuchHostType struct{}

func (errNoSuchHostType) Error() string { return "no such host" }

var errNoSuchHost = errNoSuchHostType{}
