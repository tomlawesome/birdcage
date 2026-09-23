package poisoner

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The addresses and MACs in this fixture are documentation-range and
// locally-administered values, not anything from a real network.
const arpFixture = `IP address       HW type     Flags       HW address            Mask     Device
10.0.0.66        0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
10.0.0.70        0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.71        0x1         0x2         AA:BB:CC:00:11:22     *        eth0
10.0.0.72        0x1         0x2         not-a-mac             *        eth0
10.0.0.73        0x1         0x2         aa:bb:cc:dd:ee         *       eth0
`

// writeARP puts the fixture in a temp file and returns its path.
func writeARP(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "arp")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write the fixture: %v", err)
	}
	return path
}

// TestLookupMAC is issue #86 decision 34's MAC: read passively from the
// kernel's own neighbour table, with no probe and no privilege.
func TestLookupMAC(t *testing.T) {
	path := writeARP(t, arpFixture)

	tests := []struct {
		name string
		ip   string
		want string
	}{
		{name: "the answering host", ip: "10.0.0.66", want: "aa:bb:cc:dd:ee:ff"},
		// Lower-cased, so an alert's MAC is comparable whatever case the
		// kernel wrote.
		{name: "upper case in the table", ip: "10.0.0.71", want: "aa:bb:cc:00:11:22"},
		// An incomplete entry: the neighbour has been asked and has not
		// answered. Reporting all-zeroes as the attacker's MAC would be
		// worse than reporting none.
		{name: "an incomplete entry", ip: "10.0.0.70", want: ""},
		{name: "an unparseable MAC", ip: "10.0.0.72", want: ""},
		{name: "a truncated MAC", ip: "10.0.0.73", want: ""},
		{name: "a host with no entry", ip: "10.0.0.99", want: ""},
		// An IPv6 answer has no entry to find: Linux does not expose IPv6
		// neighbours here at all. The empty string is the ordinary answer,
		// not a failure.
		{name: "an IPv6 address", ip: "fe80::1", want: ""},
		{name: "not an address at all", ip: "eth0", want: ""},
		{name: "the header's own first column", ip: "IP", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lookupMAC(path, tc.ip); got != tc.want {
				t.Errorf("lookupMAC(%q) = %q, want %q", tc.ip, got, tc.want)
			}
		})
	}
}

// TestLookupMACOnAMissingFile proves an unreadable neighbour table costs the
// MAC and nothing else: the alert still goes out, naming the address, which
// is the part that matters.
func TestLookupMACOnAMissingFile(t *testing.T) {
	if got := lookupMAC(filepath.Join(t.TempDir(), "absent"), "10.0.0.66"); got != "" {
		t.Errorf("lookupMAC on a missing file = %q, want the empty string", got)
	}
	if got := lookupMAC(writeARP(t, "total nonsense\n"), "10.0.0.66"); got != "" {
		t.Errorf("lookupMAC on a garbled file = %q, want the empty string", got)
	}
}

// TestLookupMACMatchesAddressesNotText proves the match is on the parsed
// address rather than the text, so 10.0.0.6 never matches the 10.0.0.66 row.
func TestLookupMACMatchesAddressesNotText(t *testing.T) {
	path := writeARP(t, arpFixture)
	if got := lookupMAC(path, "10.0.0.6"); got != "" {
		t.Errorf("lookupMAC(\"10.0.0.6\") = %q: it matched a longer address as text", got)
	}
	// The same address written differently still matches, because ParseIP
	// is what does the comparing.
	if got := lookupMAC(path, "::ffff:10.0.0.66"); got == "" {
		t.Error("an IPv4-mapped form of the same address did not match")
	}
}

// TestDefaultARPPathIsTheKernelsOwn pins the path, since nothing configures
// it outside a test.
func TestDefaultARPPathIsTheKernelsOwn(t *testing.T) {
	if DefaultARPPath != "/proc/net/arp" {
		t.Errorf("DefaultARPPath = %q, want /proc/net/arp", DefaultARPPath)
	}
	// And the fixture's shape is the kernel's: if the real file ever has a
	// different column count this test catches it on any Linux host.
	if body, err := os.ReadFile(DefaultARPPath); err == nil && len(body) > 0 {
		if _, err := net.ParseMAC("aa:bb:cc:dd:ee:ff"); err != nil {
			t.Fatalf("net.ParseMAC cannot read the format this package expects: %v", err)
		}
	}
}

// TestLookupMACWithRetryFindsALateEntry covers the neighbour-table race
// described at macRetryDelay: the entry is written by a different kernel
// path from the one that delivered the reply, so a read in the same instant
// can miss it. The fixture is empty for the first look and populated for
// the second.
func TestLookupMACWithRetryFindsALateEntry(t *testing.T) {
	path := writeARP(t, "IP address       HW type     Flags       HW address            Mask     Device\n")

	// Populate it while the retry is sleeping.
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(macRetryDelay / 2)
		_ = os.WriteFile(path, []byte(arpFixture), 0o600)
	}()

	if got := lookupMACWithRetry(path, "10.0.0.66"); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("lookupMACWithRetry = %q, want the late entry", got)
	}
	<-done
}

// TestLookupMACWithRetryReturnsEmptyWhenThereIsNothing proves the retry
// does not turn "no entry" into a failure: an answer over IPv6, or from
// off-segment, legitimately has no MAC and the alert still goes out.
func TestLookupMACWithRetryReturnsEmptyWhenThereIsNothing(t *testing.T) {
	path := writeARP(t, arpFixture)
	if got := lookupMACWithRetry(path, "10.9.9.9"); got != "" {
		t.Errorf("lookupMACWithRetry = %q, want the empty string", got)
	}
}

// TestLookupMACWithRetrySkipsTheSleepOnAHit keeps the retry off the fast
// path: the overwhelming majority of reads find the entry first time, and
// paying macRetryDelay on every hit would delay every alert.
func TestLookupMACWithRetrySkipsTheSleepOnAHit(t *testing.T) {
	path := writeARP(t, arpFixture)
	start := time.Now()
	if got := lookupMACWithRetry(path, "10.0.0.66"); got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("lookupMACWithRetry = %q", got)
	}
	if took := time.Since(start); took >= macRetryDelay {
		t.Errorf("a first-look hit still waited %v", took)
	}
}
