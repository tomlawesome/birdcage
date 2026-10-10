package auth_test

import (
	"fmt"
	"net/http"
	"net/netip"
	"testing"

	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/db"
)

// Tests 13 of the specification for issue #8 (owner, 2026-10-10, answer 25a):
// behind a reverse proxy, the client address comes from a forwarding header
// only when the connecting peer is a trusted proxy, and the header is read
// right to left. The seams these tests assume:
//
//	auth.Config.TrustedProxies []netip.Prefix
//	auth.Config.ClientIPHeader string
//	auth.ClientIP(r *http.Request, trusted []netip.Prefix, header string) string
//
// ClientIP returns the address alone (no port), in the form
// netip.Addr.String gives.

func prefixes(t *testing.T, list ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("test prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

// TestClientIPResolution is the table of right-to-left cases: which address
// ClientIP names for a peer, a trusted list, a header name and the header
// lines the peer sent.
func TestClientIPResolution(t *testing.T) {
	const xff = "X-Forwarded-For"
	cases := []struct {
		name    string
		peer    string
		trusted []string
		header  string
		lines   map[string][]string
		want    string
	}{
		{
			name: "no trusted proxies: the header is ignored",
			peer: "192.0.2.10:5000", header: xff,
			lines: map[string][]string{xff: {"1.2.3.4"}},
			want:  "192.0.2.10",
		},
		{
			name: "no trusted proxies and no header: the peer",
			peer: "192.0.2.10:5000", header: xff,
			want: "192.0.2.10",
		},
		{
			name: "trusted peer with a single address",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"1.2.3.4"}},
			want:  "1.2.3.4",
		},
		{
			name: "forged left-most entry is not believed",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"6.6.6.6, 1.2.3.4"}},
			want:  "1.2.3.4",
		},
		{
			name: "whitespace around entries is ignored",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"  6.6.6.6 ,   1.2.3.4  "}},
			want:  "1.2.3.4",
		},
		{
			name: "untrusted peer sending the header: the peer's address",
			peer: "192.0.2.10:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"1.2.3.4"}},
			want:  "192.0.2.10",
		},
		{
			name: "trusted entries on the right are skipped",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"1.2.3.4, 10.0.0.7, 10.0.0.8"}},
			want:  "1.2.3.4",
		},
		{
			name: "the first untrusted entry from the right wins over a forged one further left",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"6.6.6.6, 1.2.3.4, 10.0.0.7"}},
			want:  "1.2.3.4",
		},
		{
			name: "a chain of only trusted entries: the left-most",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"10.0.0.5, 10.0.0.7, 10.0.0.8"}},
			want:  "10.0.0.5",
		},
		{
			name: "trusted peer with no header: the peer",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			want: "10.0.0.1",
		},
		{
			name: "an entry that is not an address is not believed: the peer",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"unknown"}},
			want:  "10.0.0.1",
		},
		{
			name: "several header lines read as one list, right to left",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"6.6.6.6", "1.2.3.4"}},
			want:  "1.2.3.4",
		},
		{
			name: "a bare trusted address",
			peer: "192.0.2.50:5000", trusted: []string{"192.0.2.50/32"}, header: xff,
			lines: map[string][]string{xff: {"1.2.3.4"}},
			want:  "1.2.3.4",
		},
		{
			name: "another header name is the one read",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: "X-Real-IP",
			lines: map[string][]string{"X-Real-Ip": {"1.2.3.4"}, xff: {"6.6.6.6"}},
			want:  "1.2.3.4",
		},
		{
			name: "another header name: X-Forwarded-For is then ignored",
			peer: "10.0.0.1:5000", trusted: []string{"10.0.0.0/8"}, header: "X-Real-IP",
			lines: map[string][]string{xff: {"6.6.6.6"}},
			want:  "10.0.0.1",
		},
		{
			name: "IPv6 peer, untrusted",
			peer: "[2001:db8::1]:443", trusted: []string{"10.0.0.0/8"}, header: xff,
			lines: map[string][]string{xff: {"1.2.3.4"}},
			want:  "2001:db8::1",
		},
		{
			name: "IPv6 trusted peer and IPv6 client",
			peer: "[fd00::1]:443", trusted: []string{"fd00::/8"}, header: xff,
			lines: map[string][]string{xff: {"2001:db8::5"}},
			want:  "2001:db8::5",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "http://birdcage.example.net/api/auth/login", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			r.RemoteAddr = tc.peer
			for name, values := range tc.lines {
				for _, v := range values {
					r.Header.Add(name, v)
				}
			}
			got := auth.ClientIP(r, prefixes(t, tc.trusted...), tc.header)
			if got != tc.want {
				t.Errorf("ClientIP(peer %s, trusted %v, header %q, lines %v) = %q, want %q", tc.peer, tc.trusted, tc.header, tc.lines, got, tc.want)
			}
		})
	}
}

// failedSignIns sends wrong-password sign-ins from one client, each under a
// name that has never been used (so only the client-address bucket can
// refuse it, not any one account's), with the given extra request headers.
// It returns how many were answered 401 before the first 429, and whether a
// 429 came within limit attempts.
func failedSignIns(t *testing.T, base, tag string, header map[string]string, limit int) (refusedBefore int, limited bool) {
	t.Helper()
	h := map[string]string{csrfHeader: csrfValue}
	for k, v := range header {
		h[k] = v
	}
	for i := 0; i < limit; i++ {
		body := map[string]string{"username": fmt.Sprintf("ghost-%s-%d", tag, i), "password": "not-the-password-at-all-1"}
		status, raw := call(t, newClient(t), http.MethodPost, base+"/api/auth/login", body, h)
		switch status {
		case http.StatusTooManyRequests:
			return refusedBefore, true
		case http.StatusUnauthorized:
			refusedBefore++
		default:
			t.Fatalf("failed sign-in %s #%d: status %d, want 401 or 429; body=%s", tag, i, status, raw)
		}
	}
	return refusedBefore, false
}

// oneFailedSignIn is a single wrong-password sign-in under a fresh name; it
// returns the status.
func oneFailedSignIn(t *testing.T, base, tag string, header map[string]string) int {
	t.Helper()
	h := map[string]string{csrfHeader: csrfValue}
	for k, v := range header {
		h[k] = v
	}
	body := map[string]string{"username": "ghost-" + tag, "password": "not-the-password-at-all-1"}
	status, _ := call(t, newClient(t), http.MethodPost, base+"/api/auth/login", body, h)
	return status
}

// startRegistered is startSystemWith after the first admin is registered:
// before any account exists every sign-in answers 503 (setup required).
func startRegistered(t *testing.T, database *db.DB, cfg auth.Config) *system {
	t.Helper()
	sys := startSystemWith(t, database, cfg)
	sys.registerFirstAdmin(t, newClient(t))
	return sys
}

// loopbackProxies lists the peers the test server's own connections come
// from, so the test server plays the trusted reverse proxy.
func loopbackProxies(t *testing.T) []netip.Prefix {
	return prefixes(t, "127.0.0.0/8", "::1/128")
}

// TestTwoClientsBehindATrustedProxyHaveSeparateLimiterBuckets: with the
// connecting peer trusted, five failures from the client X-Forwarded-For
// names do not 429 a different client; the first client is itself limited.
func TestTwoClientsBehindATrustedProxyHaveSeparateLimiterBuckets(t *testing.T) {
	database := openDatabase(t)
	sys := startRegistered(t, database, auth.Config{Key: testKey('a'), TrustedProxies: loopbackProxies(t), ClientIPHeader: "X-Forwarded-For"})
	base := sys.server.URL
	clientA := map[string]string{"X-Forwarded-For": "198.51.100.1"}
	clientB := map[string]string{"X-Forwarded-For": "198.51.100.2"}

	before, limited := failedSignIns(t, base, "a", clientA, 12)
	if !limited {
		t.Fatalf("client A was never limited after %d failed sign-ins; the limiter must still work behind a proxy", before)
	}
	if before < 5 {
		t.Errorf("client A was limited after %d failures, want at least five allowed", before)
	}
	if status := oneFailedSignIn(t, base, "b", clientB); status != http.StatusUnauthorized {
		t.Errorf("client B's first failed sign-in after client A was limited: status %d, want 401 (its own bucket)", status)
	}
	if status := oneFailedSignIn(t, base, "a-again", clientA); status != http.StatusTooManyRequests {
		t.Errorf("client A after being limited: status %d, want 429", status)
	}
}

// TestForwardingHeaderIsIgnoredWithoutTrustedProxies: with no trusted
// proxies (the default), every request is one client, whatever the header
// says: client A's failures limit client B.
func TestForwardingHeaderIsIgnoredWithoutTrustedProxies(t *testing.T) {
	database := openDatabase(t)
	sys := startRegistered(t, database, auth.Config{Key: testKey('a')})
	base := sys.server.URL

	before, limited := failedSignIns(t, base, "a", map[string]string{"X-Forwarded-For": "198.51.100.1"}, 12)
	if !limited {
		t.Fatalf("no 429 after %d failed sign-ins with no trusted proxies", before)
	}
	if status := oneFailedSignIn(t, base, "b", map[string]string{"X-Forwarded-For": "198.51.100.2"}); status != http.StatusTooManyRequests {
		t.Errorf("client B with a different X-Forwarded-For and no trusted proxies: status %d, want 429 (the header must be ignored)", status)
	}
}

// TestForwardingHeaderIsIgnoredFromAnUntrustedPeer: proxies are trusted, but
// not the peer the requests really come from, so the header is ignored.
func TestForwardingHeaderIsIgnoredFromAnUntrustedPeer(t *testing.T) {
	database := openDatabase(t)
	sys := startRegistered(t, database, auth.Config{
		Key: testKey('a'), TrustedProxies: prefixes(t, "10.0.0.0/8", "203.0.113.0/24"), ClientIPHeader: "X-Forwarded-For",
	})
	base := sys.server.URL

	before, limited := failedSignIns(t, base, "a", map[string]string{"X-Forwarded-For": "198.51.100.1"}, 12)
	if !limited {
		t.Fatalf("no 429 after %d failed sign-ins from an untrusted peer", before)
	}
	if status := oneFailedSignIn(t, base, "b", map[string]string{"X-Forwarded-For": "198.51.100.2"}); status != http.StatusTooManyRequests {
		t.Errorf("a different X-Forwarded-For from an untrusted peer: status %d, want 429 (the header must be ignored)", status)
	}
}

// TestForgedLeftMostEntryDoesNotEscapeTheLimiter: behind a trusted proxy the
// client address is the first untrusted entry from the right, so a client
// that varies what it puts on the left of the header stays in one bucket.
func TestForgedLeftMostEntryDoesNotEscapeTheLimiter(t *testing.T) {
	database := openDatabase(t)
	sys := startRegistered(t, database, auth.Config{Key: testKey('a'), TrustedProxies: loopbackProxies(t), ClientIPHeader: "X-Forwarded-For"})
	base := sys.server.URL

	before, limited := failedSignIns(t, base, "a", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.1"}, 12)
	if !limited {
		t.Fatalf("no 429 after %d failed sign-ins", before)
	}
	if status := oneFailedSignIn(t, base, "forged", map[string]string{"X-Forwarded-For": "7.7.7.7, 198.51.100.1"}); status != http.StatusTooManyRequests {
		t.Errorf("same real client with another forged left-most entry: status %d, want 429", status)
	}
	if status := oneFailedSignIn(t, base, "other", map[string]string{"X-Forwarded-For": "6.6.6.6, 198.51.100.2"}); status != http.StatusUnauthorized {
		t.Errorf("a different real client with the same forged left-most entry: status %d, want 401", status)
	}
}

// TestClientIPHeaderNamesTheHeaderRead: with ClientIPHeader set to
// X-Real-IP, that header separates the clients and X-Forwarded-For does not.
func TestClientIPHeaderNamesTheHeaderRead(t *testing.T) {
	database := openDatabase(t)
	sys := startRegistered(t, database, auth.Config{Key: testKey('a'), TrustedProxies: loopbackProxies(t), ClientIPHeader: "X-Real-IP"})
	base := sys.server.URL

	before, limited := failedSignIns(t, base, "a", map[string]string{"X-Real-IP": "198.51.100.1", "X-Forwarded-For": "6.6.6.6"}, 12)
	if !limited {
		t.Fatalf("no 429 after %d failed sign-ins", before)
	}
	if status := oneFailedSignIn(t, base, "b", map[string]string{"X-Real-IP": "198.51.100.2", "X-Forwarded-For": "6.6.6.6"}); status != http.StatusUnauthorized {
		t.Errorf("a different X-Real-IP: status %d, want 401 (its own bucket)", status)
	}
	if status := oneFailedSignIn(t, base, "c", map[string]string{"X-Real-IP": "198.51.100.1", "X-Forwarded-For": "7.7.7.7"}); status != http.StatusTooManyRequests {
		t.Errorf("same X-Real-IP, different X-Forwarded-For: status %d, want 429 (only X-Real-IP is read)", status)
	}
}
