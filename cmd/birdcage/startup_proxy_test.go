package main

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// Reverse-proxy settings of loadStartupConfig (issue #8 items 13-14, owner
// 2026-10-10, answer 25a). The names are written out in full, as in
// startup_auth_test.go. Seams assumed, on the auth.Config that
// loadStartupConfig leaves in startupConfig.auth:
//
//	TrustedProxies []netip.Prefix  (from BIRDCAGE_TRUSTED_PROXIES)
//	TrustUnixSocket bool           (item 15: the entry "unix" in BIRDCAGE_TRUSTED_PROXIES)
//	ClientIPHeader string          (from BIRDCAGE_CLIENT_IP_HEADER, default X-Forwarded-For)
//	SecureCookie   bool            (listener serves TLS, or BIRDCAGE_PUBLIC_URL is https)
const (
	testEnvTrustedProxies = "BIRDCAGE_TRUSTED_PROXIES"
	testEnvClientIPHeader = "BIRDCAGE_CLIENT_IP_HEADER"
	testEnvHTTPAddr       = "BIRDCAGE_HTTP_ADDR"
	testEnvHTTPTLSCert    = "BIRDCAGE_HTTP_TLS_CERT"
	testEnvHTTPTLSKey     = "BIRDCAGE_HTTP_TLS_KEY"
)

func covers(prefixes []netip.Prefix, addr string) bool {
	a := netip.MustParseAddr(addr)
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// TestLoadStartupConfigTrustedProxiesEmptyByDefault: no setting means no
// trusted proxies (forwarding headers are ignored) and the header name
// defaults to X-Forwarded-For.
func TestLoadStartupConfigTrustedProxiesEmptyByDefault(t *testing.T) {
	cfg, err := loadStartupConfig(startupEnv(t, nil), discardLog(), discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("loadStartupConfig: %v", err)
	}
	if len(cfg.auth.TrustedProxies) != 0 {
		t.Errorf("auth.TrustedProxies = %v, want empty by default", cfg.auth.TrustedProxies)
	}
	if cfg.auth.ClientIPHeader != "X-Forwarded-For" {
		t.Errorf("auth.ClientIPHeader = %q, want X-Forwarded-For by default", cfg.auth.ClientIPHeader)
	}
}

// TestLoadStartupConfigClientIPHeaderIsTakenFromTheSetting: another header
// name is passed through as given.
func TestLoadStartupConfigClientIPHeaderIsTakenFromTheSetting(t *testing.T) {
	cfg, err := loadStartupConfig(startupEnv(t, map[string]string{
		testEnvTrustedProxies: "192.0.2.1",
		testEnvClientIPHeader: "X-Real-IP",
	}), discardLog(), discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("loadStartupConfig: %v", err)
	}
	if cfg.auth.ClientIPHeader != "X-Real-IP" {
		t.Errorf("auth.ClientIPHeader = %q, want X-Real-IP", cfg.auth.ClientIPHeader)
	}
}

// TestLoadStartupConfigTrustedProxiesParse: bare IPs, CIDRs and the
// shorthand private, comma-separated, with spaces allowed around entries.
func TestLoadStartupConfigTrustedProxiesParse(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		inside  []string
		outside []string
	}{
		{"a bare IPv4 address", "192.0.2.5", []string{"192.0.2.5"}, []string{"192.0.2.6", "10.0.0.1", "127.0.0.1"}},
		{"a bare IPv6 address", "2001:db8::5", []string{"2001:db8::5"}, []string{"2001:db8::6", "::1"}},
		{"a CIDR", "198.51.100.0/24", []string{"198.51.100.0", "198.51.100.255"}, []string{"198.51.101.1", "192.0.2.5"}},
		{"an IPv6 CIDR", "2001:db8::/32", []string{"2001:db8::1", "2001:db8:ffff::1"}, []string{"2001:db9::1"}},
		{"a list with spaces", "192.0.2.5, 198.51.100.0/24 ,2001:db8::5", []string{"192.0.2.5", "198.51.100.7", "2001:db8::5"}, []string{"192.0.2.6", "10.0.0.1"}},
		{
			"private: loopback, RFC 1918, CGNAT, link-local and IPv6 ULA",
			"private",
			[]string{
				"127.0.0.1", "::1",
				"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1",
				"100.64.0.1", "100.127.255.255",
				"169.254.1.1", "fe80::1",
				"fd00::1", "fdff::1",
			},
			[]string{"8.8.8.8", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.169.0.1", "2001:db8::1"},
		},
		{"private beside a public address", "private,203.0.113.9", []string{"10.1.2.3", "203.0.113.9"}, []string{"203.0.113.10", "8.8.8.8"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadStartupConfig(startupEnv(t, map[string]string{testEnvTrustedProxies: tc.value}), discardLog(), discardLog(), discardLog(), discardLog())
			if err != nil {
				t.Fatalf("loadStartupConfig with %s=%q: %v", testEnvTrustedProxies, tc.value, err)
			}
			for _, a := range tc.inside {
				if !covers(cfg.auth.TrustedProxies, a) {
					t.Errorf("%s=%q: %s is not trusted, want it trusted (list %v)", testEnvTrustedProxies, tc.value, a, cfg.auth.TrustedProxies)
				}
			}
			for _, a := range tc.outside {
				if covers(cfg.auth.TrustedProxies, a) {
					t.Errorf("%s=%q: %s is trusted, want it not trusted (list %v)", testEnvTrustedProxies, tc.value, a, cfg.auth.TrustedProxies)
				}
			}
		})
	}
}

// TestLoadStartupConfigRefusesAnInvalidTrustedProxy: one bad entry fails
// start-up (it is not skipped), and the error names the setting.
func TestLoadStartupConfigRefusesAnInvalidTrustedProxy(t *testing.T) {
	for _, value := range []string{
		"not-an-ip",
		"10.0.0.0/33",
		"10.0.0.0/",
		"300.1.1.1",
		"192.0.2.0/24, bogus",
		"bogus, private",
		"proxy.example.net",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := loadStartupConfig(startupEnv(t, map[string]string{testEnvTrustedProxies: value}), discardLog(), discardLog(), discardLog(), discardLog())
			if err == nil {
				t.Fatalf("loadStartupConfig with %s=%q = nil error, want a refusal", testEnvTrustedProxies, value)
			}
			if !strings.Contains(err.Error(), testEnvTrustedProxies) {
				t.Errorf("error = %q, want it to name %s", err.Error(), testEnvTrustedProxies)
			}
		})
	}
}

// TestLoadStartupConfigSecureCookie is item 14: the session cookie is Secure
// whenever birdcage serves TLS itself or BIRDCAGE_PUBLIC_URL is https.
func TestLoadStartupConfigSecureCookie(t *testing.T) {
	const plain = "127.0.0.1:8080" // plain HTTP, loopback: the shape behind a reverse proxy
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"plain listener and an https public URL", map[string]string{testEnvHTTPAddr: plain, testEnvPublicURL: "https://birdcage.example.net"}, true},
		{"plain listener and an https public URL with a port", map[string]string{testEnvHTTPAddr: plain, testEnvPublicURL: "https://birdcage.example.net:8443"}, true},
		{"plain unix socket and an https public URL", map[string]string{testEnvHTTPAddr: "unix:///run/birdcage/http.sock", testEnvPublicURL: "https://birdcage.example.net"}, true},
		{"plain listener and no public URL", map[string]string{testEnvHTTPAddr: plain}, false},
		{"plain listener and an http public URL", map[string]string{testEnvHTTPAddr: plain, testEnvPublicURL: "http://birdcage.example.net"}, false},
		{"plain listener and an http localhost public URL", map[string]string{testEnvHTTPAddr: plain, testEnvPublicURL: "http://localhost:8080"}, false},
		{"minted-certificate TLS listener and no public URL", map[string]string{testEnvHTTPAddr: "0.0.0.0:8080"}, true},
		{"minted-certificate TLS listener and an http public URL", map[string]string{testEnvHTTPAddr: "0.0.0.0:8080", testEnvPublicURL: "http://birdcage.example.net"}, true},
		{"default listener (minted certificate) and no public URL", map[string]string{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadStartupConfig(startupEnv(t, tc.env), discardLog(), discardLog(), discardLog(), discardLog())
			if err != nil {
				t.Fatalf("loadStartupConfig: %v", err)
			}
			if cfg.auth.SecureCookie != tc.want {
				t.Errorf("auth.SecureCookie = %v, want %v", cfg.auth.SecureCookie, tc.want)
			}
		})
	}
}

// TestLoadStartupConfigSecureCookieWithAnOperatorCertificate: a listener
// serving the operator's own certificate is a TLS listener.
func TestLoadStartupConfigSecureCookieWithAnOperatorCertificate(t *testing.T) {
	certPath, keyPath := mintTestCert(t)
	cfg, err := loadStartupConfig(startupEnv(t, map[string]string{
		testEnvHTTPAddr:    "127.0.0.1:8443",
		testEnvHTTPTLSCert: certPath,
		testEnvHTTPTLSKey:  keyPath,
	}), discardLog(), discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("loadStartupConfig: %v", err)
	}
	if !cfg.auth.SecureCookie {
		t.Error("auth.SecureCookie = false with an operator certificate, want true")
	}
}

// TestLoadStartupConfigTrustedProxiesUnix is item 15: the entry unix trusts a
// proxy connected over the unix socket. It is accepted alone and beside IPs,
// CIDRs and private, in any position and any letter case, and it adds no
// address to the trusted prefixes (it is not an IP entry).
func TestLoadStartupConfigTrustedProxiesUnix(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		unix    bool
		inside  []string
		outside []string
	}{
		{"unix alone", "unix", true, nil, []string{"127.0.0.1", "10.0.0.1", "::1", "192.0.2.5"}},
		{"unix with spaces", "  unix ", true, nil, []string{"127.0.0.1"}},
		{"unix in capitals", "UNIX", true, nil, []string{"127.0.0.1"}},
		{"unix beside a bare address", "unix,192.0.2.5", true, []string{"192.0.2.5"}, []string{"127.0.0.1", "192.0.2.6"}},
		{"unix after a CIDR", "198.51.100.0/24, unix", true, []string{"198.51.100.9"}, []string{"127.0.0.1"}},
		{"unix beside private", "private,unix", true, []string{"127.0.0.1", "10.1.2.3", "::1"}, []string{"8.8.8.8"}},
		{"unix first, then private and an address", "unix, private, 203.0.113.9", true, []string{"10.1.2.3", "203.0.113.9"}, []string{"203.0.113.10"}},
		{"no unix entry: not trusted", "private,192.0.2.5", false, []string{"10.1.2.3"}, []string{"8.8.8.8"}},
		{"private does not include unix", "private", false, []string{"127.0.0.1"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadStartupConfig(startupEnv(t, map[string]string{testEnvTrustedProxies: tc.value}), discardLog(), discardLog(), discardLog(), discardLog())
			if err != nil {
				t.Fatalf("loadStartupConfig with %s=%q: %v", testEnvTrustedProxies, tc.value, err)
			}
			if cfg.auth.TrustUnixSocket != tc.unix {
				t.Errorf("%s=%q: auth.TrustUnixSocket = %v, want %v", testEnvTrustedProxies, tc.value, cfg.auth.TrustUnixSocket, tc.unix)
			}
			for _, a := range tc.inside {
				if !covers(cfg.auth.TrustedProxies, a) {
					t.Errorf("%s=%q: %s is not trusted, want it trusted (list %v)", testEnvTrustedProxies, tc.value, a, cfg.auth.TrustedProxies)
				}
			}
			for _, a := range tc.outside {
				if covers(cfg.auth.TrustedProxies, a) {
					t.Errorf("%s=%q: %s is trusted, want it not trusted (list %v)", testEnvTrustedProxies, tc.value, a, cfg.auth.TrustedProxies)
				}
			}
		})
	}
}

// TestLoadStartupConfigTrustUnixSocketOffByDefault: with no setting, a
// unix-socket peer is not trusted.
func TestLoadStartupConfigTrustUnixSocketOffByDefault(t *testing.T) {
	cfg, err := loadStartupConfig(startupEnv(t, map[string]string{testEnvHTTPAddr: "unix:///run/birdcage/http.sock"}), discardLog(), discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("loadStartupConfig: %v", err)
	}
	if cfg.auth.TrustUnixSocket {
		t.Error("auth.TrustUnixSocket = true with no BIRDCAGE_TRUSTED_PROXIES, want false")
	}
}

// TestLoadStartupConfigStillRefusesABadEntryBesideUnix: unix does not loosen
// the check on the other entries.
func TestLoadStartupConfigStillRefusesABadEntryBesideUnix(t *testing.T) {
	for _, value := range []string{"unix, bogus", "bogus,unix", "unix:/run/birdcage/http.sock", "unixsocket", "unix,10.0.0.0/33"} {
		t.Run(value, func(t *testing.T) {
			_, err := loadStartupConfig(startupEnv(t, map[string]string{testEnvTrustedProxies: value}), discardLog(), discardLog(), discardLog(), discardLog())
			if err == nil {
				t.Fatalf("loadStartupConfig with %s=%q = nil error, want a refusal", testEnvTrustedProxies, value)
			}
			if !strings.Contains(err.Error(), testEnvTrustedProxies) {
				t.Errorf("error = %q, want it to name %s", err.Error(), testEnvTrustedProxies)
			}
		})
	}
}

// TestParseTrustedProxiesSplitsPeersFromHops (SEC-A1): the private shorthand
// names peers (whose header is believed) but never hops (chain entries that
// are skipped); an explicit address or CIDR is both.
func TestParseTrustedProxiesSplitsPeersFromHops(t *testing.T) {
	cases := []struct {
		name      string
		value     string
		peersHave []string
		peersLack []string
		hopsHave  []string
		hopsLack  []string
	}{
		{"private: peers only", "private", []string{"10.1.2.3", "100.64.0.9"}, nil, nil, []string{"10.1.2.3", "100.64.0.9", "192.168.1.50", "127.0.0.1"}},
		{"private plus an address: only the address is a hop", "private,203.0.113.9", []string{"10.1.2.3", "203.0.113.9"}, nil, []string{"203.0.113.9"}, []string{"10.1.2.3", "100.64.0.9"}},
		{"an explicit CIDR is both", "10.0.0.0/8", []string{"10.1.2.3"}, nil, []string{"10.1.2.3"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peers, hops, _, err := parseTrustedProxies(tc.value)
			if err != nil {
				t.Fatalf("parseTrustedProxies(%q): %v", tc.value, err)
			}
			for _, a := range tc.peersHave {
				if !covers(peers, a) {
					t.Errorf("peers %v do not contain %s", peers, a)
				}
			}
			for _, a := range tc.hopsHave {
				if !covers(hops, a) {
					t.Errorf("hops %v do not contain %s", hops, a)
				}
			}
			for _, a := range tc.hopsLack {
				if covers(hops, a) {
					t.Errorf("hops %v contain %s, want none of the private shorthand", hops, a)
				}
			}
			if tc.value == "private" && len(hops) != 0 {
				t.Errorf("hops = %v, want empty for private", hops)
			}
		})
	}
}

// warnRecorder is a slog handler that keeps the Warn-or-higher messages.
type warnRecorder struct {
	mu    *sync.Mutex
	warns *[]string
}

func newWarnRecorder() *warnRecorder {
	return &warnRecorder{mu: &sync.Mutex{}, warns: &[]string{}}
}

func (h *warnRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (h *warnRecorder) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		h.mu.Lock()
		*h.warns = append(*h.warns, r.Message)
		h.mu.Unlock()
	}
	return nil
}
func (h *warnRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *warnRecorder) WithGroup(string) slog.Handler      { return h }

// trustedProxyWarnings loads the config and returns the Warn-level
// configLog messages that name BIRDCAGE_TRUSTED_PROXIES.
func trustedProxyWarnings(t *testing.T, env map[string]string) []string {
	t.Helper()
	rec := newWarnRecorder()
	if _, err := loadStartupConfig(startupEnv(t, env), slog.New(rec), discardLog(), discardLog(), discardLog()); err != nil {
		t.Fatalf("loadStartupConfig: %v", err)
	}
	var got []string
	for _, m := range *rec.warns {
		if strings.Contains(m, testEnvTrustedProxies) {
			got = append(got, m)
		}
	}
	return got
}

// Residual of SEC-A1: trusted proxies on a listener reachable off the box
// warn once; loopback, unix-socket and unset settings stay quiet.
func TestLoadStartupConfigWarnsTrustedProxiesOnNonLoopbackBind(t *testing.T) {
	got := trustedProxyWarnings(t, map[string]string{testEnvTrustedProxies: "private"})
	if len(got) != 1 {
		t.Errorf("Warn lines naming %s = %q, want exactly one (default bind is non-loopback)", testEnvTrustedProxies, got)
	}
}

func TestLoadStartupConfigNoTrustedProxiesWarningOnLoopbackBind(t *testing.T) {
	got := trustedProxyWarnings(t, map[string]string{testEnvTrustedProxies: "private", testEnvHTTPAddr: "127.0.0.1:8080"})
	if len(got) != 0 {
		t.Errorf("Warn lines = %q, want none on a loopback bind", got)
	}
}

func TestLoadStartupConfigNoTrustedProxiesWarningOnUnixSocket(t *testing.T) {
	got := trustedProxyWarnings(t, map[string]string{testEnvTrustedProxies: "unix", testEnvHTTPAddr: "unix:///run/birdcage/http.sock"})
	if len(got) != 0 {
		t.Errorf("Warn lines = %q, want none on a unix socket", got)
	}
}

func TestLoadStartupConfigNoTrustedProxiesWarningWhenUnset(t *testing.T) {
	got := trustedProxyWarnings(t, nil)
	if len(got) != 0 {
		t.Errorf("Warn lines = %q, want none when %s is unset", got, testEnvTrustedProxies)
	}
}
