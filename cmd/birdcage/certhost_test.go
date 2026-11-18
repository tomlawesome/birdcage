package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/tlsconfig"
)

// testCert builds a self-signed certificate with the given SANs.
func testCert(t *testing.T, dns []string, ips ...string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestCertHostAllower(t *testing.T) {
	cert := testCert(t, []string{"app.example.com", "*.wild.example.com"}, "192.0.2.10", "2001:db8::1")
	allow := certHostAllower(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil })
	cases := []struct{ in, want string }{
		{"app.example.com", "app.example.com"},
		{"APP.Example.COM", "app.example.com"},
		{"app.example.com:8443", "app.example.com"},
		{"App.Example.Com:443", "app.example.com"},
		{"192.0.2.10", "192.0.2.10"},
		{"192.0.2.10:8443", "192.0.2.10"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[2001:db8::1]:8443", "2001:db8::1"},
		{"other.example.com", ""},
		{"evil.example", ""},
		{"192.0.2.11", ""},
		{"[2001:db8::2]:8443", ""},
		{"x.wild.example.com", ""},
		{"wild.example.com", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := allow(c.in); got != c.want {
			t.Errorf("allow(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// In given-certificate mode a plain request on the dashboard port gets a 308
// to https, and never reaches the handler.
func TestServeAllGivenCertAnswersPlainHTTPWith308(t *testing.T) {
	cert := testCert(t, []string{"app.example.com"})
	addr := freeLoopbackAddr(t)
	_, port, _ := net.SplitHostPort(addr)
	reached := make(chan struct{}, 1)
	dashboard := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached <- struct{}{}
		}),
		TLSConfig: &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }},
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveAll(ctx, stop, dashboard, tlsconfig.ModeCert, "", nil, nil, discardLog(), discardLog(), discardLog(), discardLog())
	}()
	t.Cleanup(func() {
		stop()
		if err := <-done; err != nil {
			t.Logf("serveAll after stop: %v", err)
		}
	})

	client := &http.Client{
		Timeout:       2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var resp *http.Response
	var err error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		req, _ := http.NewRequest("GET", "http://"+addr+"/x?y=1", nil)
		req.Host = "app.example.com"
		if resp, err = client.Do(req); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("plain GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "https://app.example.com:"+port+"/x?y=1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	select {
	case <-reached:
		t.Error("handler was reached over plain HTTP")
	default:
	}
}
