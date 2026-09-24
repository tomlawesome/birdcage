package ingest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #130 security review: rotate/renew consistency, renewed
// certificates nobody switched to, and concurrent renewals.

// tryPost is credFixture.post without t: safe to call from a goroutine
// other than the test's own.
func (f *credFixture) tryPost(path, token string, cert tls.Certificate, body any) (int, []byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: f.ca.Pool(), Certificates: []tls.Certificate{cert}},
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, f.srv.URL+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }() // test teardown
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, out, err
}

func certSerial(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.SerialNumber.Text(16)
}

// TestRenewalBetweenRotationReadAndCommitKeepsTheNodeWorking: a renewal
// that lands after rotation has read the canary's current certificate
// but before rotation commits must still leave the node a working pair
// -- its renewed certificate with its rotated token. Before
// store.LockCanaryCredentials, on Postgres the renewal committed inside
// that window, the rotated token was bound to the outgoing certificate,
// and the pair was refused (401): an honest node locked out. (SQLite
// serialises every transaction already, so there the renewal simply
// waits; the test runs on both.)
func TestRenewalBetweenRotationReadAndCommitKeepsTheNodeWorking(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		var hook atomic.Pointer[func()]
		f := newCredFixture(t, database, func(h *ingestHandler) {
			h.afterRotateCertRead = func() {
				if fn := hook.Load(); fn != nil {
					(*fn)()
				}
			}
		})
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)
		if got := f.heartbeat(t, n.token, n.cert); got != http.StatusOK {
			t.Fatalf("before: status = %d, want 200", got)
		}

		key, body := renewBody(t)
		type result struct {
			status int
			out    []byte
			err    error
		}
		renewed := make(chan result, 1)
		var once sync.Once
		interleave := func() {
			once.Do(func() {
				finished := make(chan struct{})
				go func() {
					defer close(finished)
					status, out, err := f.tryPost("/ingest/renew", n.token, n.cert, body)
					renewed <- result{status, out, err}
				}()
				// Give the renewal every chance to commit inside
				// rotation's window. With the lock it cannot, and this
				// times out; without it, it finishes here.
				select {
				case <-finished:
				case <-time.After(time.Second):
				}
			})
		}
		hook.Store(&interleave)

		status, out := f.post(t, "/ingest/rotate", n.token, n.cert, nil, "")
		if status != http.StatusOK {
			t.Fatalf("rotate: status = %d; %s", status, out)
		}
		var rot rotateResponse
		if err := json.Unmarshal(out, &rot); err != nil {
			t.Fatalf("unmarshal rotate: %v", err)
		}

		r := <-renewed
		if r.err != nil || r.status != http.StatusOK {
			t.Fatalf("renew: status = %d, err = %v; %s", r.status, r.err, r.out)
		}
		var resp renewResponse
		if err := json.Unmarshal(r.out, &resp); err != nil {
			t.Fatalf("unmarshal renew: %v", err)
		}
		newCert := keyPair(t, []byte(resp.ClientCertPEM), key)

		if got := f.heartbeat(t, rot.Token, newCert); got != http.StatusOK {
			t.Errorf("rotated token over the renewed certificate: status = %d, want 200", got)
		}
	})
}

// TestRenewalSupersedesAnUnusedRenewedCertificate: a copy of the
// node's certificate and token renews and never presents the result,
// hoping to keep a hidden seven-day credential. The real node's next
// renewal revokes it, audited ingest.cert_renewal_superseded naming its
// serial, and is not refused.
func TestRenewalSupersedesAnUnusedRenewedCertificate(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		real := f.enrolNode(t, "node-a", agentkind.Honeypot)
		if got := f.heartbeat(t, real.token, real.cert); got != http.StatusOK {
			t.Fatalf("before: status = %d, want 200", got)
		}
		copied := real

		status, hidden, _ := f.renew(t, copied)
		if status != http.StatusOK {
			t.Fatalf("copy renews: status = %d", status)
		}
		status, renewed, _ := f.renew(t, real)
		if status != http.StatusOK {
			t.Fatalf("real node renews while the copy's certificate is pending: status = %d, want 200", status)
		}

		if got := f.heartbeat(t, real.token, hidden); got != http.StatusUnauthorized {
			t.Errorf("superseded pending certificate: status = %d, want 401", got)
		}
		if got := auditCount(t, database, "ingest.cert_renewal_superseded", "node-a"); got != 1 {
			t.Fatalf("ingest.cert_renewal_superseded rows = %d, want 1", got)
		}
		var reason string
		if err := database.QueryRow(`SELECT reason FROM audit_log WHERE action = ? AND target = ?`,
			"ingest.cert_renewal_superseded", "node-a").Scan(&reason); err != nil {
			t.Fatalf("read audit reason: %v", err)
		}
		if serial := certSerial(t, hidden); !strings.Contains(reason, serial) {
			t.Errorf("audit reason %q does not name the superseded serial %s", reason, serial)
		}
		if got := f.heartbeat(t, real.token, renewed); got != http.StatusOK {
			t.Errorf("latest renewed certificate: status = %d, want 200", got)
		}
	})
}

// TestRenewalRetryAfterLostResponseSucceeds is the honest agent's path
// through the same rule: its renewal response is lost, it retries with
// a fresh key over its current certificate, and the retry's certificate
// works -- with its token and a later rotated one -- while the current
// certificate keeps working until the new one's first use.
func TestRenewalRetryAfterLostResponseSucceeds(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)
		if got := f.heartbeat(t, n.token, n.cert); got != http.StatusOK {
			t.Fatalf("before: status = %d, want 200", got)
		}
		if status, _, _ := f.renew(t, n); status != http.StatusOK {
			t.Fatalf("first renewal: status = %d", status)
		} // response "lost": its certificate is never used
		status, retried, _ := f.renew(t, n)
		if status != http.StatusOK {
			t.Fatalf("retried renewal: status = %d, want 200", status)
		}
		if got := f.heartbeat(t, n.token, n.cert); got != http.StatusOK {
			t.Errorf("current certificate before the retry's first use: status = %d, want 200", got)
		}
		if got := f.heartbeat(t, n.token, retried); got != http.StatusOK {
			t.Fatalf("retried certificate: status = %d, want 200", got)
		}
		status, out := f.post(t, "/ingest/rotate", n.token, retried, nil, "")
		if status != http.StatusOK {
			t.Fatalf("rotate: status = %d; %s", status, out)
		}
		var rot rotateResponse
		if err := json.Unmarshal(out, &rot); err != nil {
			t.Fatalf("unmarshal rotate: %v", err)
		}
		if got := f.heartbeat(t, rot.Token, retried); got != http.StatusOK {
			t.Errorf("rotated token over the retried certificate: status = %d, want 200", got)
		}
	})
}

// TestConcurrentRenewalsLeaveOnePendingCertificate: several renewals
// for one canary at once all succeed, but exactly one of the
// certificates they return is left usable -- the rest are superseded.
func TestConcurrentRenewalsLeaveOnePendingCertificate(t *testing.T) {
	const renewals = 5
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		f := newCredFixture(t, database)
		n := f.enrolNode(t, "node-a", agentkind.Honeypot)
		if got := f.heartbeat(t, n.token, n.cert); got != http.StatusOK {
			t.Fatalf("before: status = %d, want 200", got)
		}
		current, err := store.LookupClientCertByFingerprint(context.Background(), database, store.CertFingerprint(n.cert.Certificate[0]))
		if err != nil {
			t.Fatalf("look up current certificate: %v", err)
		}

		keys := make([]*ecdsa.PrivateKey, renewals)
		bodies := make([]map[string]string, renewals)
		for i := range keys {
			keys[i], bodies[i] = renewBody(t)
		}
		statuses := make([]int, renewals)
		outs := make([][]byte, renewals)
		errs := make([]error, renewals)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < renewals; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				statuses[i], outs[i], errs[i] = f.tryPost("/ingest/renew", n.token, n.cert, bodies[i])
			}(i)
		}
		close(start)
		wg.Wait()

		var certs []tls.Certificate
		for i := 0; i < renewals; i++ {
			if errs[i] != nil || statuses[i] != http.StatusOK {
				t.Fatalf("renewal %d: status = %d, err = %v; %s", i, statuses[i], errs[i], outs[i])
			}
			var resp renewResponse
			if err := json.Unmarshal(outs[i], &resp); err != nil {
				t.Fatalf("unmarshal renewal %d: %v", i, err)
			}
			certs = append(certs, keyPair(t, []byte(resp.ClientCertPEM), keys[i]))
		}

		all, err := store.ListClientCertsForCanary(context.Background(), database, "node-a")
		if err != nil {
			t.Fatalf("ListClientCertsForCanary: %v", err)
		}
		pending := 0
		for _, c := range all {
			if c.ID > current.ID && c.Live() && c.FirstUsedAt == nil {
				pending++
			}
		}
		if pending != 1 {
			t.Errorf("live unused renewed certificates = %d, want exactly 1", pending)
		}
		if got := auditCount(t, database, "ingest.cert_renewal_superseded", "node-a"); got != renewals-1 {
			t.Errorf("ingest.cert_renewal_superseded rows = %d, want %d", got, renewals-1)
		}

		usable := 0
		for i, c := range certs {
			switch got := f.heartbeat(t, n.token, c); got {
			case http.StatusOK:
				usable++
			case http.StatusUnauthorized:
			default:
				t.Errorf("renewed certificate %d: status = %d", i, got)
			}
		}
		if usable != 1 {
			t.Errorf("usable renewed certificates = %d, want exactly 1 (%s)", usable, fmt.Sprint(statuses))
		}
	})
}
