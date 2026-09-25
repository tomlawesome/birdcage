package store

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// signingCA is a test-only CA built from crypto/x509 alone, so store
// tests can sign real certificates without importing internal/ca.
type signingCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

var (
	testCAOnce sync.Once
	testCA     *signingCA
)

func testSigningCA() *signingCA {
	testCAOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "store-test-ca"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			panic(err)
		}
		testCA = &signingCA{key: key, cert: cert}
	})
	return testCA
}

func (c *signingCA) sign(cn string, kind agentkind.Kind, ttl time.Duration) ([]byte, *x509.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, OrganizationalUnit: []string{string(kind)}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &leafKey.PublicKey, c.key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

// recordCert signs and records one certificate for canaryID.
func recordCert(t *testing.T, database db.Conn, canaryID string) ClientCert {
	t.Helper()
	_, cert, err := testSigningCA().sign(canaryID, agentkind.Honeypot, time.Hour)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec, err := RecordClientCert(context.Background(), database, canaryID, cert)
	if err != nil {
		t.Fatalf("RecordClientCert: %v", err)
	}
	return rec
}

func lookupCert(t *testing.T, database *db.DB, fp string) ClientCert {
	t.Helper()
	c, err := LookupClientCertByFingerprint(context.Background(), database, fp)
	if err != nil {
		t.Fatalf("LookupClientCertByFingerprint: %v", err)
	}
	return c
}

func TestRecordClientCertRoundTripsAndRefusesAnotherCanarysCN(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		_, cert, err := testSigningCA().sign("canary-a", agentkind.Honeypot, time.Hour)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		rec, err := RecordClientCert(ctx, database, "canary-a", cert)
		if err != nil {
			t.Fatalf("RecordClientCert: %v", err)
		}
		if rec.Fingerprint != CertFingerprint(cert.Raw) || rec.Serial != cert.SerialNumber.Text(16) {
			t.Errorf("recorded %+v, want the certificate's fingerprint and serial", rec)
		}
		if !rec.NotAfter.Equal(cert.NotAfter) || !rec.NotBefore.Equal(cert.NotBefore) {
			t.Errorf("validity = %s..%s, want %s..%s", rec.NotBefore, rec.NotAfter, cert.NotBefore, cert.NotAfter)
		}

		if _, err := RecordClientCert(ctx, database, "canary-b", cert); err == nil {
			t.Error("RecordClientCert recorded canary-a's certificate against canary-b")
		}
		if _, err := RecordClientCert(ctx, database, "canary-a", cert); err == nil {
			t.Error("RecordClientCert recorded the same certificate twice")
		}
		if _, err := LookupClientCertByFingerprint(ctx, database, "00"); !errors.Is(err, ErrClientCertNotFound) {
			t.Errorf("unknown fingerprint err = %v, want ErrClientCertNotFound", err)
		}
	})
}

// TestRecordClientCertFirstUseRevokesOnlyOlder is B2's one-way rule:
// first use of a certificate revokes every older one of the same
// canary and nothing newer, nothing of any other canary, and only once.
// Three certificates are recorded back to back -- inside one second,
// so X.509 validity alone could not order them; id does.
func TestRecordClientCertFirstUseRevokesOnlyOlder(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		k1 := recordCert(t, database, "canary-a")
		k2 := recordCert(t, database, "canary-a")
		k3 := recordCert(t, database, "canary-a")
		other := recordCert(t, database, "canary-b")
		at := mustParse(t, "2026-01-01T00:00:00Z")

		first, revoked, err := RecordClientCertFirstUse(ctx, database, k2, at)
		if err != nil {
			t.Fatalf("RecordClientCertFirstUse(k2): %v", err)
		}
		if !first || revoked != 1 {
			t.Fatalf("first=%v revoked=%d, want true, 1 (k1 only)", first, revoked)
		}
		if lookupCert(t, database, k1.Fingerprint).Live() {
			t.Error("k1 still live after k2's first use")
		}
		if !lookupCert(t, database, k3.Fingerprint).Live() {
			t.Error("k3 (newer) revoked by k2's first use")
		}
		if !lookupCert(t, database, other.Fingerprint).Live() {
			t.Error("another canary's certificate revoked")
		}

		again, revoked, err := RecordClientCertFirstUse(ctx, database, k2, at.Add(time.Minute))
		if err != nil {
			t.Fatalf("second RecordClientCertFirstUse(k2): %v", err)
		}
		if again || revoked != 0 {
			t.Errorf("second first-use: first=%v revoked=%d, want false, 0", again, revoked)
		}
		if got := lookupCert(t, database, k2.Fingerprint).FirstUsedAt; got == nil || !got.Equal(at) {
			t.Errorf("k2 first_used_at = %v, want %s (unchanged)", got, at)
		}

		if _, revoked, err := RecordClientCertFirstUse(ctx, database, k3, at.Add(2*time.Minute)); err != nil || revoked != 1 {
			t.Errorf("k3 first use: revoked=%d err=%v, want 1 (k2), nil", revoked, err)
		}
		// A revoked certificate's first use changes nothing.
		if first, _, err := RecordClientCertFirstUse(ctx, database, k1, at); err != nil || first {
			t.Errorf("revoked k1 first use: first=%v err=%v, want false, nil", first, err)
		}
		cur, err := CurrentClientCert(ctx, database, "canary-a")
		if err != nil || cur.ID != k3.ID {
			t.Errorf("CurrentClientCert = %d, %v; want k3 (%d)", cur.ID, err, k3.ID)
		}
	})
}

// TestTokenBoundToCert is B3's binding, including the one window
// ADR-0012 B2 requires: the outgoing certificate still pairs with the
// carried token until the new certificate's first use.
func TestTokenBoundToCert(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		k1 := recordCert(t, database, "canary-a")
		foreign := recordCert(t, database, "canary-b")
		now := mustParse(t, "2026-01-01T00:00:00Z")

		raw, _, err := MintCanaryTokenForCert(ctx, database, "canary-a", k1.Fingerprint, now)
		if err != nil {
			t.Fatalf("MintCanaryTokenForCert: %v", err)
		}
		tok, err := LookupCanaryTokenByHash(ctx, database, HashToken(raw))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash: %v", err)
		}
		check := func(name string, tok CanaryToken, cert ClientCert, want bool) {
			t.Helper()
			got, err := TokenBoundToCert(ctx, database, tok, cert)
			if err != nil {
				t.Fatalf("%s: TokenBoundToCert: %v", name, err)
			}
			if got != want {
				t.Errorf("%s: TokenBoundToCert = %v, want %v", name, got, want)
			}
		}
		check("exact binding", tok, k1, true)
		check("another canary's certificate", tok, foreign, false)

		unboundRaw, _, err := MintCanaryToken(ctx, database, "canary-a", now)
		if err != nil {
			t.Fatalf("MintCanaryToken: %v", err)
		}
		unbound, err := LookupCanaryTokenByHash(ctx, database, HashToken(unboundRaw))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash(unbound): %v", err)
		}
		check("unbound (NULL) token", unbound, k1, false)

		// Renewal: k2 recorded, every live token carried across.
		k2 := recordCert(t, database, "canary-a")
		n, err := BindCanaryTokensToCert(ctx, database, "canary-a", k2.Fingerprint)
		if err != nil {
			t.Fatalf("BindCanaryTokensToCert: %v", err)
		}
		if n != 2 {
			t.Errorf("rebound %d tokens, want 2 (both live tokens of canary-a)", n)
		}
		tok, err = LookupCanaryTokenByHash(ctx, database, HashToken(raw))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash after rebind: %v", err)
		}
		if tok.CertFingerprint != k2.Fingerprint {
			t.Fatalf("token bound to %s after renewal, want k2", tok.CertFingerprint)
		}
		check("new certificate after renewal", tok, k2, true)
		check("outgoing certificate while the new one is unused", tok, k1, true)

		// A token bound to the older certificate never pairs with a
		// newer one it was not carried to.
		k3 := recordCert(t, database, "canary-a")
		older := tok
		older.CertFingerprint = k1.Fingerprint
		check("token on older certificate, newer certificate presented", older, k3, false)

		if _, _, err := RecordClientCertFirstUse(ctx, database, lookupCert(t, database, k2.Fingerprint), now); err != nil {
			t.Fatalf("RecordClientCertFirstUse(k2): %v", err)
		}
		check("outgoing certificate after the new one's first use", tok, lookupCert(t, database, k1.Fingerprint), false)
	})
}

// TestRevokeCanaryCredentialsEndsEverythingForOneNode is B5's store
// side: every token and every certificate of one canary, in one
// transaction, and nothing of any other canary.
func TestRevokeCanaryCredentialsEndsEverythingForOneNode(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		now := mustParse(t, "2026-01-01T00:00:00Z")
		for _, id := range []string{"canary-a", "canary-b"} {
			if err := InsertCanary(ctx, database, Canary{ID: id, Name: "same-name", Lane: "lan", Kind: agentkind.Honeypot, EnrolledAt: now}); err != nil {
				t.Fatalf("InsertCanary(%s): %v", id, err)
			}
		}
		a1 := recordCert(t, database, "canary-a")
		a2 := recordCert(t, database, "canary-a")
		b1 := recordCert(t, database, "canary-b")
		aTok1, _, _ := MintCanaryTokenForCert(ctx, database, "canary-a", a1.Fingerprint, now)
		aTok2, _, _ := MintCanaryTokenForCert(ctx, database, "canary-a", a2.Fingerprint, now.Add(time.Second))
		bTok, _, _ := MintCanaryTokenForCert(ctx, database, "canary-b", b1.Fingerprint, now)

		revokeAt := now.Add(time.Hour)
		tx, err := database.Begin(ctx)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		got, err := RevokeCanaryCredentials(ctx, tx, "canary-a", revokeAt)
		if err != nil {
			t.Fatalf("RevokeCanaryCredentials: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if got.Tokens != 2 || got.Certificates != 2 {
			t.Errorf("revoked %+v, want 2 tokens and 2 certificates", got)
		}
		for _, raw := range []string{aTok1, aTok2} {
			if _, err := LookupCanaryTokenByHash(ctx, database, HashToken(raw)); !errors.Is(err, ErrTokenNotFound) {
				t.Errorf("canary-a token still resolves: err = %v", err)
			}
		}
		for _, c := range []ClientCert{a1, a2} {
			if lookupCert(t, database, c.Fingerprint).Live() {
				t.Errorf("canary-a certificate %d still live", c.ID)
			}
		}
		if _, err := LookupCanaryTokenByHash(ctx, database, HashToken(bTok)); err != nil {
			t.Errorf("canary-b's token revoked too: %v", err)
		}
		if !lookupCert(t, database, b1.Fingerprint).Live() {
			t.Error("canary-b's certificate revoked too")
		}

		// A second revoke changes nothing, and keeps the first time.
		tx, err = database.Begin(ctx)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		again, err := RevokeCanaryCredentials(ctx, tx, "canary-a", revokeAt.Add(time.Hour))
		if err != nil {
			t.Fatalf("second RevokeCanaryCredentials: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if again.Tokens != 0 || again.Certificates != 0 {
			t.Errorf("second revoke changed %+v, want nothing", again)
		}
		if got := lookupCert(t, database, a1.Fingerprint).RevokedAt; got == nil || !got.Equal(revokeAt) {
			t.Errorf("a1 revoked_at = %v, want %s", got, revokeAt)
		}

		// An unknown id is an error, and a rolled-back revoke is no revoke.
		tx, err = database.Begin(ctx)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if _, err := RevokeCanaryCredentials(ctx, tx, "no-such-canary", revokeAt); !errors.Is(err, ErrCanaryNotFound) {
			t.Errorf("unknown canary err = %v, want ErrCanaryNotFound", err)
		}
		if _, err := RevokeCanaryCredentials(ctx, tx, "canary-b", revokeAt); err != nil {
			t.Fatalf("RevokeCanaryCredentials(canary-b): %v", err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatalf("Rollback: %v", err)
		}
		if _, err := LookupCanaryTokenByHash(ctx, database, HashToken(bTok)); err != nil {
			t.Errorf("rolled-back revoke still revoked canary-b's token: %v", err)
		}
	})
}

// TestSecondEnrolmentUnderAnExistingNameIsANewNode is ADR-0012 B5's
// Keylime CVE-2025-13609 lesson: enrolling a second node under the
// name of a live one creates a new canary id with its own credential and
// leaves the live node's credential exactly as it was.
func TestSecondEnrolmentUnderAnExistingNameIsANewNode(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")

		secret1, _ := contactedFixture(t, database, mintedAt)
		first, outcome, err := Provision(ctx, database, HashToken(secret1), mintedAt.Add(2*time.Minute), fakeIssue)
		if err != nil || outcome != Provisioned {
			t.Fatalf("first Provision: %v, %v", outcome, err)
		}
		firstTok, err := LookupCanaryTokenByHash(ctx, database, HashToken(first.CanaryToken))
		if err != nil {
			t.Fatalf("first token lookup: %v", err)
		}

		// contactedFixture always uses the same name, so this is a second
		// enrolment under the first node's name.
		secret2, _ := contactedFixture(t, database, mintedAt.Add(time.Hour))
		second, outcome, err := Provision(ctx, database, HashToken(secret2), mintedAt.Add(time.Hour+2*time.Minute), fakeIssue)
		if err != nil || outcome != Provisioned {
			t.Fatalf("second Provision: %v, %v", outcome, err)
		}
		if second.CanaryID == first.CanaryID {
			t.Fatal("second enrolment under the same name reused the live node's id")
		}

		stillFirst, err := LookupCanaryTokenByHash(ctx, database, HashToken(first.CanaryToken))
		if err != nil {
			t.Fatalf("first node's token no longer resolves after the second enrolment: %v", err)
		}
		if stillFirst.CanaryID != first.CanaryID || stillFirst.CertFingerprint != firstTok.CertFingerprint {
			t.Errorf("first node's token changed: %+v, was %+v", stillFirst, firstTok)
		}
		if !lookupCert(t, database, firstTok.CertFingerprint).Live() {
			t.Error("first node's certificate revoked by the second enrolment")
		}
		certs, err := ListClientCertsForCanary(ctx, database, first.CanaryID)
		if err != nil || len(certs) != 1 {
			t.Errorf("first node has %d certificates (err %v), want exactly its own 1", len(certs), err)
		}
	})
}

// TestProvisionRollsBackWhenTheCertificateCannotBeRecorded: a signer
// returning a certificate for the wrong identity is refused at record
// time, and the whole provisioning rolls back -- secret unspent, no
// canary, no token, no certificate row.
func TestProvisionRollsBackWhenTheCertificateCannotBeRecorded(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		mintedAt := mustParse(t, "2026-01-01T00:00:00Z")
		secret, session := contactedFixture(t, database, mintedAt)
		wrongCN := func(string, agentkind.Kind) ([]byte, *x509.Certificate, error) {
			return testSigningCA().sign("somebody-else", agentkind.Honeypot, time.Hour)
		}
		if _, _, err := Provision(context.Background(), database, HashToken(secret), mintedAt.Add(2*time.Minute), wrongCN); err == nil {
			t.Fatal("Provision accepted a certificate naming another canary")
		}
		for _, table := range []string{"agents", "agent_tokens", "client_certs"} {
			var n int
			if err := database.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
				t.Fatalf("count %s: %v", table, err)
			}
			if n != 0 {
				t.Errorf("%s has %d rows after a rolled-back provision, want 0", table, n)
			}
		}
		var secretHash *string
		if err := database.QueryRow(`SELECT enrolment_secret_hash FROM enrolment_sessions WHERE id = ?`, session.ID).Scan(&secretHash); err != nil {
			t.Fatalf("scan session: %v", err)
		}
		if secretHash == nil {
			t.Error("enrolment secret spent by a provision that rolled back")
		}
	})
}
