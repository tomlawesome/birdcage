package approval

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// The fixtures below are built by signing a message in the test with a
// key generated in the test, and then mutating the result once per
// rule. Nothing here is a committed signature: a real provider's
// signature cannot be a fixture (it would be the owner's own mail), and
// a committed synthetic one would pin the library's output rather than
// this package's rules. `birdcage approval check` exists so real
// signatures can be tried by hand instead.

const (
	testDomain    = "example.net"
	testSelector  = "birdcage2026"
	testPinned    = "admin@example.net"
	testReference = "u-2026-09-19-7f3a"
	testBody      = "Yes, go ahead.\r\n\r\nOn Friday, birdcage wrote:\r\n> please approve\r\n"
)

// testKey is a signing key and the DNS TXT record that publishes its
// public half, so a fixture and the resolver that checks it cannot
// drift apart.
type testKey struct {
	signer crypto.Signer
	txt    string
}

func rsaTestKey(t *testing.T) testKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}
	return testKey{signer: key, txt: "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)}
}

func ed25519TestKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return testKey{signer: priv, txt: "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)}
}

// resolverFor returns a LookupTXT that answers only from records, so a
// test that reaches for a name it did not publish fails loudly rather
// than falling through to the network.
func resolverFor(records map[string]string) func(string) ([]string, error) {
	return func(name string) ([]string, error) {
		txt, ok := records[name]
		if !ok {
			return nil, fmt.Errorf("no TXT record for %s in this test", name)
		}
		return []string{txt}, nil
	}
}

func keyRecords(key testKey) map[string]string {
	return map[string]string{testSelector + "._domainkey." + testDomain: key.txt}
}

// message is an unsigned message, assembled header by header so a test
// can change exactly one thing.
type message struct {
	headers [][2]string
	body    string
}

func baseMessage(now time.Time) message {
	return message{
		headers: [][2]string{
			{"From", "Birdcage Admin <" + testPinned + ">"},
			{"To", "birdcage@example.net"},
			{"Subject", "Re: [birdcage " + testReference + "] upgrade mockingbird to v0.4.0"},
			{"Date", now.Format(time.RFC1123Z)},
			{"Message-ID", "<reply-0001@example.net>"},
		},
		body: testBody,
	}
}

func (m message) set(name, value string) message {
	out := m
	out.headers = append([][2]string(nil), m.headers...)
	for i := range out.headers {
		if strings.EqualFold(out.headers[i][0], name) {
			out.headers[i][1] = value
			return out
		}
	}
	out.headers = append(out.headers, [2]string{name, value})
	return out
}

func (m message) add(name, value string) message {
	out := m
	out.headers = append(append([][2]string(nil), m.headers...), [2]string{name, value})
	return out
}

func (m message) raw() []byte {
	var b bytes.Buffer
	for _, h := range m.headers {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	b.WriteString("\r\n")
	b.WriteString(m.body)
	return b.Bytes()
}

// sign signs m with key and returns the whole signed message. headerKeys
// is the h= list; nil means the four this package requires plus To.
func sign(t *testing.T, m message, key testKey, domain, selector string, headerKeys []string) []byte {
	t.Helper()
	if headerKeys == nil {
		headerKeys = []string{"From", "To", "Subject", "Date", "Message-ID"}
	}
	var out bytes.Buffer
	err := dkim.Sign(&out, bytes.NewReader(m.raw()), &dkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 key.signer,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             headerKeys,
	})
	if err != nil {
		t.Fatalf("dkim.Sign: %v", err)
	}
	return out.Bytes()
}

// rules is a Rules that passes, for a test to spoil one field of.
func rules(now time.Time, key testKey) Rules {
	return Rules{
		PinnedFrom: testPinned,
		Reference:  testReference,
		Now:        now,
		MaxAge:     24 * time.Hour,
		Resolver:   resolverFor(keyRecords(key)),
		Seen:       func(string) bool { return false },
	}
}

func fixedNow(t *testing.T) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, "2026-09-19T11:00:00Z")
	if err != nil {
		t.Fatalf("parse test time: %v", err)
	}
	return now
}

// mustReject runs Verify and requires it to fail, with a reason
// containing want -- the reason is what gets stored and printed, so a
// test that only checked "an error happened" would not notice it
// becoming useless.
func mustReject(t *testing.T, raw []byte, r Rules, want string) {
	t.Helper()
	_, err := Verify(context.Background(), raw, r)
	if err == nil {
		t.Fatalf("Verify accepted a message it should have rejected (expected a reason mentioning %q)", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Verify rejected for the wrong reason:\n got: %v\nwant it to mention: %q", err, want)
	}
}

// --- positives ---

func TestVerifyAcceptsRSASignedApproval(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now.Add(-10*time.Minute)), key, testDomain, testSelector, nil)

	got, err := Verify(context.Background(), raw, rules(now, key))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.From != testPinned {
		t.Errorf("From = %q, want %q", got.From, testPinned)
	}
	if got.MessageID != "<reply-0001@example.net>" {
		t.Errorf("MessageID = %q", got.MessageID)
	}
	if got.Domain != testDomain || got.Selector != testSelector {
		t.Errorf("signature identified as %s/%s, want %s/%s", got.Selector, got.Domain, testSelector, testDomain)
	}
	if !strings.HasPrefix(got.Subject, "Re: ") {
		t.Errorf("Subject = %q, want the Re: prefix preserved", got.Subject)
	}
	if got.Date.IsZero() {
		t.Error("Date is zero")
	}
}

func TestVerifyAcceptsEd25519SignedApproval(t *testing.T) {
	now := fixedNow(t)
	key := ed25519TestKey(t)
	raw := sign(t, baseMessage(now.Add(-time.Minute)), key, testDomain, testSelector, nil)

	if _, err := Verify(context.Background(), raw, rules(now, key)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// The reply prefix is whatever the admin's mail client puts there, so
// the subject rule is "contains", not "equals".
func TestVerifyAcceptsAnyReplyPrefix(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	for _, prefix := range []string{"", "Re: ", "AW: ", "SV: ", "Re: Re: Fwd: "} {
		m := baseMessage(now).set("Subject", prefix+"[birdcage "+testReference+"] upgrade")
		raw := sign(t, m, key, testDomain, testSelector, nil)
		if _, err := Verify(context.Background(), raw, rules(now, key)); err != nil {
			t.Errorf("Verify with subject prefix %q: %v", prefix, err)
		}
	}
}

// A message whose line endings were flattened to bare LF somewhere on
// its way to a file still verifies: bare LF is not a valid message, so
// promoting it back to CRLF cannot change a message that was valid.
func TestVerifyAcceptsMessageWithBareLineFeeds(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)
	flattened := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))

	if _, err := Verify(context.Background(), flattened, rules(now, key)); err != nil {
		t.Fatalf("Verify on a bare-LF copy: %v", err)
	}
}

// The domain comparison is case-insensitive; the local part is not.
func TestVerifyDomainCaseIsIgnoredAndLocalPartCaseIsNot(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)

	m := baseMessage(now).set("From", "admin@EXAMPLE.NET")
	raw := sign(t, m, key, testDomain, testSelector, nil)
	if _, err := Verify(context.Background(), raw, rules(now, key)); err != nil {
		t.Errorf("Verify rejected an upper-case domain: %v", err)
	}

	m = baseMessage(now).set("From", "Admin@example.net")
	raw = sign(t, m, key, testDomain, testSelector, nil)
	mustReject(t, raw, rules(now, key), "approvals are only accepted from")
}

// --- one negative per rule ---

func TestVerifyRejectsOversizedMessage(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := make([]byte, MaxRawSize+1)
	if _, err := Verify(context.Background(), raw, rules(now, key)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Verify on an oversized message returned %v, want ErrTooLarge", err)
	}
}

func TestVerifyRejectsTwoFromHeaders(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	m := baseMessage(now).add("From", "attacker@example.org")
	raw := sign(t, m, key, testDomain, testSelector, nil)
	mustReject(t, raw, rules(now, key), "2 From headers")
}

func TestVerifyRejectsAnotherSender(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	m := baseMessage(now).set("From", "someone-else@example.net")
	raw := sign(t, m, key, testDomain, testSelector, nil)
	mustReject(t, raw, rules(now, key), "approvals are only accepted from")
}

func TestVerifyRejectsSubjectWithoutTheReference(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)

	m := baseMessage(now).set("Subject", "Re: upgrade mockingbird")
	raw := sign(t, m, key, testDomain, testSelector, nil)
	mustReject(t, raw, rules(now, key), "does not contain [birdcage "+testReference+"]")

	// A different request's reference is not this request's approval.
	m = baseMessage(now).set("Subject", "Re: [birdcage some-other-request] upgrade")
	raw = sign(t, m, key, testDomain, testSelector, nil)
	mustReject(t, raw, rules(now, key), "does not contain [birdcage "+testReference+"]")
}

func TestVerifyRejectsStaleAndFutureDates(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)

	stale := sign(t, baseMessage(now.Add(-48*time.Hour)), key, testDomain, testSelector, nil)
	mustReject(t, stale, rules(now, key), "the limit is 24h0m0s in either direction")

	future := sign(t, baseMessage(now.Add(48*time.Hour)), key, testDomain, testSelector, nil)
	mustReject(t, future, rules(now, key), "the limit is 24h0m0s in either direction")
}

func TestVerifyRejectsAReplayedMessageID(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)

	r := rules(now, key)
	var asked []string
	r.Seen = func(id string) bool {
		asked = append(asked, id)
		return true
	}
	mustReject(t, raw, r, "has already been accepted")
	if len(asked) != 1 || asked[0] != "<reply-0001@example.net>" {
		t.Errorf("Seen was asked about %v, want the message's own Message-ID once", asked)
	}
}

func TestVerifyRejectsMissingMessageID(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	m := baseMessage(now)
	m.headers = m.headers[:len(m.headers)-1] // drop Message-ID
	raw := sign(t, m, key, testDomain, testSelector, []string{"From", "To", "Subject", "Date"})
	mustReject(t, raw, rules(now, key), "0 Message-ID headers")
}

// l= says "only the first N bytes of the body are signed", which lets
// anyone append anything below the signed part. It is refused before
// the signature is even checked.
func TestVerifyRejectsBodyLengthTag(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)
	withL := bytes.Replace(raw, []byte("DKIM-Signature: "), []byte("DKIM-Signature: l=10; "), 1)
	if bytes.Equal(raw, withL) {
		t.Fatal("test setup: the l= tag was not injected")
	}
	mustReject(t, withL, rules(now, key), "covers only part of the body (l=)")
}

func TestVerifyRejectsAnUnsignedMessage(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	mustReject(t, baseMessage(now).raw(), rules(now, key), "carries no DKIM signature")
}

// Anyone can sign a message with their own domain's key. The signature
// has to be the pinned address's domain or it proves nothing about the
// admin.
func TestVerifyRejectsASignatureFromAnotherDomain(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, "example.org", testSelector, nil)

	r := rules(now, key)
	r.Resolver = resolverFor(map[string]string{testSelector + "._domainkey.example.org": key.txt})
	mustReject(t, raw, r, "no DKIM signature was made by example.net")
}

// A parent-domain signature is refused too -- see this package's doc
// comment for why the registrable-parent rule is not implemented.
func TestVerifyRejectsAParentDomainSignature(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	m := baseMessage(now).set("From", "admin@mail.example.net")
	raw := sign(t, m, key, "example.net", testSelector, nil)

	r := rules(now, key)
	r.PinnedFrom = "admin@mail.example.net"
	mustReject(t, raw, r, "no DKIM signature was made by mail.example.net")
}

func TestVerifyRejectsTwoSignaturesFromThePinnedDomain(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	once := sign(t, baseMessage(now), key, testDomain, testSelector, nil)

	// Signing the signed message again gives it a second
	// DKIM-Signature header from the same domain.
	var twice bytes.Buffer
	if err := dkim.Sign(&twice, bytes.NewReader(once), &dkim.SignOptions{
		Domain: testDomain, Selector: testSelector, Signer: key.signer, Hash: crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             []string{"From", "To", "Subject", "Date", "Message-ID"},
	}); err != nil {
		t.Fatalf("second dkim.Sign: %v", err)
	}
	mustReject(t, twice.Bytes(), rules(now, key), "carries 2 DKIM signatures from example.net")
}

// Every one of the four headers the rules above depend on has to be
// inside h=, or the rule that reads it is checking something nobody
// signed.
func TestVerifyRejectsASignatureThatOmitsARequiredHeader(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	all := []string{"From", "To", "Subject", "Date", "Message-ID"}

	for _, omit := range []string{"Subject", "Date", "Message-ID"} {
		var keys []string
		for _, k := range all {
			if k != omit {
				keys = append(keys, k)
			}
		}
		raw := sign(t, baseMessage(now), key, testDomain, testSelector, keys)
		mustReject(t, raw, rules(now, key), "does not cover "+strings.ToLower(omit))
	}
}

func TestVerifyRejectsATamperedBody(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)
	tampered := bytes.Replace(raw, []byte("Yes, go ahead."), []byte("Yes, go ahead!"), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("test setup: the body was not changed")
	}
	mustReject(t, tampered, rules(now, key), "is not valid")
}

func TestVerifyRejectsATamperedSignedHeader(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)
	// Change the To header, which is inside h=, without resigning.
	tampered := bytes.Replace(raw, []byte("To: birdcage@example.net"), []byte("To: birdcage@example.org"), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("test setup: the To header was not changed")
	}
	mustReject(t, tampered, rules(now, key), "is not valid")
}

// The key is published in DNS, so a revoked or missing record is a
// rejection rather than a pass.
func TestVerifyRejectsWhenTheKeyIsNotPublished(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)

	r := rules(now, key)
	r.Resolver = resolverFor(nil)
	mustReject(t, raw, r, "is not valid")
}

// --- the caller's own mistakes ---

func TestVerifyRefusesIncompleteRules(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)

	cases := map[string]func(*Rules){
		"no administrator address is pinned": func(r *Rules) { r.PinnedFrom = "" },
		"is not a valid address":             func(r *Rules) { r.PinnedFrom = "not an address" },
		"no request reference":               func(r *Rules) { r.Reference = "" },
		"contains a bracket":                 func(r *Rules) { r.Reference = "ref]injected" },
		"Rules.Now is zero":                  func(r *Rules) { r.Now = time.Time{} },
		"Rules.MaxAge must be positive":      func(r *Rules) { r.MaxAge = 0 },
		"Rules.Resolver is nil":              func(r *Rules) { r.Resolver = nil },
		"Rules.Seen is nil":                  func(r *Rules) { r.Seen = nil },
	}
	for want, spoil := range cases {
		r := rules(now, key)
		spoil(&r)
		mustReject(t, raw, r, want)
	}
}

func TestVerifyHonoursACancelledContext(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Verify(ctx, raw, rules(now, key)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify with a cancelled context returned %v, want context.Canceled", err)
	}
}

// --- helpers ---

func TestSubjectReference(t *testing.T) {
	cases := map[string]string{
		"Re: [birdcage u-1] upgrade":        "u-1",
		"[birdcage u-2]":                    "u-2",
		"AW: Fwd: [birdcage u-3] x":         "u-3",
		"no reference here":                 "",
		"[birdcage ] empty":                 "",
		"[birdcage u-4] and [birdcage u-5]": "u-4",
	}
	for subject, want := range cases {
		if got := SubjectReference(subject); got != want {
			t.Errorf("SubjectReference(%q) = %q, want %q", subject, got, want)
		}
	}
}

func TestTokenAndSubjectReferenceAgree(t *testing.T) {
	if got := SubjectReference("Re: " + Token("abc-123") + " hello"); got != "abc-123" {
		t.Errorf("SubjectReference of Token(\"abc-123\") = %q", got)
	}
}

// --- RFC 6376 Appendix A ---

// The RFC's own example message (A.2) and public key (A.3), byte for
// byte as published. Two things are checked with it, and nothing in it
// is edited to make either pass.
//
// First, that the library verifies the published signature unchanged --
// a sanity check on the dependency, with a signature nobody here made.
//
// Second, that this package's domain rule refuses it. The example is a
// subdomain case: the message is from joe@football.example.com and is
// signed with d=example.com. Under the exact-match rule (see the
// package comment) that is a refusal, and this test pins that choice so
// changing it has to be deliberate.
const rfc6376AppendixAMessage = `DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
      c=simple/simple; q=dns/txt; i=joe@football.example.com;
      h=Received : From : To : Subject : Date : Message-ID;
      bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
      b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
      4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
      KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
      4bmp/YzhwvcubU4=;
Received: from client1.football.example.com  [192.0.2.1]
      by submitserver.example.com with SUBMISSION;
      Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game. Are you hungry yet?

Joe.
`

const rfc6376AppendixAKey = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ" +
	"KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt" +
	"IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v" +
	"/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi" +
	"tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB"

func TestRFC6376AppendixAExample(t *testing.T) {
	raw := normalizeLineEndings([]byte(rfc6376AppendixAMessage))
	resolver := resolverFor(map[string]string{"brisbane._domainkey.example.com": rfc6376AppendixAKey})

	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{LookupTXT: resolver})
	if err != nil {
		t.Fatalf("dkim.VerifyWithOptions on the RFC 6376 example: %v", err)
	}
	if len(verifications) != 1 {
		t.Fatalf("got %d verifications for the RFC 6376 example, want 1", len(verifications))
	}
	if verifications[0].Err != nil {
		t.Fatalf("the RFC 6376 example's own signature did not verify: %v", verifications[0].Err)
	}

	// The signing domain is accepted when it is asked for by name.
	selector, domain, err := verifySignature(context.Background(), raw, "example.com", resolver)
	if err != nil {
		t.Fatalf("verifySignature for example.com: %v", err)
	}
	if selector != "brisbane" || domain != "example.com" {
		t.Errorf("accepted signature is %s/%s, want brisbane/example.com", selector, domain)
	}

	// The From address's own domain is a subdomain of it, and that is
	// refused: this package does not accept a parent-domain signature.
	if _, _, err := verifySignature(context.Background(), raw, "football.example.com", resolver); err == nil {
		t.Error("verifySignature accepted a parent-domain signature for football.example.com")
	}
}

// A signature covers the bottom-most instance of each header it names
// (RFC 6376 section 5.4.2), but net/mail's Get returns the top-most. So
// anything holding a validly signed message -- birdcage itself, which
// couriers the raw bytes, is the threat ADR-0007 is written against --
// can prepend a second Subject or Date and leave the signature intact.
// The signature still verifies; the agent reads the injected value.
//
// For Subject that rewrites which request was approved, which is the
// whole binding between an admin's reply and one action. For Date it
// makes an approval from any time in the past look fresh.
func prepend(raw []byte, line string) []byte {
	return append([]byte(line+"\r\n"), raw...)
}

func TestVerifyRejectsAnInjectedSubject(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)

	// Signed for testReference; presented as approving another request.
	attacked := prepend(raw, "Subject: Re: [birdcage some-other-request] upgrade")

	r := rules(now, key)
	r.Reference = "some-other-request"
	mustReject(t, attacked, r, "Subject headers")
}

func TestVerifyRejectsAnInjectedDate(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	old := now.Add(-365 * 24 * time.Hour)
	raw := sign(t, baseMessage(old), key, testDomain, testSelector, nil)

	// A year-old approval, dressed up as one sent a moment ago.
	attacked := prepend(raw, "Date: "+now.Format(time.RFC1123Z))

	mustReject(t, attacked, rules(now, key), "Date headers")
}

// Owner decision 25 (2026-09-19): the signing domain is pinned from
// what the administrator's provider actually signs with, learned from
// the setup test approval, rather than derived from the address. A
// provider handling mail for you@mail.example.net commonly signs as
// example.net, and working out whether one domain legitimately covers
// another needs the Public Suffix List.
func TestVerifyAcceptsThePinnedSigningDomain(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)

	const subdomain = "mail." + testDomain
	m := baseMessage(now).set("From", "Birdcage Admin <admin@"+subdomain+">")
	raw := sign(t, m, key, testDomain, testSelector, nil)

	r := rules(now, key)
	r.PinnedFrom = "admin@" + subdomain

	// Unpinned, the address's own domain is required, and this is not it.
	mustReject(t, raw, r, "no DKIM signature was made by "+subdomain)

	// Pinned to what the provider actually signs with, it verifies.
	r.PinnedSigningDomain = testDomain
	got, err := Verify(context.Background(), raw, r)
	if err != nil {
		t.Fatalf("Verify with the pinned signing domain: %v", err)
	}
	if got.Domain != testDomain {
		t.Errorf("Domain = %q, want %q", got.Domain, testDomain)
	}
}

func TestVerifyRejectsASignatureFromAnotherPinnedDomain(t *testing.T) {
	now := fixedNow(t)
	key := rsaTestKey(t)
	raw := sign(t, baseMessage(now), key, testDomain, testSelector, nil)

	r := rules(now, key)
	r.PinnedSigningDomain = "somewhere-else.example"
	mustReject(t, raw, r, "no DKIM signature was made by somewhere-else.example")
}
