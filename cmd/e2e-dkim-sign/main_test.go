package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const testMsg = "From: e2e-admin@e2e.invalid\n" +
	"To: e2e-admin@e2e.invalid\n" +
	"Subject: [birdcage e2e-ref] Re: approve\n" +
	"Date: Fri, 25 Sep 2026 12:00:00 +0000\n" +
	"Message-ID: <unit@e2e.invalid>\n" +
	"\n" +
	"approved  \n\n\n"

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The hand-built signer is only trusted with l= because go-msgauth
// accepts what it builds without l=. This pins that.
func TestHandSignVerifiesWithGoMsgauth(t *testing.T) {
	k := testKey(t)
	signed := mustHandSign(crlf([]byte(testMsg)), k, "e2e.invalid", "e2e", false)
	if err := selfCheck(signed, &k.PublicKey, "e2e.invalid", "e2e"); err != nil {
		t.Fatalf("hand-built signature does not verify: %v", err)
	}
	// And a folded, re-spaced header block still verifies (relaxed).
	folded := strings.Replace(testMsg, "Subject: [birdcage e2e-ref] Re: approve", "Subject:  [birdcage e2e-ref]\n\t Re:   approve", 1)
	signed = mustHandSign(crlf([]byte(folded)), k, "e2e.invalid", "e2e", false)
	if err := selfCheck(signed, &k.PublicKey, "e2e.invalid", "e2e"); err != nil {
		t.Fatalf("hand-built signature over a folded header does not verify: %v", err)
	}
}

func TestVariants(t *testing.T) {
	k := testKey(t)
	msg := crlf([]byte(testMsg))
	for _, tc := range []struct {
		variant  string
		verifies bool
		check    func(t *testing.T, out string)
	}{
		{"good", true, nil},
		{"body", false, func(t *testing.T, out string) {
			if !strings.Contains(out, "added after signing") {
				t.Error("body not altered")
			}
		}},
		{"drop-header", false, func(t *testing.T, out string) {
			if strings.Contains(out, "\r\nTo:") {
				t.Error("To still present")
			}
		}},
		{"length", false, func(t *testing.T, out string) {
			if !regexp.MustCompile(`l=\d+;`).MatchString(out) {
				t.Error("no l= tag")
			}
		}},
		{"second-subject", true, func(t *testing.T, out string) {
			if strings.Count(out, "\r\nSubject:") != 1 || !strings.HasPrefix(out, "Subject:") {
				t.Error("second Subject not prepended")
			}
		}},
		{"wrong-key", false, nil},
	} {
		t.Run(tc.variant, func(t *testing.T) {
			out, err := signVariant(msg, k, "e2e.invalid", "e2e", tc.variant)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(bytes.ReplaceAll(out, []byte("\r\n"), nil), []byte("\n")) {
				t.Error("output has a bare LF")
			}
			// go-msgauth refuses l= itself, so "length" fails here for
			// that reason; the others fail (or not) on the signature.
			err = selfCheck(out, &k.PublicKey, "e2e.invalid", "e2e")
			if (err == nil) != tc.verifies {
				t.Errorf("verifies against the published key = %v, want %v (err %v)", err == nil, tc.verifies, err)
			}
			if tc.check != nil {
				tc.check(t, string(out))
			}
		})
	}
}

func TestKeygenAndSignCommands(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.pem")
	rec := filepath.Join(dir, "dkim.conf")
	if err := run([]string{"keygen", "-key", key, "-record", rec, "-domain", "e2e.invalid", "-selector", "e2e"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", fi, err)
	}
	line, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^local-data: 'e2e\._domainkey\.e2e\.invalid\. 60 IN TXT ("[^"]{1,200}" ?)+'\n$`).Match(line) {
		t.Fatalf("record line malformed: %s", line)
	}
	var out bytes.Buffer
	if err := run([]string{"sign", "-key", key, "-domain", "e2e.invalid", "-selector", "e2e"}, strings.NewReader(testMsg), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "DKIM-Signature:") {
		t.Fatalf("not signed: %q", out.String()[:40])
	}
	for _, bad := range [][]string{nil, {"nope"}, {"sign", "-key", key, "-domain", "d", "-selector", "s", "-variant", "nope"}, {"keygen"}} {
		if err := run(bad, strings.NewReader(testMsg), &out); err == nil {
			t.Errorf("run(%q) succeeded", bad)
		}
	}
}
