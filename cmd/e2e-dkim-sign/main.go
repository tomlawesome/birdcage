// Command e2e-dkim-sign plays the administrator's mail provider in issue
// #80's live mail journey: it holds a DKIM key made for the run, hands
// the public half to the test DNS server (build/e2e-dns) to publish, and
// signs the approval replies scripts/e2e/mail.sh puts in the mailbox --
// one correctly, the rest broken in the ways #80 names so that birdcage
// has to refuse them.
//
// Test-only. It is built into build/e2e-dns's image by
// scripts/e2e/mail-stack.sh and never ships. It deliberately does not
// import internal/agent/approval: the thing under test must not also be
// the thing that decides what a good signature looks like. The signing is
// github.com/emersion/go-msgauth/dkim's, as a real provider's would be
// someone else's code.
//
//	e2e-dkim-sign keygen -key /dkim/key.pem -record /dns/dkim.conf \
//	  -domain e2e.invalid -selector e2e
//	e2e-dkim-sign sign -key /dkim/key.pem -domain e2e.invalid \
//	  -selector e2e -variant good < reply.eml > signed.eml
//
// keygen makes a fresh 2048-bit RSA key -- never a committed one -- and
// writes the private half as PKCS#8 PEM, readable by its owner only, and
// the public half as the unbound local-data line that publishes it at
// <selector>._domainkey.<domain>.
//
// sign reads a message on stdin (bare LF or CRLF), signs it and writes
// it with CRLF line ends to stdout, as a message on the wire has. The
// variants are listed in the variants map below.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// signedKeys is the h= list every variant signs: the four headers
// birdcage requires inside the signature, and To, so that the
// drop-header variant can take away a header that is signed without
// tripping one of birdcage's own header-count rules first. What refuses
// that variant has to be the signature itself.
var signedKeys = []string{"From", "To", "Subject", "Date", "Message-ID"}

// variants maps each -variant to what it does after (or instead of) a
// plain signature. Each one is a mutation #80 asks to see refused, or a
// control proving the DNS lookup decides the answer.
var variants = map[string]string{
	"good":           "signed correctly: the one birdcage must accept",
	"body":           "the body altered after signing",
	"drop-header":    "a signed header (To) removed after signing",
	"length":         "signed with an l= body-length tag",
	"second-subject": "a second Subject prepended after signing",
	"wrong-key":      "signed with a key made on the spot and never published",
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "e2e-dkim-sign:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: e2e-dkim-sign {keygen|sign} [flags]")
	}
	switch args[0] {
	case "keygen":
		return runKeygen(args[1:])
	case "sign":
		return runSign(args[1:], stdin, stdout)
	default:
		return fmt.Errorf("unknown command %q; want keygen or sign", args[0])
	}
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	keyPath := fs.String("key", "", "where to write the private key (PEM)")
	recordPath := fs.String("record", "", "where to write the unbound local-data line")
	domain := fs.String("domain", "", "the signing domain (d=)")
	selector := fs.String("selector", "", "the selector (s=)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *recordPath == "" || *domain == "" || *selector == "" {
		return errors.New("keygen needs -key, -record, -domain and -selector")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(*keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *keyPath, err)
	}
	record, err := txtRecord(&key.PublicKey)
	if err != nil {
		return err
	}
	line := unboundLocalData(*selector+"._domainkey."+*domain+".", record)
	if err := os.WriteFile(*recordPath, []byte(line+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *recordPath, err)
	}
	return nil
}

// txtRecord is the DKIM key record (RFC 6376 section 3.6.1) for pub.
func txtRecord(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encode public key: %w", err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der), nil
}

// unboundLocalData is the unbound.conf line serving value as a TXT record
// for name. A TXT character-string holds at most 255 bytes and a 2048-bit
// key's record is longer, so it is split into several strings in one
// record; resolvers (Go's LookupTXT included) join them back up.
func unboundLocalData(name, value string) string {
	var parts []string
	for len(value) > 0 {
		n := min(200, len(value))
		parts = append(parts, `"`+value[:n]+`"`)
		value = value[n:]
	}
	return fmt.Sprintf("local-data: '%s 60 IN TXT %s'", name, strings.Join(parts, " "))
}

func runSign(args []string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "the private key written by keygen")
	domain := fs.String("domain", "", "the signing domain (d=)")
	selector := fs.String("selector", "", "the selector (s=)")
	variant := fs.String("variant", "good", "what to do to the message; one of: "+variantList())
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *domain == "" || *selector == "" {
		return errors.New("sign needs -key, -domain and -selector")
	}
	if _, ok := variants[*variant]; !ok {
		return fmt.Errorf("unknown variant %q; want one of %s", *variant, variantList())
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}
	out, err := signVariant(crlf(raw), key, *domain, *selector, *variant)
	if err != nil {
		return err
	}
	_, err = stdout.Write(out)
	return err
}

func variantList() string {
	return "good, body, drop-header, length, second-subject, wrong-key"
}

func readKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an RSA key", path)
	}
	return rk, nil
}

// signVariant signs msg and applies the variant. Before any mutation the
// untouched signed message is verified with go-msgauth against key's own
// public half, so a refusal seen later in the journey is the mutation's
// doing (or DNS's), never a signature that was broken to begin with.
func signVariant(msg []byte, key *rsa.PrivateKey, domain, selector, variant string) ([]byte, error) {
	switch variant {
	case "length":
		// go-msgauth will not sign with l= (and its verifier refuses
		// one), so this signature is built by hand. l= is the length of
		// the whole canonical body, so the signature covers exactly what
		// a plain one would -- a well-formed, valid signature whose only
		// fault is carrying the tag.
		if err := selfCheck(mustHandSign(msg, key, domain, selector, false), &key.PublicKey, domain, selector); err != nil {
			return nil, fmt.Errorf("the hand-built signature does not verify without l=, so an l= refusal would prove nothing: %w", err)
		}
		return mustHandSign(msg, key, domain, selector, true), nil
	case "wrong-key":
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate the unpublished key: %w", err)
		}
		key = other
	}

	signed, err := sign(msg, key, domain, selector)
	if err != nil {
		return nil, err
	}
	if err := selfCheck(signed, &key.PublicKey, domain, selector); err != nil {
		return nil, fmt.Errorf("the freshly signed message does not verify against its own key: %w", err)
	}

	switch variant {
	case "body":
		head, body := split(signed)
		return append(head, append([]byte("approved -- and also this line, added after signing\r\n"), body...)...), nil
	case "drop-header":
		return dropHeader(signed, "To")
	case "second-subject":
		return append([]byte("Subject: [birdcage e2e-other] Re: approve something else\r\n"), signed...), nil
	}
	return signed, nil
}

func sign(msg []byte, key *rsa.PrivateKey, domain, selector string) ([]byte, error) {
	var sig bytes.Buffer
	err := dkim.Sign(&sig, bytes.NewReader(msg), &dkim.SignOptions{
		Domain:                 domain,
		Selector:               selector,
		Signer:                 key,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             signedKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return sig.Bytes(), nil
}

// selfCheck verifies signed with go-msgauth, looking the key up in a map
// holding only pub rather than in DNS.
func selfCheck(signed []byte, pub *rsa.PublicKey, domain, selector string) error {
	record, err := txtRecord(pub)
	if err != nil {
		return err
	}
	name := selector + "._domainkey." + domain
	vs, err := dkim.VerifyWithOptions(bytes.NewReader(signed), &dkim.VerifyOptions{
		LookupTXT: func(q string) ([]string, error) {
			if q != name {
				return nil, fmt.Errorf("no record for %s", q)
			}
			return []string{record}, nil
		},
	})
	if err != nil {
		return err
	}
	if len(vs) != 1 {
		return fmt.Errorf("%d signatures, want 1", len(vs))
	}
	return vs[0].Err
}

// mustHandSign builds a relaxed/relaxed rsa-sha256 DKIM-Signature by hand
// (RFC 6376 sections 3.4, 3.5 and 3.7), with l= when withLength is set,
// and returns the signed message. It exists only because go-msgauth has
// no way to put l= in a signature; signVariant proves it right by having
// go-msgauth verify its output without l= before trusting it with l=.
func mustHandSign(msg []byte, key *rsa.PrivateKey, domain, selector string, withLength bool) []byte {
	head, body := split(msg)
	canonBody := relaxedBody(body)
	bh := sha256.Sum256(canonBody)

	tags := "v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + domain + "; s=" + selector + ";\r\n" +
		" h=" + strings.Join(lower(signedKeys), ":") + ";"
	if withLength {
		tags += fmt.Sprintf(" l=%d;", len(canonBody))
	}
	tags += "\r\n bh=" + base64.StdEncoding.EncodeToString(bh[:]) + ";\r\n b="

	h := sha256.New()
	fields := headerFields(head)
	used := map[int]bool{}
	for _, name := range signedKeys {
		// The bottom-most instance not already used (RFC 6376 5.4.2).
		for i := len(fields) - 1; i >= 0; i-- {
			if used[i] || !strings.EqualFold(fieldName(fields[i]), name) {
				continue
			}
			used[i] = true
			h.Write([]byte(relaxedHeader(fields[i]) + "\r\n"))
			break
		}
	}
	sigField := "DKIM-Signature: " + tags
	h.Write([]byte(relaxedHeader(sigField)))
	b, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h.Sum(nil))
	if err != nil {
		panic(err) // a 2048-bit key and a SHA-256 digest cannot fail here
	}
	out := []byte(sigField + base64.StdEncoding.EncodeToString(b) + "\r\n")
	return append(out, msg...)
}

var wsp = regexp.MustCompile(`[ \t]+`)

// relaxedHeader is RFC 6376 section 3.4.2 for one whole field, folded
// lines included.
func relaxedHeader(field string) string {
	name, value, _ := strings.Cut(field, ":")
	value = strings.ReplaceAll(value, "\r\n", "")
	value = strings.TrimSpace(wsp.ReplaceAllString(value, " "))
	return strings.ToLower(strings.TrimRight(name, " \t")) + ":" + value
}

// relaxedBody is RFC 6376 section 3.4.4.
func relaxedBody(body []byte) []byte {
	lines := strings.Split(string(body), "\r\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(wsp.ReplaceAllString(l, " "), " ")
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

// headerFields splits a CRLF header block into whole fields, keeping a
// folded field's continuation lines with it.
func headerFields(head []byte) []string {
	var fields []string
	for _, line := range strings.Split(strings.TrimSuffix(string(head), "\r\n\r\n"), "\r\n") {
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(fields) > 0 {
			fields[len(fields)-1] += "\r\n" + line
			continue
		}
		fields = append(fields, line)
	}
	return fields
}

func fieldName(field string) string {
	name, _, _ := strings.Cut(field, ":")
	return strings.TrimSpace(name)
}

func lower(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}

// dropHeader removes every instance of the named field from the header.
func dropHeader(msg []byte, name string) ([]byte, error) {
	head, body := split(msg)
	var kept []string
	dropped := false
	for _, f := range headerFields(head) {
		if strings.EqualFold(fieldName(f), name) {
			dropped = true
			continue
		}
		kept = append(kept, f)
	}
	if !dropped {
		return nil, fmt.Errorf("the message has no %s header to drop", name)
	}
	return append([]byte(strings.Join(kept, "\r\n")+"\r\n\r\n"), body...), nil
}

// split returns the header block (ending in the blank line) and the body.
func split(msg []byte) (head, body []byte) {
	i := bytes.Index(msg, []byte("\r\n\r\n"))
	if i < 0 {
		return msg, nil
	}
	return msg[: i+4 : i+4], msg[i+4:]
}

// crlf promotes bare LF line ends to CRLF, leaving existing CRLF alone.
func crlf(b []byte) []byte {
	return bytes.ReplaceAll(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
}
