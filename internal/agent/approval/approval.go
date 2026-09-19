// Package approval is the check ADR-0007 puts in every agent's hands:
// given the raw bytes of an email, decide whether it really is the
// pinned administrator approving one named request.
//
// It lives under internal/agent because the agent is the party that has
// to be convinced. Birdcage reads the mailbox and carries the bytes
// (internal/mailbox), and birdcage may run this same check for its own
// records -- but a birdcage that has been taken over gains nothing by
// lying about the result, because each agent runs Verify itself on the
// bytes it was handed. That is the whole point of the design: birdcage
// is a courier, not an authority. The agent-dependency fence
// (scripts/agent-deps-check.sh) allows internal/agent/* into the
// Mockingbird image for exactly this reason.
//
// What is checked, and why each one is here rather than assumed:
//
//   - The message is small. A mailbox is attacker-reachable input, and
//     an approval is a few kilobytes of text; MaxRawSize refuses
//     anything larger before a parser sees a byte of it.
//   - Exactly one DKIM signature is valid and was made by the domain of
//     the pinned From address. Not "at least one": a message can carry
//     several signatures, and accepting any one of them would let a
//     relay that signs everything it touches approve an upgrade.
//   - No signature carries l= (body length). l= says "only the first N
//     bytes of the body are signed", which lets anyone append whatever
//     they like below the signed part and keep the signature valid. A
//     legitimate approval has no use for it.
//   - From, Subject, Date and Message-ID are all inside the signature's
//     h= list. A signature that does not cover Date does not stop a
//     replay; one that does not cover Subject does not tie the approval
//     to a request. Each of those four is load-bearing below, so each
//     must be signed.
//   - From appears exactly once. Two From headers are a classic
//     signature-scope trick: the signature covers one of them and the
//     reader shows the other.
//   - From equals the pinned address -- exact on the local part (local
//     parts are case-sensitive per RFC 5321), case-insensitive on the
//     domain (domains are not).
//   - The subject contains the reference token "[birdcage <ref>]".
//     Contains, not equals: every mail client in the world prefixes a
//     reply with Re:, AW: or SV:, and the approval is a reply.
//   - The Date is within MaxAge of Now in either direction. Both
//     directions: a message from the future is as suspect as a stale
//     one, and clock skew is a reason to allow a margin, not a reason
//     to allow one side without bound.
//   - The Message-ID has not been seen before (the Seen hook). Date
//     alone would let the same approval be replayed for its whole
//     window.
//
// # The domain rule
//
// A signature is accepted only when its d= is exactly the domain of the
// pinned From address, compared case-insensitively. A signature from a
// parent domain -- d=example.com on a From of admin@mail.example.com --
// is refused.
//
// That is stricter than the usual DKIM advice, and it is a deliberate
// choice rather than an oversight. Accepting "the registrable parent"
// means knowing where the registrable part of a name ends, and the only
// way to know that is a public-suffix list. A public-suffix list is a
// lookup dataset that goes stale, which this project does not vendor,
// and hand-rolling the rule ("the last two labels") would accept
// d=co.uk as a parent of anything.example.co.uk -- a rule that lets any
// customer of the same registry approve anybody's upgrade. Refusing a
// legitimate parent-domain signature costs an operator a pinned address
// that matches what their provider signs with; getting the parent rule
// wrong costs the whole control. The RFC 6376 Appendix A example is
// itself a subdomain case (d=example.com, From joe@football.example.com)
// and is refused here for exactly this reason -- see
// TestRFC6376AppendixAExample.
package approval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	netmail "net/mail"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// MaxRawSize is the largest message Verify will look at: 1 MiB, checked
// before anything parses. An approval is a short reply; anything near
// this size is either a mistake or someone probing what the parser will
// do with a large input.
const MaxRawSize = 1 << 20

// maxSignatures bounds how many DKIM signatures are verified, so a
// message carrying a thousand of them cannot turn one poll into a
// thousand public-key operations and a thousand DNS lookups. A real
// message has one or two.
const maxSignatures = 8

// signedHeaders is the set of header fields the accepted signature must
// cover. Each one is used by a rule below, so a signature that leaves
// any of them out leaves that rule unenforceable.
var signedHeaders = []string{"from", "subject", "date", "message-id"}

// Rules is everything Verify needs from its caller. Nothing here has a
// default: a missing Resolver is an error rather than a silent fall
// back to net.LookupTXT, and a missing Seen is an error rather than a
// silently skipped replay check. Both would be the kind of default that
// looks like it is working right up until it matters.
type Rules struct {
	// PinnedFrom is the administrator's address, as pinned on the agent
	// at enrolment (issue #47) -- the settings row
	// admin_approval_address.
	PinnedFrom string
	// Reference is the request reference the subject must carry, as the
	// token "[birdcage <ref>]".
	Reference string
	// Now is the instant Date is measured against. Passed in rather
	// than read from the clock so a test, and the CLI's --at, decide it.
	Now time.Time
	// MaxAge is how far from Now the Date may be, in either direction.
	MaxAge time.Duration
	// Resolver looks up DNS TXT records for a name -- the same shape as
	// net.LookupTXT and as dkim.VerifyOptions.LookupTXT, which is what
	// it is handed to. It is injected so tests never touch DNS and so
	// this package never opens a network connection of its own choosing.
	Resolver func(domain string) ([]string, error)
	// Seen reports whether this Message-ID has been accepted before. It
	// is the replay check; returning true rejects the message.
	Seen func(messageID string) bool
}

// Approval is what a message that passed every rule turns out to be.
// Domain and Selector identify the DKIM key that signed it, which is
// what an operator needs to see when they are working out why their
// provider's signature did or did not pass.
type Approval struct {
	From      string
	MessageID string
	Subject   string
	Date      time.Time
	Domain    string
	Selector  string
}

// ErrTooLarge is returned for a message over MaxRawSize, before
// anything parses it.
var ErrTooLarge = errors.New("approval: the message is larger than 1 MiB; refusing to parse it")

// Verify runs every rule in this package's doc comment against raw and
// returns what the message turns out to be, or the first rule it broke.
//
// The error is written to be stored and shown: it is what
// internal/store records as an approval's reject_reason and what
// `birdcage approval check` prints, so it names the rule in plain words
// rather than in tag letters.
//
// Order is deliberate: the cheap structural checks run before the
// signature check, so a message that was never going to be an approval
// costs no public-key operation and no DNS lookup, and the reported
// reason is the most useful one rather than whichever happened to fail
// first.
func Verify(ctx context.Context, raw []byte, rules Rules) (Approval, error) {
	if err := ctx.Err(); err != nil {
		return Approval{}, err
	}
	if len(raw) > MaxRawSize {
		return Approval{}, ErrTooLarge
	}
	pinned, err := rules.validate()
	if err != nil {
		return Approval{}, err
	}

	// RFC 5322 line endings are CRLF, and DKIM's canonicalization is
	// defined on them. IMAP hands over CRLF already; a message saved to
	// a file by hand may have had its line endings mangled to bare LF
	// somewhere along the way, which would fail the body hash for a
	// reason that has nothing to do with the signature. A bare LF is
	// not a valid message anyway, so promoting it to CRLF cannot change
	// the meaning of a message that was valid to begin with.
	raw = normalizeLineEndings(raw)

	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return Approval{}, fmt.Errorf("approval: the message could not be parsed as an email: %w", err)
	}

	// Two From headers are a signature-scope trick, not a formatting
	// quirk: the signature covers one and the reader is shown the
	// other. Checked before the address is parsed, since net/mail's Get
	// would silently return only the first.
	if n := len(msg.Header["From"]); n != 1 {
		return Approval{}, fmt.Errorf("approval: the message has %d From headers; exactly one is allowed", n)
	}
	from, err := netmail.ParseAddress(msg.Header.Get("From"))
	if err != nil {
		return Approval{}, fmt.Errorf("approval: the From header is not a valid address (%q): %w", msg.Header.Get("From"), err)
	}
	if !sameAddress(from.Address, pinned.Address) {
		return Approval{}, fmt.Errorf("approval: the message is from %s, but approvals are only accepted from %s", from.Address, pinned.Address)
	}

	// Subject and Date get the same count check as From, and for the
	// same reason: a signature covers the bottom-most instance of a
	// header it names (RFC 6376 section 5.4.2) while net/mail's Get
	// returns the top-most. Anything holding a validly signed message
	// can prepend a second one, leaving the signature intact and
	// showing the reader a value nobody signed. Birdcage carries these
	// bytes, and ADR-0007 is written on the assumption birdcage is
	// hacked -- so for Subject that would rewrite which request was
	// approved, and for Date it would make an approval from any time in
	// the past look fresh.
	if n := len(msg.Header["Subject"]); n != 1 {
		return Approval{}, fmt.Errorf("approval: the message has %d Subject headers; exactly one is allowed", n)
	}
	subject := msg.Header.Get("Subject")
	token := Token(rules.Reference)
	if !subjectCarries(subject, token) {
		return Approval{}, fmt.Errorf("approval: the subject does not contain %s (it is %q)", token, subject)
	}

	if n := len(msg.Header["Date"]); n != 1 {
		return Approval{}, fmt.Errorf("approval: the message has %d Date headers; exactly one is allowed", n)
	}
	date, err := msg.Header.Date()
	if err != nil {
		return Approval{}, fmt.Errorf("approval: the Date header could not be read: %w", err)
	}
	if skew := rules.Now.Sub(date); skew > rules.MaxAge || skew < -rules.MaxAge {
		return Approval{}, fmt.Errorf("approval: the message is dated %s, which is %s away from now; the limit is %s in either direction",
			date.UTC().Format(time.RFC3339), absDuration(skew).Round(time.Second), rules.MaxAge)
	}

	if n := len(msg.Header["Message-Id"]); n != 1 {
		return Approval{}, fmt.Errorf("approval: the message has %d Message-ID headers; exactly one is allowed", n)
	}
	messageID := strings.TrimSpace(msg.Header.Get("Message-Id"))
	if messageID == "" {
		return Approval{}, errors.New("approval: the message has no Message-ID, so a replay of it could not be recognised")
	}
	if rules.Seen(messageID) {
		return Approval{}, fmt.Errorf("approval: %s has already been accepted; an approval is used once", messageID)
	}

	selector, domain, err := verifySignature(ctx, raw, pinned.domain(), rules.Resolver)
	if err != nil {
		return Approval{}, err
	}

	return Approval{
		From:      from.Address,
		MessageID: messageID,
		Subject:   subject,
		Date:      date,
		Domain:    domain,
		Selector:  selector,
	}, nil
}

// Token is the exact string an approval's subject must contain for
// reference. One function so birdcage's outgoing request, the verifier
// and the CLI cannot drift apart on spacing or brackets.
func Token(reference string) string {
	return "[birdcage " + reference + "]"
}

// SubjectReference is the reverse of Token: the reference carried by
// subject, or "" if it carries none. Birdcage uses it on an incoming
// message, where the reference is whatever the admin replied about
// rather than something we already knew.
func SubjectReference(subject string) string {
	for _, s := range subjectForms(subject) {
		_, rest, ok := strings.Cut(s, "[birdcage ")
		if !ok {
			continue
		}
		ref, _, ok := strings.Cut(rest, "]")
		if !ok {
			continue
		}
		if ref = strings.TrimSpace(ref); ref != "" {
			return ref
		}
	}
	return ""
}

// pinnedAddress is a validated PinnedFrom.
type pinnedAddress struct{ Address string }

func (p pinnedAddress) domain() string {
	_, d, _ := strings.Cut(p.Address, "@")
	return d
}

// validate proves the caller filled Rules in. Every one of these is a
// programming error rather than a message problem, so they are reported
// separately from the rules that judge the message itself.
func (r Rules) validate() (pinnedAddress, error) {
	if strings.TrimSpace(r.PinnedFrom) == "" {
		return pinnedAddress{}, errors.New("approval: no administrator address is pinned; set the admin_approval_address setting")
	}
	addr, err := netmail.ParseAddress(r.PinnedFrom)
	if err != nil {
		return pinnedAddress{}, fmt.Errorf("approval: the pinned administrator address %q is not a valid address: %w", r.PinnedFrom, err)
	}
	if _, d, ok := strings.Cut(addr.Address, "@"); !ok || d == "" {
		return pinnedAddress{}, fmt.Errorf("approval: the pinned administrator address %q has no domain", r.PinnedFrom)
	}
	if strings.TrimSpace(r.Reference) == "" {
		return pinnedAddress{}, errors.New("approval: no request reference was given to check the subject against")
	}
	if strings.ContainsAny(r.Reference, "[]") {
		return pinnedAddress{}, fmt.Errorf("approval: the request reference %q contains a bracket, which would break the subject token", r.Reference)
	}
	if r.Now.IsZero() {
		return pinnedAddress{}, errors.New("approval: Rules.Now is zero; the caller must supply the time to measure Date against")
	}
	if r.MaxAge <= 0 {
		return pinnedAddress{}, errors.New("approval: Rules.MaxAge must be positive")
	}
	if r.Resolver == nil {
		return pinnedAddress{}, errors.New("approval: Rules.Resolver is nil; this package never looks up DNS on its own")
	}
	if r.Seen == nil {
		return pinnedAddress{}, errors.New("approval: Rules.Seen is nil; skipping the replay check has to be deliberate")
	}
	return pinnedAddress{Address: addr.Address}, nil
}

// verifySignature is the DKIM half: exactly one valid signature from
// wantDomain, no l= anywhere, and the four load-bearing headers inside
// that signature's h= list. It returns the accepted signature's
// selector and domain.
func verifySignature(ctx context.Context, raw []byte, wantDomain string, resolver func(string) ([]string, error)) (selector, domain string, err error) {
	sigs, err := signatureTags(raw)
	if err != nil {
		return "", "", err
	}
	if len(sigs) == 0 {
		return "", "", errors.New("approval: the message carries no DKIM signature")
	}
	// l= is refused whichever signature carries it and whether or not
	// that signature would otherwise have been ignored: a message
	// offering a length-limited signature at all is not one to reason
	// carefully about.
	for _, s := range sigs {
		if _, ok := s["l"]; ok {
			return "", "", errors.New("approval: a DKIM signature covers only part of the body (l=), which would let anything be appended below it")
		}
	}
	// One raw signature header per domain, so the selector reported
	// below unambiguously belongs to the signature that was accepted.
	var matchingRaw []map[string]string
	for _, s := range sigs {
		if strings.EqualFold(s["d"], wantDomain) {
			matchingRaw = append(matchingRaw, s)
		}
	}
	switch len(matchingRaw) {
	case 0:
		return "", "", fmt.Errorf("approval: no DKIM signature was made by %s (the message is signed by %s)", wantDomain, strings.Join(signingDomains(sigs), ", "))
	case 1:
	default:
		return "", "", fmt.Errorf("approval: the message carries %d DKIM signatures from %s; exactly one is allowed", len(matchingRaw), wantDomain)
	}

	// dkim's LookupTXT has no context of its own, so cancellation is
	// checked at the one place it is worth checking: immediately before
	// each lookup.
	lookup := func(name string) ([]string, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return resolver(name)
	}

	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{
		LookupTXT:        lookup,
		MaxVerifications: maxSignatures,
	})
	if err != nil {
		if errors.Is(err, dkim.ErrTooManySignatures) {
			return "", "", fmt.Errorf("approval: the message carries more than %d DKIM signatures", maxSignatures)
		}
		return "", "", fmt.Errorf("approval: the DKIM signatures could not be checked: %w", err)
	}

	var accepted *dkim.Verification
	var lastErr error
	for _, v := range verifications {
		if !strings.EqualFold(v.Domain, wantDomain) {
			continue
		}
		if v.Err != nil {
			lastErr = v.Err
			continue
		}
		if accepted != nil {
			return "", "", fmt.Errorf("approval: more than one valid DKIM signature from %s", wantDomain)
		}
		accepted = v
	}
	if accepted == nil {
		if lastErr != nil {
			return "", "", fmt.Errorf("approval: the DKIM signature from %s is not valid: %w", wantDomain, lastErr)
		}
		return "", "", fmt.Errorf("approval: no valid DKIM signature from %s", wantDomain)
	}

	if missing := missingSignedHeaders(accepted.HeaderKeys); len(missing) > 0 {
		return "", "", fmt.Errorf("approval: the DKIM signature does not cover %s, so %s not part of what was signed",
			strings.Join(missing, ", "), pluralIs(len(missing)))
	}

	selector = strings.TrimSpace(matchingRaw[0]["s"])
	if selector == "" {
		return "", "", errors.New("approval: the accepted DKIM signature names no selector")
	}
	return selector, accepted.Domain, nil
}

// missingSignedHeaders returns the entries of signedHeaders that are not
// in keys, preserving signedHeaders' order so the message reads the same
// way every time.
func missingSignedHeaders(keys []string) []string {
	have := make(map[string]bool, len(keys))
	for _, k := range keys {
		have[strings.ToLower(strings.TrimSpace(k))] = true
	}
	var missing []string
	for _, want := range signedHeaders {
		if !have[want] {
			missing = append(missing, want)
		}
	}
	return missing
}

func pluralIs(n int) string {
	if n == 1 {
		return "it is"
	}
	return "they are"
}

// signingDomains is the d= of every signature on the message, for the
// error that says who did sign it when nobody we wanted did.
func signingDomains(sigs []map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range sigs {
		d := strings.TrimSpace(s["d"])
		if d == "" {
			d = "(no domain)"
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return []string{"nobody"}
	}
	return out
}

// signatureTags parses every DKIM-Signature header on the message into
// its tag=value map.
//
// This package parses them itself rather than reading them off
// dkim.Verification because a Verification does not carry the selector
// or the l= tag, and both are load-bearing here: l= is the rule that
// refuses a partially-signed body, and the selector is what an operator
// needs to see when they are comparing against their provider's DNS
// record.
func signatureTags(raw []byte) ([]map[string]string, error) {
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("approval: the message could not be parsed as an email: %w", err)
	}
	var out []map[string]string
	for _, v := range msg.Header["Dkim-Signature"] {
		out = append(out, parseTags(v))
	}
	return out, nil
}

// parseTags splits a DKIM tag list ("v=1; a=rsa-sha256; d=example.net")
// into a map. Whitespace, including the folding a long b= or bh= value
// carries, is stripped from both sides; a value may itself contain "="
// (base64 padding does), so only the first one splits.
func parseTags(value string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(value, ";") {
		name, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, exists := tags[name]; exists {
			// A repeated tag is malformed. Keeping the first is the
			// conservative reading, and the signature verification
			// below will reject the message anyway.
			continue
		}
		tags[name] = strings.TrimSpace(v)
	}
	return tags
}

// sameAddress compares an address the pinned way: exact on the local
// part, case-insensitive on the domain. RFC 5321 leaves the local part's
// case to the receiving host, so treating "Admin@" and "admin@" as the
// same address would be this package deciding something it has no way
// to know.
func sameAddress(got, pinned string) bool {
	gotLocal, gotDomain, ok := strings.Cut(got, "@")
	if !ok {
		return false
	}
	pinnedLocal, pinnedDomain, ok := strings.Cut(pinned, "@")
	if !ok {
		return false
	}
	return gotLocal == pinnedLocal && strings.EqualFold(gotDomain, pinnedDomain)
}

// subjectCarries reports whether subject contains token, trying the
// subject both as received and as RFC 2047 decoded -- a client that
// encodes the whole subject line would otherwise hide a token that is
// plainly there when the admin looks at it.
func subjectCarries(subject, token string) bool {
	for _, s := range subjectForms(subject) {
		if strings.Contains(s, token) {
			return true
		}
	}
	return false
}

// subjectForms is subject as received and, when it differs, as RFC 2047
// decoded.
func subjectForms(subject string) []string {
	forms := []string{subject}
	decoded, err := (&mime.WordDecoder{}).DecodeHeader(subject)
	if err == nil && decoded != subject {
		forms = append(forms, decoded)
	}
	return forms
}

// normalizeLineEndings promotes any bare LF to CRLF and leaves an
// existing CRLF alone, so a message that was valid to begin with passes
// through unchanged.
func normalizeLineEndings(raw []byte) []byte {
	if !bytes.Contains(raw, []byte("\n")) {
		return raw
	}
	out := make([]byte, 0, len(raw)+bytes.Count(raw, []byte("\n")))
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\n' && (i == 0 || raw[i-1] != '\r') {
			out = append(out, '\r', '\n')
			continue
		}
		out = append(out, raw[i])
	}
	return out
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
