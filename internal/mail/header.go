package mail

import (
	"strings"
	"unicode/utf8"
)

// headerSafe reports whether v can be used as a header value, or as any
// input that ends up inside one.
//
// The rule is deliberately stricter than "no CR and no LF". Header
// injection is the attack this stops -- a newline in a canary name or in
// BIRDCAGE_MAIL_FROM would let whoever chose that text append headers of
// their own, or end the headers early and write the body -- but a bare
// CR, a NUL or a C1 escape in a header is never anything birdcage meant
// to send either, so the gate is "no control characters at all" rather
// than a list of the two that are known to be dangerous today.
//
// C1 (0x80-0x9F) is included for the reason internal/term.Escape gives:
// in a single-byte encoding those bytes are control characters, and
// nothing birdcage generates ever needs one.
//
// This check runs on every header value every time a message is
// assembled, regardless of what net/smtp does with the same string
// afterwards. net/smtp does validate the addresses it is handed, but
// the subject, the date and the message id never pass through it at all
// -- they are bytes we write into the DATA stream ourselves -- so
// relying on a library's own check would leave exactly the fields we
// compose unguarded.
func headerSafe(v string) bool {
	for _, r := range v {
		switch {
		case r == utf8.RuneError:
			// Invalid UTF-8 decodes to RuneError one byte at a time. A
			// real U+FFFD is also rejected; nothing birdcage puts in a
			// header contains one.
			return false
		case r < 0x20 || r == 0x7F:
			return false
		case r >= 0x80 && r <= 0x9F:
			return false
		}
	}
	return true
}

// stripControl removes every character headerSafe rejects, leaving the
// rest of the text exactly as it was found. Used on the one piece of
// attacker-influenced text a message carries -- the canary's name, which
// is whoever named the canary's choice of string -- because a name is
// worth showing when it is ordinary and worth dropping entirely when it
// is not (see templates.go's withholding rule), and stripping first is
// what makes those two cases distinguishable.
//
// Not an escape: SECURITY.md's "Output escaping" section puts escaping
// at the point of display, per surface. This is that point for the mail
// surface, and a mail reader has no way to render "\x1b" as anything
// other than what it looks like, so the characters are removed rather
// than made visible.
func stripControl(v string) string {
	if headerSafe(v) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		switch {
		case r == utf8.RuneError, r < 0x20, r == 0x7F, r >= 0x80 && r <= 0x9F:
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
