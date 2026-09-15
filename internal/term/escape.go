// Package term makes text safe to print to an operator's terminal.
//
// This is an output-side concern only. Text birdcage did not generate
// itself -- a canary id, a service name, a source address, an
// OpenCanary "raw" field -- comes from a machine we expect to be
// attacked, and is stored verbatim: SECURITY.md's rule, and #48's rule
// for the agent, is that the stored record is evidence and nothing
// upstream of output strips or rewrites it. Escape lets a caller print
// that same text without a terminal executing whatever control bytes it
// contains, without touching the row it came from.
package term

import (
	"strings"
	"unicode/utf8"
)

// Escape returns s with every C0 control character (U+0000-U+001F), DEL
// (U+007F), and C1 control character (U+0080-U+009F) rendered as a
// visible, literal escape sequence instead of the byte a terminal would
// act on. Left unescaped, these can hide lines, move the cursor to
// overwrite what is already on screen, or recolour unrelated output --
// e.g. making a revoked token's line read as active.
//
// Every other rune, including non-ASCII printable text such as a canary
// named in Japanese, passes through unchanged: this only touches control
// characters, never quotes, backslashes, or ordinary punctuation, so it
// does not otherwise alter the text an operator sees.
//
// An invalid UTF-8 byte is escaped the same way a control character is,
// rather than passed through as whatever the terminal decides to make of
// it.
func Escape(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			writeHexByte(&b, s[i])
			i++
			continue
		}
		switch {
		case r < 0x20 || r == 0x7f:
			writeControlEscape(&b, r)
		case r >= 0x80 && r <= 0x9f:
			writeUnicodeEscape(&b, r)
		default:
			b.WriteRune(r)
		}
		i += size
	}
	return b.String()
}

// needsEscape reports whether s contains anything Escape would change,
// so a plain-text caller (the overwhelmingly common case: canary ids and
// names in practice contain no control bytes at all) never pays for a
// strings.Builder it doesn't need.
func needsEscape(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			return true
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
		i += size
	}
	return false
}

const hexDigits = "0123456789abcdef"

func writeHexByte(b *strings.Builder, c byte) {
	b.WriteString(`\x`)
	b.WriteByte(hexDigits[c>>4])
	b.WriteByte(hexDigits[c&0xf])
}

// writeControlEscape renders a C0 control character or DEL. The three
// most common ones get their conventional short form; everything else
// -- including ESC, which is how most of the actually dangerous
// sequences (cursor movement, colour, alternate screen) begin -- gets a
// \xHH literal.
func writeControlEscape(b *strings.Builder, r rune) {
	switch r {
	case '\n':
		b.WriteString(`\n`)
	case '\r':
		b.WriteString(`\r`)
	case '\t':
		b.WriteString(`\t`)
	default:
		writeHexByte(b, byte(r))
	}
}

// writeUnicodeEscape renders a C1 control character (U+0080-U+009F).
// These are single Unicode code points, encoded as two UTF-8 bytes each,
// so \xHH (a one-byte escape) would be ambiguous about which of the two
// input bytes it names; \uHHHH names the code point itself instead.
func writeUnicodeEscape(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	b.WriteByte(hexDigits[(r>>12)&0xf])
	b.WriteByte(hexDigits[(r>>8)&0xf])
	b.WriteByte(hexDigits[(r>>4)&0xf])
	b.WriteByte(hexDigits[r&0xf])
}
