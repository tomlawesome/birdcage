package term

import (
	"strings"
	"testing"
)

// TestEscapeControlSequenceRenderedNotExecuted is this issue's proof: a
// control sequence -- here ESC "[2J" (\x1b[2J), which clears the
// terminal screen -- must reach the writer as literal, printable bytes
// rather than as the raw ESC byte a terminal would act on. Asserting the
// exact output bytes is the point: "looks escaped" isn't enough,
// because a partially-escaped string could still contain the one
// dangerous byte.
func TestEscapeControlSequenceRenderedNotExecuted(t *testing.T) {
	in := "canary-\x1b[2J-evil"
	want := `canary-\x1b[2J-evil`
	got := Escape(in)
	if got != want {
		t.Fatalf("Escape(%q) = %q, want %q", in, got, want)
	}
	for _, b := range []byte(got) {
		if b == 0x1b {
			t.Fatalf("Escape(%q) = %q still contains a raw ESC byte", in, got)
		}
	}
}

// TestEscapeHidesLineViaCarriageReturn covers the "hide what's on
// screen" attack the issue describes: a bare \r would let a canary id
// overwrite the start of the line it's printed on. It must come back as
// the literal two characters backslash-r, not the raw 0x0d byte.
func TestEscapeHidesLineViaCarriageReturn(t *testing.T) {
	in := "ok\rrevoked: false"
	want := `ok\rrevoked: false`
	if got := Escape(in); got != want {
		t.Fatalf("Escape(%q) = %q, want %q", in, got, want)
	}
}

func TestEscapeOrdinaryAndNonASCIIUnchanged(t *testing.T) {
	cases := []string{
		"canary-01",
		"web-honeypot",
		"カナリア-東京",           // Japanese: an operator must still be able to read this
		"düsseldorf-office", // Latin-1 supplement letters, still printable
		"emoji-🐦-trap",
		`already has "quotes" and a \backslash`,
	}
	for _, in := range cases {
		if got := Escape(in); got != in {
			t.Errorf("Escape(%q) = %q, want unchanged", in, got)
		}
	}
}

// TestEscapeC1ControlCharacter covers U+0085 (NEL), a C1 control
// character encoded as two UTF-8 bytes, not covered by the C0/DEL byte
// range. Built with string(rune(...)) rather than a source literal so
// this file never has to carry a raw control byte itself.
func TestEscapeC1ControlCharacter(t *testing.T) {
	nel := string(rune(0x85))
	in := "canary-" + nel + "-nel"
	want := "canary-" + `\u0085` + "-nel"
	if got := Escape(in); got != want {
		t.Fatalf("Escape(%q) = %q, want %q", in, got, want)
	}
}

func TestEscapeInvalidUTF8Byte(t *testing.T) {
	in := "canary-\xff-bad"
	want := `canary-\xff-bad`
	if got := Escape(in); got != want {
		t.Fatalf("Escape(%q) = %q, want %q", in, got, want)
	}
}

func TestEscapeEmptyString(t *testing.T) {
	if got := Escape(""); got != "" {
		t.Fatalf("Escape(\"\") = %q, want empty", got)
	}
}

func TestEscapeAllC0AndDEL(t *testing.T) {
	for c := 0; c < 0x20; c++ {
		in := string(rune(c))
		got := Escape(in)
		for _, b := range []byte(got) {
			if b == byte(c) && c != '\\' {
				t.Fatalf("Escape(%q) = %q still contains raw control byte 0x%02x", in, got, c)
			}
		}
	}
	got := Escape("\x7f")
	if got == "\x7f" {
		t.Fatalf("Escape(DEL) returned DEL unescaped")
	}
}

// TestEscapeBidiOverrides: the Trojan Source class (CVE-2021-42574).
// These characters move nothing on screen; they reverse how the text
// around them reads, so a canary id can display as an id other than the
// one stored. They must survive as visible text, not as formatting.
func TestEscapeBidiOverrides(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"right-to-left override", "canary-\u202eresrever", `canary-\u202eresrever`},
		{"left-to-right mark", "a\u200eb", `a\u200eb`},
		{"first strong isolate", "a\u2068b\u2069c", `a\u2068b\u2069c`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Escape(tc.in)
			if got != tc.want {
				t.Errorf("Escape(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.ContainsRune(got, 0x202e) || strings.ContainsRune(got, 0x200e) || strings.ContainsRune(got, 0x2068) {
				t.Errorf("Escape(%q) left a bidi character in the output", tc.in)
			}
		})
	}
}
