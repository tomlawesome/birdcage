// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// bannerLines is every rendered line, in order, without colour.
func bannerLines() []string {
	out := []string{bannerTopRule}
	out = append(out, bannerSkyAbove...)
	out = append(out, bannerWordmark...)
	out = append(out, bannerSkyBelow...)
	return append(out, bannerBottomRule)
}

func TestBannerHasContentOnEveryLine(t *testing.T) {
	lines := bannerLines()
	if len(lines) < 10 {
		t.Fatalf("expected a substantial banner, got %d lines", len(lines))
	}
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			t.Errorf("line %d is blank -- a blank line in the middle of the art breaks the block", i)
		}
	}
}

// The wordmark rows must all be the same rendered width, or the extruded
// edges shear and it stops looking like one solid object.
func TestWordmarkRowsAlign(t *testing.T) {
	want := utf8.RuneCountInString(bannerWordmark[0])
	for i, l := range bannerWordmark {
		if got := utf8.RuneCountInString(l); got != want {
			t.Errorf("wordmark row %d is %d runes wide, want %d -- the rows must align", i, got, want)
		}
	}
}

// Nothing may be wider than the rules that bracket it, or the art
// visibly overflows its own frame.
func TestNothingOverflowsTheRules(t *testing.T) {
	width := utf8.RuneCountInString(bannerTopRule)
	for i, l := range bannerLines() {
		if got := utf8.RuneCountInString(l); got > width {
			t.Errorf("line %d is %d runes wide, wider than the %d-rune rule", i, got, width)
		}
	}
	if utf8.RuneCountInString(bannerBottomRule) != width {
		t.Error("the top and bottom rules are different widths")
	}
}

// The art itself carries no escape sequences: colour is applied at print
// time and dropped off a TTY, so `docker logs` and a log collector get
// the same shape as a terminal does, just without the colour. An escape
// baked into the constants would defeat that.
func TestBannerArtCarriesNoEscapeSequences(t *testing.T) {
	for i, l := range bannerLines() {
		if strings.ContainsRune(l, '\x1b') {
			t.Errorf("line %d contains an ANSI escape -- colour belongs in PrintBanner, not the art", i)
		}
	}
}

// It has to survive a container's stdout, which is not a terminal. This
// is the whole reason the banner exists: marking a restart in
// `docker logs`.
func TestBannerIsValidUTF8(t *testing.T) {
	for i, l := range bannerLines() {
		if !utf8.ValidString(l) {
			t.Errorf("line %d is not valid UTF-8", i)
		}
	}
}

func TestPrintBannerDoesNotPanic(t *testing.T) {
	PrintBanner()
}

// TestColorWordmarkLineClassifiesCorrectly proves the three character
// classes land on the colours they should: '█' gets top, every
// box-drawing edge character gets shadow, and spaces are left bare
// (no escape wrapping at all, not even a no-op one).
func TestColorWordmarkLineClassifiesCorrectly(t *testing.T) {
	got := colorWordmarkLine("█ ╗", "<TOP>", "<SHADOW>")
	want := "<TOP>█" + ansiReset + " " + "<SHADOW>╗" + ansiReset
	if got != want {
		t.Errorf("colorWordmarkLine(%q) = %q, want %q", "█ ╗", got, want)
	}
}

// TestColorWordmarkLineBatchesConsecutiveRuns proves same-class runs are
// wrapped once, not once per rune -- a naive per-character
// implementation would still be *correct* here, just far noisier, and
// this is what actually distinguishes the two.
func TestColorWordmarkLineBatchesConsecutiveRuns(t *testing.T) {
	got := colorWordmarkLine("███", "<TOP>", "<SHADOW>")
	want := "<TOP>███" + ansiReset
	if got != want {
		t.Errorf("colorWordmarkLine(%q) = %q, want one batched span %q", "███", got, want)
	}
}

// TestColorWordmarkLineOnRealWordmarkClassifiesEveryRune checks every
// rune actually appearing in bannerWordmark lands in the class its own
// character warrants: '█' wrapped in top, every box-drawing edge
// character wrapped in shadow, space left bare. Not every row contains
// both classes -- the wordmark's bottom row is a pure box-drawing
// baseline stroke with no '█' at all -- so this checks classification
// per rune actually present, not "every row has one of each".
func TestColorWordmarkLineOnRealWordmarkClassifiesEveryRune(t *testing.T) {
	for _, line := range bannerWordmark {
		out := colorWordmarkLine(line, "<T>", "<S>")
		for _, r := range line {
			switch r {
			case ' ':
				continue
			case '█':
				if !strings.Contains(out, "<T>"+string(r)) {
					t.Errorf("line %q: '█' not wrapped in the top colour in %q", line, out)
				}
			default:
				if !strings.Contains(out, "<S>") {
					t.Errorf("line %q: edge rune %q not wrapped in the shadow colour in %q", line, r, out)
				}
			}
		}
	}
}

// TestColorGlyphsAppliesMappedColorsAndFallback checks a mapped glyph
// gets its own colour and everything else -- including a glyph present
// in the string but absent from the map -- gets fallback.
func TestColorGlyphsAppliesMappedColorsAndFallback(t *testing.T) {
	got := colorGlyphs("a✦b", map[rune]string{'✦': "<STAR>"}, "<FALLBACK>")
	want := "<FALLBACK>a" + ansiReset + "<STAR>✦" + ansiReset + "<FALLBACK>b" + ansiReset
	if got != want {
		t.Errorf("colorGlyphs = %q, want %q", got, want)
	}
}

// TestColorGlyphsBatchesConsecutiveFallbackRuns is colorGlyphs' half of
// the batching claim -- the sky lines are mostly space, and a naive
// per-rune implementation would wrap every single space in its own
// escape pair.
func TestColorGlyphsBatchesConsecutiveFallbackRuns(t *testing.T) {
	got := colorGlyphs("   ", map[rune]string{'✦': "<STAR>"}, "<DIM>")
	want := "<DIM>   " + ansiReset
	if got != want {
		t.Errorf("colorGlyphs(%q) = %q, want one batched fallback span %q", "   ", got, want)
	}
}

// TestSkyColorMapsCoverEveryStarGlyphInTheRealArt guards against a
// bannerSkyAbove/Below edit silently leaving a new ✦/○/◯ occurrence out
// of its line's colour map -- it would still render (via fallback), just
// not with the intended accent colour, which is exactly the kind of
// mismatch that's invisible in a code review of the art alone.
func TestSkyColorMapsCoverEveryStarGlyphInTheRealArt(t *testing.T) {
	check := func(lines []string, colors []map[rune]string, name string) {
		if len(lines) != len(colors) {
			t.Fatalf("%s: %d lines but %d colour maps", name, len(lines), len(colors))
		}
		for i, line := range lines {
			for _, r := range line {
				if r == '·' || r == ' ' {
					continue
				}
				if _, ok := colors[i][r]; !ok {
					t.Errorf("%s[%d]: glyph %q has no colour mapping", name, i, r)
				}
			}
		}
	}
	check(bannerSkyAbove, bannerSkyAboveColors, "bannerSkyAbove")
	check(bannerSkyBelow, bannerSkyBelowColors, "bannerSkyBelow")
}
