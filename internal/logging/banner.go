// SPDX-License-Identifier: AGPL-3.0-only

package logging

import (
	"fmt"
	"os"
	"strings"
)

// bannerWhite/bannerBrightYellow/bannerGreen round out the banner's own
// palette on top of ansiDim/ansiRed already shared with the leveled-log
// colors in logging.go -- kept local to this file since nothing outside
// the banner uses them.
//
// bannerTop/bannerShadow are the wordmark's two-tone bevel -- a solid
// block face and a darker box-drawing edge is what reads as extruded
// rather than flat (see this file's own doc comment above). These two,
// plus bannerDeepPurple, are 256-colour escapes, not the standard 16
// most other constants here use: neither "pink" nor "mustard yellow" nor
// "deep purple" has a standard-16 equivalent that actually looks like
// the name (both standard and bright magenta read as one shade of
// pink-purple, not clearly either; plain yellow already means something
// else two lines below, and bright yellow is even further off). This is
// a one-off decorative banner, not a data-bearing log line where palette
// consistency matters for scanability, and 256-colour support is no
// longer a meaningful compatibility risk for anything that renders ANSI
// colour at all -- so precision here won out over matching the
// 16-colour convention.
const (
	bannerWhite        = "\x1b[37m"
	bannerBrightYellow = "\x1b[93m"
	bannerGreen        = "\x1b[32m"
	bannerTop          = "\x1b[38;5;205m" // pink
	bannerShadow       = "\x1b[38;5;178m" // mustard yellow
	bannerDeepPurple   = "\x1b[38;5;54m"  // deep purple (#5f0087)
)

// The boot banner, split into backdrop and wordmark so the two can be
// coloured differently -- a dim starfield behind a bright wordmark reads
// as depth, where one flat colour reads as a wall of blocks.
//
// Its job is to make a restart unmissable when you are scrolling back
// through `docker logs` looking for where the container came up. That is
// why it is deliberately large and deliberately unlike every other line
// birdcage prints.
//
// Box-drawing and block characters rather than plain ASCII: the bevelled
// ╗╝ edges are what make the letters look extruded, and there is no
// ASCII equivalent that does. This is not a new dependency on UTF-8 --
// every log line already separates its columns with │ (see formatLine),
// so a terminal that mangles this would already be mangling the rest of
// the output.
const (
	bannerTopRule    = `─────────────────────────────────────────────────────────────────────────────`
	bannerBottomRule = bannerTopRule
)

// bannerSkyAbove/bannerSkyBelow are the backdrop. Placement is
// deliberately irregular -- evenly spaced stars read as a pattern, and a
// pattern doesn't read as sky.
//
// Each line has its own glyphColors map (built in PrintBanner) rather
// than one colour for the whole backdrop -- a handful of the ✦/○/◯
// glyphs pick up a colour of their own so the sky reads as a varied
// twinkle rather than a flat wash, while every `·` -- by far the most
// common glyph -- stays dim. Which specific glyph gets which colour was
// chosen by hand per occurrence (four ○/◯ across the whole backdrop,
// too few to bother with a systematic rule), not derived from the glyph
// itself.
//
// The four ○/◯ ("planet") colours are deliberately red, cyan, green and
// deep purple -- not pink or mustard yellow, both already the
// wordmark's own two dominant colours (bannerTop/bannerShadow). A
// planet sharing one of those would echo the wordmark instead of
// contrasting with it, which defeats the point of colouring the
// backdrop separately at all. ✦ stays bright yellow throughout
// regardless -- it reads as a distinct sparkle rather than a block of
// colour, so it doesn't compete with the wordmark's mustard shadow the
// way a plain-yellow planet would.
var (
	bannerSkyAbove = []string{
		`      ·            ✦             ·                  ·           ✦      ·`,
		`  ✦        ·               ○                ·             ·          ◯`,
	}
	bannerSkyBelow = []string{
		`    ·          ◯              ·                ✦             ·           ·`,
		`         ✦             ·              ·                ○          ·`,
	}

	// bannerWordmark is BIRDCAGE in an extruded block face -- same font
	// (ANSI Shadow) and same glyph set as mikroview's own wordmark, so
	// both projects' boot banners read as one family. Centred under
	// bannerTopRule (8 leading spaces either side of the 60-column
	// glyph art, 77 columns wide) rather than left-padded flush like
	// mikroview's 73-of-77-column MIKROVIEW: BIRDCAGE is a shorter word
	// in the same font, and centring it keeps the wordmark looking
	// deliberately placed rather than merely narrower.
	bannerWordmark = []string{
		`        ██████╗ ██╗██████╗ ██████╗  ██████╗ █████╗  ██████╗ ███████╗`,
		`        ██╔══██╗██║██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝ ██╔════╝`,
		`        ██████╔╝██║██████╔╝██║  ██║██║     ███████║██║  ███╗█████╗  `,
		`        ██╔══██╗██║██╔══██╗██║  ██║██║     ██╔══██║██║   ██║██╔══╝  `,
		`        ██████╔╝██║██║  ██║██████╔╝╚██████╗██║  ██║╚██████╔╝███████╗`,
		`        ╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝`,
	}
)

// bannerSkyAboveColors/bannerSkyBelowColors pick out which glyph in each
// sky line gets its own colour -- see bannerSkyAbove/Below's doc comment
// for why these are hand-assigned per line rather than one map for every
// occurrence of a glyph. A glyph missing from a line's map (every `·`)
// falls through to the plain dim treatment every other backdrop
// character gets.
var (
	bannerSkyAboveColors = []map[rune]string{
		{'✦': bannerBrightYellow},
		{'✦': bannerBrightYellow, '○': ansiRed, '◯': ansiCyan},
	}
	bannerSkyBelowColors = []map[rune]string{
		{'◯': bannerGreen, '✦': bannerBrightYellow},
		{'✦': bannerBrightYellow, '○': bannerDeepPurple},
	}
)

// PrintBanner writes the boot-time wordmark directly to stdout, once,
// outside the leveled log path -- it isn't a log line (no timestamp/
// level/component), just a startup marker, so it doesn't go through a
// component logger. Called only from cmd/birdcage/main.go -- cmd/
// mockingbird deliberately never calls this (see this package's own doc
// comment for why).
//
// Colour is applied per-band rather than around the whole thing, and is
// dropped entirely off a TTY or under NO_COLOR (see colorEnabled) -- the
// art itself carries no escape sequences, so `docker logs` and a log
// collector get the same shape, just without the colour.
func PrintBanner() {
	var b strings.Builder

	color := colorEnabled()
	sky := func(line string, glyphs map[rune]string) string {
		if !color {
			return line
		}
		return colorGlyphs(line, glyphs, ansiDim)
	}
	wordmark := func(line string) string {
		if !color {
			return line
		}
		return colorWordmarkLine(line, bannerTop, bannerShadow)
	}
	rule := func(s string) string {
		if !color {
			return s
		}
		return bannerWhite + s + ansiReset
	}

	b.WriteString(rule(bannerTopRule) + "\n")
	for i, line := range bannerSkyAbove {
		b.WriteString(sky(line, bannerSkyAboveColors[i]) + "\n")
	}
	for _, line := range bannerWordmark {
		b.WriteString(wordmark(line) + "\n")
	}
	for i, line := range bannerSkyBelow {
		b.WriteString(sky(line, bannerSkyBelowColors[i]) + "\n")
	}
	b.WriteString(rule(bannerBottomRule))

	fmt.Fprintln(os.Stdout, b.String())
}

// colorGlyphs colours each rune of line by its entry in glyphColors,
// falling back to fallback for anything not listed (in practice, `·`
// and the spaces between glyphs) -- batching consecutive runes that
// land on the same colour into one escape-wrapped span, the same
// run-length approach colorWordmarkLine uses below, rather than
// wrapping every individual character (mostly space) in its own colour
// pair.
func colorGlyphs(line string, glyphColors map[rune]string, fallback string) string {
	colorOf := func(r rune) string {
		if code, ok := glyphColors[r]; ok {
			return code
		}
		return fallback
	}

	runes := []rune(line)
	var b strings.Builder
	for i := 0; i < len(runes); {
		c := colorOf(runes[i])
		j := i + 1
		for j < len(runes) && colorOf(runes[j]) == c {
			j++
		}
		b.WriteString(c + string(runes[i:j]) + ansiReset)
		i = j
	}
	return b.String()
}

// colorWordmarkLine splits one wordmark row into its solid-block "top"
// face and box-drawing "shadow" edge, colouring each run of consecutive
// same-class characters as one span -- matching how a hand-written
// escape sequence would wrap it (one colour change per run, not per
// character), rather than emitting a redundant colour code before every
// single rune. A run of plain spaces is left uncoloured, same as the sky
// glyphs' surrounding space.
//
// The classification is purely structural, not a hardcoded rune list:
// '█' is the top face, ' ' is space, and everything else in this art is
// one of the box-drawing edge characters (╗╝║╔═╚) -- so a future edit to
// bannerWordmark that reshapes the letters still colours correctly
// without this function needing to change.
func colorWordmarkLine(line, top, shadow string) string {
	type class int
	const (
		classSpace class = iota
		classTop
		classShadow
	)
	classOf := func(r rune) class {
		switch r {
		case '█':
			return classTop
		case ' ':
			return classSpace
		default:
			return classShadow
		}
	}

	runes := []rune(line)
	var b strings.Builder
	for i := 0; i < len(runes); {
		c := classOf(runes[i])
		j := i + 1
		for j < len(runes) && classOf(runes[j]) == c {
			j++
		}
		seg := string(runes[i:j])
		switch c {
		case classTop:
			b.WriteString(top + seg + ansiReset)
		case classShadow:
			b.WriteString(shadow + seg + ansiReset)
		default:
			b.WriteString(seg)
		}
		i = j
	}
	return b.String()
}
