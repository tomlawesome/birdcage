// SPDX-License-Identifier: LicenseRef-Birdcage-Noncommercial-1.0

package logging

import (
	"log/slog"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/tomlawesome/birdcage/internal/term"
)

func TestFormatLineNoColorLayout(t *testing.T) {
	ts := "18:43:44"
	got := formatLine(ts, slog.LevelInfo, "ingest", "no decision made yet", "", false)
	want := "18:43:44 INFO  ingest      │ no decision made yet\n"
	if got != want {
		t.Errorf("formatLine =\n%q\nwant\n%q", got, want)
	}
}

func TestFormatLineErrorLevelNoDoubleSpace(t *testing.T) {
	// ERROR is one character wider than INFO/WARN, so it should get one
	// space before the component, not two -- otherwise the │ column
	// drifts out of alignment on error lines specifically.
	got := formatLine("18:43:46", slog.LevelError, "ingest-tls", "bind: address already in use", "", false)
	want := "18:43:46 ERROR ingest-tls  │ bind: address already in use\n"
	if got != want {
		t.Errorf("formatLine =\n%q\nwant\n%q", got, want)
	}
}

func TestFormatLineLongComponentDoesNotTruncate(t *testing.T) {
	got := formatLine("18:43:44", slog.LevelInfo, "self-test-runner", "re-armed", "", false)
	if !strings.Contains(got, "self-test-runner") {
		t.Errorf("expected the full component name to survive padding, got %q", got)
	}
	if !strings.HasSuffix(got, "│ re-armed\n") {
		t.Errorf("expected the message to still follow the separator, got %q", got)
	}
}

func TestFormatLineColorWrapsLevelAndDimsTheRest(t *testing.T) {
	got := formatLine("18:43:44", slog.LevelWarn, "rotation", "permission denied", "", true)
	if !strings.Contains(got, ansiYellow+"WARN "+ansiReset) {
		t.Errorf("expected the level token colored yellow and reset, got %q", got)
	}
	if !strings.Contains(got, ansiDim+"18:43:44"+ansiReset) {
		t.Errorf("expected the timestamp dimmed, got %q", got)
	}
	// The message itself is never wrapped in an ANSI code -- only the
	// timestamp/level/component/separator get colored.
	if !strings.HasSuffix(got, "permission denied\n") {
		t.Errorf("expected the message to stay uncolored at the end of the line, got %q", got)
	}
}

func TestLevelWordAndColorByThreshold(t *testing.T) {
	cases := []struct {
		level slog.Level
		word  string
		color string
	}{
		{slog.LevelDebug, "DEBUG", ansiDim},
		{slog.LevelInfo, "INFO", ansiCyan},
		{slog.LevelWarn, "WARN", ansiYellow},
		{slog.LevelError, "ERROR", ansiRed},
	}
	for _, c := range cases {
		if got := levelWord(c.level); got != c.word {
			t.Errorf("levelWord(%v) = %q, want %q", c.level, got, c.word)
		}
		if got := levelColor(c.level); got != c.color {
			t.Errorf("levelColor(%v) = %q, want %q", c.level, got, c.color)
		}
	}
}

// TestNewAttachesComponentAndHandleRendersIt exercises the real
// slog.Logger/Handler path (New + Handle), not just formatLine, so the
// WithAttrs plumbing that carries "component" through to Handle is
// covered, not just the string-formatting helper.
func TestNewAttachesComponentAndHandleRendersIt(t *testing.T) {
	var buf strings.Builder
	h := &handler{w: &buf, level: slog.LevelInfo, color: false, mu: sharedHandler.mu}
	logger := slog.New(h).With(slog.String("component", "ingest"))

	logger.Info("accepted a batch")

	got := buf.String()
	if !strings.Contains(got, "INFO") {
		t.Errorf("expected an INFO line, got %q", got)
	}
	if !strings.Contains(got, "ingest") {
		t.Errorf("expected the component column to show ingest, got %q", got)
	}
	if !strings.Contains(got, "accepted a batch") {
		t.Errorf("expected the message to appear, got %q", got)
	}
}

// TestHandleRendersNonComponentAttrsAfterMessage guards against every
// attr except "component" being silently walked and discarded, so a
// caller like log.Warn(msg, "err", err) always shows the cause.
// component must still select the column and must not also show up in
// the tail.
func TestHandleRendersNonComponentAttrsAfterMessage(t *testing.T) {
	var buf strings.Builder
	h := &handler{w: &buf, level: slog.LevelInfo, color: false, mu: &sync.Mutex{}}
	logger := slog.New(h).With(slog.String("component", "db"))

	logger.Warn("history.keyFile is set but could not be used", "keyFile", "/etc/birdcage/key", "err", "permission denied")

	got := buf.String()
	want := "WARN  db          │ history.keyFile is set but could not be used keyFile=/etc/birdcage/key err=\"permission denied\"\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("Handle() line =\n%q\nwant suffix\n%q", got, want)
	}
	if strings.Count(got, "component=") != 0 {
		t.Errorf("expected component not to also render in the attr tail, got %q", got)
	}
}

// TestHandleOrdersHandlerAttrsBeforeRecordAttrs matches
// slog.TextHandler's convention: attrs attached via With/WithAttrs
// (here, on the *slog.Logger) come first, then attrs passed at the
// call site, in the order each was supplied.
func TestHandleOrdersHandlerAttrsBeforeRecordAttrs(t *testing.T) {
	var buf strings.Builder
	h := &handler{w: &buf, level: slog.LevelInfo, color: false, mu: &sync.Mutex{}}
	logger := slog.New(h).With(slog.String("component", "ingest"), slog.String("reqID", "abc123"))

	logger.Info("closing connection", "reason", "idle", "duration", "30s")

	got := buf.String()
	wantOrder := "reqID=abc123 reason=idle duration=30s"
	if !strings.Contains(got, wantOrder) {
		t.Errorf("expected handler attrs before record attrs in call order, got %q", got)
	}
}

// TestHandleRendersGroupAttrsDotted covers slog.Group: this codebase
// never emits groups itself today, but nothing should crash or
// mis-render if a future caller (or a wrapped library) does.
func TestHandleRendersGroupAttrsDotted(t *testing.T) {
	var buf strings.Builder
	h := &handler{w: &buf, level: slog.LevelInfo, color: false, mu: &sync.Mutex{}}
	logger := slog.New(h).With(slog.String("component", "ingest"))

	logger.Info("purge failed", slog.Group("job", slog.String("id", "42"), slog.Int("attempt", 3)))

	got := buf.String()
	if !strings.Contains(got, "job.id=42 job.attempt=3") {
		t.Errorf("expected dotted group.key=value pairs, got %q", got)
	}
}

// TestHandleQuotesAttrValuesThatWouldBeAmbiguous ensures a value
// containing a space, an "=", or a control character can't run into
// the next token or the newline-per-line invariant the rest of the log
// format relies on.
func TestHandleQuotesAttrValuesThatWouldBeAmbiguous(t *testing.T) {
	var buf strings.Builder
	h := &handler{w: &buf, level: slog.LevelInfo, color: false, mu: &sync.Mutex{}}
	logger := slog.New(h).With(slog.String("component", "db"))

	logger.Warn("vault open failed", "err", "open /var/lib/x: permission denied")

	got := buf.String()
	if !strings.Contains(got, `err="open /var/lib/x: permission denied"`) {
		t.Errorf("expected the space-containing value to be quoted, got %q", got)
	}
}

func TestSetLevelFiltersBelowThreshold(t *testing.T) {
	t.Cleanup(func() { SetLevel("info") })

	var buf strings.Builder
	h := &handler{w: &buf, level: programLevel, color: false, mu: sharedHandler.mu}
	logger := slog.New(h).With(slog.String("component", "test"))

	SetLevel("warn")
	logger.Info("should be filtered out")
	if buf.Len() != 0 {
		t.Errorf("expected Info to be filtered at warn threshold, got %q", buf.String())
	}

	logger.Warn("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("expected Warn to pass at warn threshold, got %q", buf.String())
	}
}

func TestSetLevelUnrecognizedFallsBackToInfo(t *testing.T) {
	t.Cleanup(func() { SetLevel("info") })

	SetLevel("nonsense")
	if programLevel.Level() != slog.LevelInfo {
		t.Errorf("expected an unrecognized level string to fall back to info, got %v", programLevel.Level())
	}
}

func TestSetLevelCaseInsensitiveAndTrimmed(t *testing.T) {
	t.Cleanup(func() { SetLevel("info") })

	SetLevel("  ERROR  ")
	if programLevel.Level() != slog.LevelError {
		t.Errorf("expected case-insensitive/trimmed parsing, got %v", programLevel.Level())
	}
}

func TestHandleIsSafeForConcurrentUse(t *testing.T) {
	var buf strings.Builder
	h := &handler{w: &buf, level: slog.LevelInfo, color: false, mu: &sync.Mutex{}}
	logger := slog.New(h).With(slog.String("component", "concurrent"))

	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			logger.Info("line")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}

	if got := strings.Count(buf.String(), "\n"); got != 20 {
		t.Errorf("expected 20 complete lines with no interleaving corruption, got %d newlines", got)
	}
}

// TestRecoverMustBeDeferredDirectly guards the exact footgun Recover's
// own doc comment warns about: recover() only stops a panic when
// called directly by the function that was itself deferred. Wrapping
// the call in another closure (`defer func() { Recover(logger) }()`)
// looks equivalent but silently doesn't work -- this test would crash
// with an unrecovered panic if Recover (or its calling convention) ever
// regressed to that pattern.
func TestRecoverMustBeDeferredDirectly(t *testing.T) {
	var buf strings.Builder
	h := &handler{w: &buf, level: slog.LevelInfo, color: false, mu: &sync.Mutex{}}
	logger := slog.New(h).With(slog.String("component", "recover-test"))

	func() {
		defer Recover(logger)
		panic("boom")
	}()

	if !strings.Contains(buf.String(), "recovered from panic") {
		t.Errorf("expected a logged recovery, got %q", buf.String())
	}
	if !strings.Contains(buf.String(), "boom") {
		t.Errorf("expected the panic value in the log line, got %q", buf.String())
	}
}

// TestPrintableIsTermEscape proves Printable is exactly
// internal/term.Escape, not a second implementation of it -- see
// Printable's own doc comment for why.
func TestPrintableIsTermEscape(t *testing.T) {
	cases := []string{
		"alice\x1b[2K\rroot",
		"alice\x00",
		"alice‮eslaf",
		"tom@example.com",
		"日本語",
		"",
	}
	for _, s := range cases {
		if got, want := Printable(s), term.Escape(s); got != want {
			t.Errorf("Printable(%q) = %q, want term.Escape's own %q", s, got, want)
		}
	}
}

// TestPrintableNeutralisesTerminalControlSequences proves the practical
// invariant callers rely on: whatever Printable does under the hood, no
// control character or bidirectional-override code point (the Trojan
// Source class, CVE-2021-42574) survives it. Unlike mikroview's own
// Printable, this does not sweep in every Unicode Cf rune -- see
// Printable's doc comment and TestPrintableLeavesZeroWidthJoinerAlone
// below for the one case (the zero-width joiner) where that shows up.
func TestPrintableNeutralisesTerminalControlSequences(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"erase line", "alice\x1b[2K\rroot"},
		{"clear screen", "\x1b[2J"},
		{"cursor move", "\x1b[10;10H"},
		{"newline", "alice\nadmin"},
		{"NUL", "alice\x00"},
		{"RTL override", "alice‮eslaf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Printable(tc.in)
			for _, r := range got {
				if unicode.IsControl(r) {
					t.Fatalf("Printable(%q) = %q, still contains control rune %U", tc.in, got, r)
				}
			}
		})
	}
}

func TestPrintableLeavesOrdinaryTextAlone(t *testing.T) {
	for _, s := range []string{"alice", "tom@example.com", "José", "日本語", "a-b_c.d"} {
		if got := Printable(s); got != s {
			t.Errorf("Printable(%q) = %q, want it unchanged", s, got)
		}
	}
}

// TestPrintableLeavesZeroWidthJoinerAlone documents the one deliberate
// behaviour gap from mikroview's original Printable (see that
// function's doc comment): a ZWJ shapes text (e.g. joining emoji into
// one glyph) rather than reordering or hiding it, so term.Escape -- and
// therefore this alias -- does not treat it as unsafe the way
// mikroview's blanket Cf check did.
func TestPrintableLeavesZeroWidthJoinerAlone(t *testing.T) {
	s := "ali‍ce"
	if got := Printable(s); got != s {
		t.Errorf("Printable(%q) = %q, want the zero-width joiner left alone", s, got)
	}
}

// A bidirectional override in an attribute value must be escaped like
// any other character that would rearrange the operator's terminal.
// strconv.Quote escapes it once quoting is triggered; the check that
// triggers quoting is what this guards, since unicode.IsControl alone
// lets U+202E through untouched.
func TestAttrValueQuotesABidiOverride(t *testing.T) {
	got := quoteAttrValue("host‮evil")
	if strings.Contains(got, "‮") {
		t.Errorf("quoteAttrValue left a bidi override unescaped: %q", got)
	}
}
