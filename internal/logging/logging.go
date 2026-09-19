// SPDX-License-Identifier: AGPL-3.0-only

// Package logging is birdcage's server-side log formatting: leveled,
// colorized (auto-disabled off a TTY or with NO_COLOR set), with a
// stable component column so a scrolling terminal or `docker logs` stays
// scannable. Built on log/slog rather than a third-party logging
// library, matching the rest of the codebase's near-zero-dependency
// posture (see go.mod). Ported from mikroview's own internal/logging
// (issue #71), which has run this exact line shape in production; only
// the wordmark and the terminal-detection call underneath colorEnabled
// changed (see that function's doc comment for why).
//
// Shared by both of this repository's binaries: cmd/birdcage takes the
// full leveled-log-plus-banner-plus-boot-inventory treatment, cmd/
// mockingbird uses only the leveled logger (component loggers, SetLevel,
// Recover) and deliberately never calls PrintBanner or logs a
// configuration inventory -- see cmd/mockingbird's own package doc for
// why: it runs on the honeypot, where a boot inventory would hand an
// attacker exactly the operational detail (state directory, log path,
// listen address) this package's callers must never print.
//
// Not used for CLI recovery/administration command output (`birdcage
// canary list`, `birdcage settings get`, etc.) -- those print directly
// to stdout via internal/term.Escape for scripting/piping, not through
// this leveled path.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/tomlawesome/birdcage/internal/term"
)

// componentWidth is the padded width of the component column, sized to
// the longest of this repository's own runtime components (e.g.
// "heartbeat", "ingest-tls") without truncating -- a rare longer
// component just doesn't align as neatly, rather than ever cutting a
// name short.
const componentWidth = 11

// programLevel is shared by every logger returned from New -- SetLevel
// adjusts it once, at startup, from each binary's own environment
// variable (BIRDCAGE_LOG_LEVEL, MOCKINGBIRD_LOG_LEVEL -- see
// docs/configuration.md). A slog.LevelVar rather than a plain field so
// every already-created component logger picks up the change without
// needing to be re-created.
var programLevel = new(slog.LevelVar)

// stdoutWriter writes to whatever os.Stdout currently refers to, rather
// than latching the *os.File package-level var initialization captures
// -- a plain `w: os.Stdout` field would read that pointer once, at
// package init, before any test (or a future caller) has a chance to
// redirect it. This is what lets a test reassign the os.Stdout package
// variable (the same os.Pipe technique cmd/birdcage's own CLI tests use,
// e.g. cmd/birdcage/canary_test.go's captureStdout) and capture a
// component logger's own output too, without this package needing a
// bespoke SetOutput/restore API of its own.
type stdoutWriter struct{}

func (stdoutWriter) Write(p []byte) (int, error) {
	return os.Stdout.Write(p)
}

var sharedHandler = &handler{
	w:     stdoutWriter{},
	level: programLevel,
	color: colorEnabled(),
	mu:    &sync.Mutex{},
}

// colorEnabled follows the NO_COLOR convention (https://no-color.org)
// and auto-disables when stdout isn't a terminal (piped to a file, a
// log collector, `docker logs | grep`, etc.) -- ANSI escapes in that
// case would just show up as literal garbage, not color.
//
// Terminal detection uses os.ModeCharDevice rather than
// golang.org/x/term (mikroview's own choice) or github.com/mattn/
// go-isatty: neither is part of this module's current build list (see
// go.mod), and this repository's dependency policy is not to add one
// for something the standard library already answers -- a regular file
// or a pipe's Stat().Mode() never carries os.ModeCharDevice, only an
// actual tty/pty does.
func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// New returns a logger tagged with component -- component renders in
// its own column (see handler.Handle) rather than as a prefix baked
// into every message string, so callers write plain messages the way
// they always did with log.Printf.
func New(component string) *slog.Logger {
	return slog.New(sharedHandler).With(slog.String("component", component))
}

// Recover must be deferred directly -- `defer logging.Recover(logger)`
// -- never wrapped in another closure (`defer func() {
// logging.Recover(logger) }()` looks equivalent but is a real, common
// Go footgun: recover() only stops a panic when called directly by the
// function that was itself deferred. One layer of closure in between
// means recover() is no longer being called "directly" by the deferred
// call, so it returns nil and the panic keeps propagating exactly as
// if this were never called at all -- silently, since nothing about it
// looks wrong until it's actually exercised by a real panic. Logs and
// swallows an in-flight panic instead of letting it propagate.
//
// Go gives no default containment for a panic in a goroutine: only
// net/http's own per-request goroutine gets an automatic recover, and
// that protection doesn't extend to any goroutine spawned from within a
// handler, let alone this repository's independently-started
// long-running goroutines (birdcage's HTTP API server and HTTPS ingest
// listener; mockingbird's receiver, log tailer, sender, heartbeat,
// command poll/runner, token rotation, and OpenCanary child supervisor).
// An unrecovered panic in any one of them takes down the entire process
// -- not just the subsystem it happened in. Call this at the smallest
// unit of work a goroutine repeats (once per request/event/connection,
// not once for the goroutine's entire lifetime) so a single bad input
// degrades that one unit of work rather than silently ending the
// goroutine for good.
func Recover(logger *slog.Logger) {
	if r := recover(); r != nil {
		// Baked into the message rather than passed as a "stack" attr:
		// appendAttr (below) quotes any value containing a control
		// character, which a multi-line stack trace always does, and
		// a quoted, escaped stack trace is far less readable than one
		// printed as-is.
		logger.Error(fmt.Sprintf("recovered from panic: %v\n%s", r, debug.Stack()))
	}
}

// SetLevel parses one of debug/info/warn/error (case-insensitive) and
// applies it to every logger returned from New, past and future.
// Anything unrecognized (a typo, an empty string) falls back to info
// silently, matching how every other malformed config/env value in
// this codebase degrades rather than failing startup over a log
// setting.
func SetLevel(s string) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		programLevel.Set(slog.LevelDebug)
	case "warn", "warning":
		programLevel.Set(slog.LevelWarn)
	case "error":
		programLevel.Set(slog.LevelError)
	default:
		programLevel.Set(slog.LevelInfo)
	}
}

// handler implements slog.Handler directly rather than customizing
// slog.NewTextHandler -- the target line shape (a fixed-column
// component field and a │ separator before the message, with any
// other attrs trailing the message as key=value pairs) isn't something
// TextHandler's ReplaceAttr hook can produce.
type handler struct {
	w     io.Writer
	level slog.Leveler
	color bool
	attrs []slog.Attr
	mu    *sync.Mutex
}

func (h *handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	component := "birdcage"
	var tail strings.Builder

	// Handler-level attrs (WithAttrs, in practice just New's
	// "component") come first, then the record's own -- the same order
	// slog.TextHandler uses, so a caller that does
	// logger.With("reqID", id).Warn(msg, "err", err) sees reqID before
	// err.
	for _, a := range h.attrs {
		if a.Key == "component" {
			component = a.Value.String()
			continue
		}
		appendAttr(&tail, "", a)
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "component" {
			component = a.Value.String()
			return true
		}
		appendAttr(&tail, "", a)
		return true
	})

	line := formatLine(r.Time.Format("15:04:05"), r.Level, component, r.Message, tail.String(), h.color)

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line)
	return err
}

// appendAttr renders a into sb as a space-separated "key=value" token,
// space-prefixed unless sb is still empty. slog.Group attrs recurse
// with their key dotted onto prefix (birdcage.reason.code, not a
// second nesting syntax) -- an empty-keyed group (slog.Group("", ...),
// which slog treats as "inline these at the parent level") passes
// prefix through unchanged rather than adding a leading dot.
func appendAttr(sb *strings.Builder, prefix string, a slog.Attr) {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		childPrefix := prefix
		if a.Key != "" {
			if prefix != "" {
				childPrefix = prefix + "." + a.Key
			} else {
				childPrefix = a.Key
			}
		}
		for _, ga := range v.Group() {
			appendAttr(sb, childPrefix, ga)
		}
		return
	}
	if a.Key == "" {
		// Matches slog.TextHandler: an empty key with a non-group value
		// has nothing to label it with, so it's dropped rather than
		// printed as a bare "=value".
		return
	}
	key := a.Key
	if prefix != "" {
		key = prefix + "." + key
	}
	if sb.Len() > 0 {
		sb.WriteByte(' ')
	}
	sb.WriteString(key)
	sb.WriteByte('=')
	sb.WriteString(quoteAttrValue(v.String()))
}

// quoteAttrValue wraps s in Go-quoted form when it contains anything
// that would make the rendered "key=value" token ambiguous or unsafe
// to print -- a space or "=" would run into the next token or the
// separator, and a control character (e.g. a stray newline inside an
// error message) would otherwise break the one-line-per-record
// invariant every other reader of this log format relies on.
func quoteAttrValue(s string) string {
	if s == "" {
		return `""`
	}
	// unsafeForTerminal, not unicode.IsControl: a right-to-left
	// override in an attribute value would reorder the rest of the line
	// in the operator's terminal without being a control character. An
	// attribute can carry a canary id or a fragment of an OpenCanary
	// event, so the value is not always ours.
	needsQuote := strings.ContainsAny(s, " \"=") || strings.ContainsFunc(s, unsafeForTerminal)
	if !needsQuote {
		return s
	}
	return strconv.Quote(s)
}

// WithAttrs stores attrs (in practice, just the "component" attr New
// attaches) so Handle can read them back per record -- a plain slice
// append rather than baking them into a pre-rendered prefix, since
// nothing else in this handler needs generic attr support.
func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *h
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	n.attrs = merged
	return &n
}

// WithGroup is a no-op: this package never groups attrs (component is
// the only one, added via New), so there's nothing to namespace.
func (h *handler) WithGroup(_ string) slog.Handler {
	return h
}

const (
	ansiReset  = "\x1b[0m"
	ansiDim    = "\x1b[90m"
	ansiCyan   = "\x1b[36m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
)

func levelWord(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "ERROR"
	case level >= slog.LevelWarn:
		return "WARN"
	case level >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

func levelColor(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return ansiRed
	case level >= slog.LevelWarn:
		return ansiYellow
	case level >= slog.LevelInfo:
		return ansiCyan
	default:
		return ansiDim
	}
}

// formatLine renders "HH:MM:SS LEVEL  component │ message key=value
// ...\n" -- the gaps after INFO/WARN and after short component names
// are the level/column padding lining up with ERROR and the longest
// common component name, not stray whitespace. attrs is already a
// fully space-joined "key=value key2=value2" tail (see appendAttr) or
// "" when the record carried no attrs beyond component; either way it
// never gets its own color treatment, matching the plain message.
func formatLine(ts string, level slog.Level, component, message, attrs string, color bool) string {
	levelToken := fmt.Sprintf("%-5s", levelWord(level))
	componentToken := fmt.Sprintf("%-*s", componentWidth, component)
	if attrs != "" {
		message = message + " " + attrs
	}

	if !color {
		return fmt.Sprintf("%s %s %s │ %s\n", ts, levelToken, componentToken, message)
	}

	return fmt.Sprintf(
		"%s%s%s %s%s%s %s%s%s %s│%s %s\n",
		ansiDim, ts, ansiReset,
		levelColor(level), levelToken, ansiReset,
		ansiDim, componentToken, ansiReset,
		ansiDim, ansiReset,
		message,
	)
}

// Printable renders s safe to write to an operator's terminal.
//
// This repository already has this exact protection as
// internal/term.Escape, used directly by cmd/birdcage's own CLI output
// (canary.go, settings.go print stored values -- canary and token ids
// -- through it). Rather than duplicate that control-character/bidi-
// override logic a second time the way mikroview's own Printable did,
// this is a thin alias onto it, kept under this package's own name so a
// leveled-log caller reaches for the same Printable name mikroview's
// did without needing to import internal/term directly.
//
// term.Escape covers every control character and the specific
// bidirectional-override code points behind the Trojan Source class
// (CVE-2021-42574) -- exactly the threat mikroview's own Printable doc
// comment describes. It is narrower in one respect: mikroview's
// original treated every Unicode Cf ("format") rune as unsafe, which
// also catches things like the zero-width joiner (U+200D) that shape
// text (emoji sequences, some scripts) without reordering or hiding
// anything -- not a terminal-safety issue by term.Escape's own,
// CVE-scoped threat model, so those pass through unchanged here where
// mikroview's blanket Cf check would have replaced them too. See
// internal/term.Escape's own doc comment for the full threat model
// (CVE-2025-55754, CVE-2025-48432, CVE-2021-42574) this alias inherits.
func Printable(s string) string {
	return term.Escape(s)
}

// unsafeForTerminal is quoteAttrValue's own test for whether an attr
// value needs Go-quoting -- unrelated to Printable/term.Escape above,
// which fully neutralizes a string for direct terminal output rather
// than just deciding whether to wrap it in quotes within a structured
// key=value token.
func unsafeForTerminal(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError
}
