package tailer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// openForRead writes content to a fresh file under t.TempDir() and
// returns it open for reading -- the fixture every lineReader test
// starts from.
func openForRead(t *testing.T, content []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path) //nolint:gosec // test fixture, path is our own t.TempDir()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

type collected struct {
	lines     [][]byte
	positions []int64
	rejected  []int64
}

func drain(t *testing.T, r *lineReader) collected {
	t.Helper()
	var c collected
	err := r.fill(func(line []byte, pos int64) {
		// lineReader reuses no backing array across emits (each line's
		// bytes come from a fresh append(nil, ...)), but copy anyway so
		// the test's expectations can't be confused with an aliasing
		// bug in the reader itself.
		cp := append([]byte(nil), line...)
		c.lines = append(c.lines, cp)
		c.positions = append(c.positions, pos)
	}, func(pos int64) {
		c.rejected = append(c.rejected, pos)
	})
	if err != nil {
		t.Fatalf("fill: %v", err)
	}
	return c
}

func TestLineReader_LineAtExactCapAccepted(t *testing.T) {
	const capBytes = 10
	content := bytes.Repeat([]byte("a"), capBytes)
	content = append(content, '\n')
	f := openForRead(t, content)

	r, err := newLineReader(f, 0, capBytes, make([]byte, readChunkSize))
	if err != nil {
		t.Fatalf("newLineReader: %v", err)
	}
	got := drain(t, r)

	if len(got.rejected) != 0 {
		t.Fatalf("rejected = %v, want none (line is exactly at the cap)", got.rejected)
	}
	if len(got.lines) != 1 || string(got.lines[0]) != string(bytes.Repeat([]byte("a"), capBytes)) {
		t.Fatalf("lines = %q, want one %d-byte line", got.lines, capBytes)
	}
	if got.positions[0] != int64(capBytes+1) {
		t.Fatalf("position = %d, want %d", got.positions[0], capBytes+1)
	}
}

func TestLineReader_LineOneOverCapRejectedWithoutBuffering(t *testing.T) {
	const capBytes = 10
	content := bytes.Repeat([]byte("a"), capBytes+1)
	content = append(content, '\n')
	content = append(content, []byte("next\n")...)
	f := openForRead(t, content)

	r, err := newLineReader(f, 0, capBytes, make([]byte, readChunkSize))
	if err != nil {
		t.Fatalf("newLineReader: %v", err)
	}
	got := drain(t, r)

	if len(got.lines) != 1 || string(got.lines[0]) != "next" {
		t.Fatalf("lines = %q, want only the following line %q", got.lines, "next")
	}
	if len(got.rejected) != 1 {
		t.Fatalf("rejected = %v, want exactly one oversize rejection", got.rejected)
	}
	wantRejectPos := int64(capBytes + 1 + 1) // capBytes+1 content bytes, plus the newline
	if got.rejected[0] != wantRejectPos {
		t.Fatalf("reject position = %d, want %d", got.rejected[0], wantRejectPos)
	}
}

func TestLineReader_InvalidUTF8PassesThroughVerbatim(t *testing.T) {
	line := []byte{'{', 0xff, 0xfe, 0x00, '}'}
	content := append(append([]byte(nil), line...), '\n')
	f := openForRead(t, content)

	r, err := newLineReader(f, 0, 64*1024, make([]byte, readChunkSize))
	if err != nil {
		t.Fatalf("newLineReader: %v", err)
	}
	got := drain(t, r)

	if len(got.lines) != 1 || !bytes.Equal(got.lines[0], line) {
		t.Fatalf("lines = %v, want verbatim %v (never interpreted, never rejected for invalid UTF-8)", got.lines, line)
	}
}

func TestLineReader_PartialTrailingLineCompletedOnLaterRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte("first\npart"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })

	r, err := newLineReader(f, 0, 64*1024, make([]byte, readChunkSize))
	if err != nil {
		t.Fatalf("newLineReader: %v", err)
	}
	got := drain(t, r)
	if len(got.lines) != 1 || string(got.lines[0]) != "first" {
		t.Fatalf("first fill: lines = %q, want [\"first\"]", got.lines)
	}
	if !r.hasPending() {
		t.Fatalf("hasPending() = false after a fill ending mid-line, want true")
	}

	// The writer finishes the line later -- append the rest plus the
	// terminating newline, using the same open fd (the lineReader's read
	// cursor and this write cursor are independent; this simulates a
	// second, unrelated writer appending, which is the real shape of
	// OpenCanary continuing to log).
	if _, err := f.WriteAt([]byte("ial\nsecond\n"), 10); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	got2 := drain(t, r)
	if len(got2.lines) != 2 || string(got2.lines[0]) != "partial" || string(got2.lines[1]) != "second" {
		t.Fatalf("second fill: lines = %q, want [\"partial\" \"second\"]", got2.lines)
	}
	if r.hasPending() {
		t.Fatalf("hasPending() = true after both lines completed, want false")
	}
}

func TestLineReader_DiscardPendingDropsUnterminatedLine(t *testing.T) {
	f := openForRead(t, []byte("whole\nleftover-no-newline"))

	r, err := newLineReader(f, 0, 64*1024, make([]byte, readChunkSize))
	if err != nil {
		t.Fatalf("newLineReader: %v", err)
	}
	got := drain(t, r)
	if len(got.lines) != 1 || string(got.lines[0]) != "whole" {
		t.Fatalf("lines = %q, want [\"whole\"]", got.lines)
	}
	if !r.hasPending() {
		t.Fatalf("hasPending() = false, want true (the trailing bytes have no newline)")
	}

	r.discardPending()
	if r.hasPending() {
		t.Fatalf("hasPending() = true after discardPending, want false")
	}
}
