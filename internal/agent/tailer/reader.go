package tailer

import (
	"bytes"
	"errors"
	"io"
	"os"
)

// readChunkSize is how much lineReader.fill asks the kernel for on each
// Read. It bounds nothing security-relevant by itself -- maxLine does
// that -- it just keeps one read syscall's worth of data small and
// reusable across polls.
const readChunkSize = 32 * 1024

// lineReader incrementally parses newline-delimited lines out of a file,
// tracking exactly how many bytes have been consumed (offset) so the
// caller can compute the queue.Position that follows each line.
//
// It never buffers more than maxLine bytes building one candidate line,
// regardless of how long a hostile or corrupted line actually is on disk:
// once the in-progress line's length would exceed maxLine, lineReader
// stops accumulating it (oversize becomes true) and merely scans further
// bytes for the terminating newline, discarding them as it goes (#48,
// "What the research changed" #3: "a log line over a fixed cap ... is
// rejected without buffering it all"). A partial line with no newline yet
// is held in cur (or just tracked by oversize) across calls to fill --
// exactly the state a live file's not-yet-complete final line needs, and
// exactly what a finished file's genuinely-truncated final line needs
// discarding via discardPending.
type lineReader struct {
	f       *os.File
	maxLine int
	buf     []byte // reusable read-chunk buffer, sized readChunkSize
	offset  int64  // bytes of f resolved into an emitted/rejected line, or held pending in cur

	cur      []byte // bytes collected so far for the in-progress line; nil once oversize
	oversize bool   // true once the in-progress line has exceeded maxLine
}

// newLineReader seeks f to start and returns a lineReader positioned to
// read from there. buf is reused as the read-chunk buffer; passing the
// same slice in across a reopen (e.g. after in-place truncation, where f
// itself is unchanged) avoids a reallocation.
func newLineReader(f *os.File, start int64, maxLine int, buf []byte) (*lineReader, error) {
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	return &lineReader{f: f, maxLine: maxLine, buf: buf, offset: start}, nil
}

// fill reads whatever is currently available from f and feeds it through
// the line state machine, calling emit(line, pos) for each complete line
// at or under maxLine and onReject(pos) for each complete line over it.
// pos is the queue.Position offset immediately following that line
// (including its newline), i.e. where a resume should continue from.
//
// fill returns when f is (currently) exhausted: a regular file's Read
// returns io.EOF with nothing further to report, which is not an error
// here, just "no more data right now" -- a live file may grow and have
// more later, a dead one won't, and telling those apart is the caller's
// job (see followLive and catchUp). fill never blocks waiting for more
// bytes to appear: each Read on a regular file returns immediately, so a
// partial final line never blocks this call, satisfying #48's "never
// block forever on a partial final line".
func (r *lineReader) fill(emit func(line []byte, pos int64), onReject func(pos int64)) error {
	for {
		n, err := r.f.Read(r.buf)
		if n > 0 {
			r.feed(r.buf[:n], emit, onReject)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

// feed resolves as many complete lines out of chunk as it can, advancing
// offset by exactly len(chunk) (chunk is always a contiguous, already-read
// slice of the file starting at the old offset).
func (r *lineReader) feed(chunk []byte, emit func(line []byte, pos int64), onReject func(pos int64)) {
	for len(chunk) > 0 {
		nl := bytes.IndexByte(chunk, '\n')
		var take []byte
		var consumed int
		if nl >= 0 {
			take = chunk[:nl]
			consumed = nl + 1
		} else {
			take = chunk
			consumed = len(chunk)
		}

		if !r.oversize {
			room := r.maxLine - len(r.cur)
			if len(take) <= room {
				r.cur = append(r.cur, take...)
			} else {
				// This line would exceed maxLine. Stop accumulating it --
				// the whole point is to never hold an oversize line in
				// memory -- and remember only that it is oversize, so the
				// bytes still to come (on this call or later ones) are
				// scanned for the newline and discarded, not appended.
				r.oversize = true
				r.cur = nil
			}
		}
		r.offset += int64(consumed)

		if nl >= 0 {
			if r.oversize {
				onReject(r.offset)
				r.oversize = false
			} else {
				line := r.cur
				r.cur = nil
				emit(line, r.offset)
			}
		}
		chunk = chunk[consumed:]
	}
}

// hasPending reports whether an in-progress line (complete or oversize,
// but not yet newline-terminated) is being held.
func (r *lineReader) hasPending() bool {
	return len(r.cur) > 0 || r.oversize
}

// discardPending drops any in-progress line. Call this when the file it
// came from is known dead -- rotated away, or truncated out from under
// the reader -- so a final unterminated line can never masquerade as a
// complete one on the next fill. It is never a complete event (nothing
// hashes an unterminated line), so there is nothing to report except that
// it happened; the caller counts it.
func (r *lineReader) discardPending() {
	r.cur = nil
	r.oversize = false
}
