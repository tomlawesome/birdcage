package tailer

import (
	"context"
	"path/filepath"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// Follow is the tailer's entry point. It first catches up -- scanning
// rotated siblings back to resumeFrom before tailing the live file, per
// #48's Durability section -- then follows the live file, calling emit
// for every complete line found either way, until ctx is cancelled.
//
// hasResume distinguishes "resume from resumeFrom" (hasResume true, the
// normal restart case: whatever queue.PositionStore.Load returned)
// from "nothing has ever been acknowledged" (hasResume false: a fresh
// install, mirroring Load's own (pos, ok, err) contract rather than
// overloading the Position zero value, which is itself a valid inode of
// 0 on some filesystems). With hasResume false, catch-up falls back to
// the oldest sibling it can still afford to read within Config's bounds
// -- the same fallback used when resumeFrom's file has rotated beyond
// those bounds -- since #48 requires "0 dropped silently" to hold on
// first start just as much as on restart.
//
// Follow returns only when ctx is done (returning ctx.Err()) or on a
// setup-level failure; every other error this package can encounter --
// the log missing, unreadable, rotating, truncated -- is handled by
// retrying, never by giving up. Surfacing "can't currently read the log"
// to the heartbeat's log-read status is a future caller's job.
func (t *Tailer) Follow(ctx context.Context, resumeFrom queue.Position, hasResume bool, emit func(Line)) (ResumeResult, error) {
	result, r, inode, err := t.catchUp(resumeFrom, hasResume, emit)
	if err != nil {
		return result, err
	}
	return result, t.followLive(ctx, r, inode, emit)
}

// catchUp performs the one-time startup scan and returns the lineReader
// (and its inode) already positioned at the live file's current end, so
// followLive can continue from exactly there without reopening. r is nil
// if the live file did not exist by the time the scan finished --
// followLive's retry-open loop takes over in that case.
func (t *Tailer) catchUp(resumeFrom queue.Position, hasResume bool, emit func(Line)) (ResumeResult, *lineReader, uint64, error) {
	dir := filepath.Dir(t.path)
	base := filepath.Base(t.path)

	// Best-effort: a missing or unreadable directory means nothing to
	// catch up on yet, not fatal -- followLive's retry loop is what
	// actually waits for the log (and its directory) to appear.
	cands, _ := listCandidates(dir, base)

	liveIdx := -1
	for i, c := range cands {
		if c.path == t.path {
			liveIdx = i
			break
		}
	}

	chain, chainStart, positionFound := t.selectChain(cands, liveIdx, resumeFrom, hasResume)

	buf := make([]byte, readChunkSize)

	for i, c := range chain {
		start := int64(0)
		if i == 0 {
			start = chainStart
		}
		t.readWhole(c, start, buf, emit)
	}

	if liveIdx < 0 {
		return ResumeResult{PositionFound: positionFound}, nil, 0, nil
	}

	live := cands[liveIdx]
	liveStart := int64(0)
	if len(chain) == 0 && positionFound {
		// selectChain found the resume position directly on the live
		// file itself -- no rotation happened since the last ack.
		liveStart = resumeFrom.Offset
	}

	f, err := openNoFollow(live.path)
	if err != nil {
		// Vanished between listing and open (benign race with rotation).
		// followLive's own retry-open loop will pick it up from scratch.
		return ResumeResult{PositionFound: positionFound}, nil, 0, nil
	}
	inode, err := fileInode(f)
	if err != nil {
		_ = f.Close()
		return ResumeResult{PositionFound: positionFound}, nil, 0, nil
	}
	lr, err := newLineReader(f, liveStart, t.cfg.MaxLineBytes, buf)
	if err != nil {
		_ = f.Close()
		return ResumeResult{PositionFound: positionFound}, nil, 0, nil
	}
	onReject := func(int64) { t.oversizeLines.Add(1) }
	if err := lr.fill(func(line []byte, pos int64) {
		emit(Line{Data: line, Pos: queue.Position{Inode: inode, Offset: pos}})
	}, onReject); err != nil {
		_ = f.Close()
		return ResumeResult{PositionFound: positionFound}, nil, 0, nil
	}

	return ResumeResult{PositionFound: positionFound}, lr, inode, nil
}

// selectChain decides which rotated siblings (if any) must be read in
// full before the live file, and where the first of them (or the live
// file, if resumeFrom names it directly) should start.
//
// It returns the siblings to read in oldest-first order, the byte offset
// the first of them (chain[0]) should start at (0 for every later one),
// and whether resumeFrom was actually located within Config's bounds. An
// empty chain with positionFound true means resumeFrom names the live
// file itself -- catchUp reads it starting at resumeFrom.Offset rather
// than 0.
func (t *Tailer) selectChain(cands []candidate, liveIdx int, resumeFrom queue.Position, hasResume bool) (chain []candidate, chainStart int64, positionFound bool) {
	siblings := make([]candidate, 0, len(cands))
	for i, c := range cands {
		if i != liveIdx {
			siblings = append(siblings, c)
		}
	}

	if hasResume {
		if liveIdx >= 0 && cands[liveIdx].inode == resumeFrom.Inode && resumeFrom.Offset <= cands[liveIdx].size {
			// No rotation since the last ack: nothing to read before the
			// live file.
			return nil, 0, true
		}
		for i, c := range siblings {
			if c.inode != resumeFrom.Inode || resumeFrom.Offset > c.size {
				continue
			}
			proposed := siblings[i:]
			var rotatedBytes int64
			for j, pc := range proposed {
				if j == 0 {
					rotatedBytes += pc.size - resumeFrom.Offset
				} else {
					rotatedBytes += pc.size
				}
			}
			if len(proposed) <= t.cfg.MaxRotatedFiles && rotatedBytes <= t.cfg.MaxRotatedBytes {
				return proposed, resumeFrom.Offset, true
			}
			// Found, but reading all the way from here would exceed the
			// scan's bounds. Fall through to the oldest-affordable
			// fallback below -- same as "not found at all".
			break
		}
	}

	// Fallback: resumeFrom wasn't found (or there was nothing to look
	// for), or it was found but reading from there exceeds the scan's
	// bounds. Either way, read as far back as MaxRotatedFiles /
	// MaxRotatedBytes still afford, starting from the newest siblings and
	// working backward, then present them oldest-first.
	var kept []candidate
	var keptBytes int64
	for i := len(siblings) - 1; i >= 0 && len(kept) < t.cfg.MaxRotatedFiles; i-- {
		next := keptBytes + siblings[i].size
		if next > t.cfg.MaxRotatedBytes {
			break
		}
		keptBytes = next
		kept = append(kept, siblings[i])
	}
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	return kept, 0, false
}

// readWhole reads candidate c in full, from start to its then-current
// EOF, emitting each complete line and discarding (and counting) any
// unterminated final one -- a rotated sibling will never grow again, so a
// trailing partial line there is dead, not merely pending.
//
// A failure to open or fstat c (vanished, or its inode changed between
// listing and open -- a benign race with rotation or #47's own cleanup at
// the edge of the recovery window) is not fatal to the scan: c is simply
// skipped, on the same reasoning MaxRotatedFiles/MaxRotatedBytes already
// accept -- the recovery window has an inherent edge, and a concurrent
// cleanup race at that edge is within it, not a new failure mode.
func (t *Tailer) readWhole(c candidate, start int64, buf []byte, emit func(Line)) {
	f, err := openNoFollow(c.path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	inode, err := fileInode(f)
	if err != nil || inode != c.inode {
		return
	}

	lr, err := newLineReader(f, start, t.cfg.MaxLineBytes, buf)
	if err != nil {
		return
	}
	_ = lr.fill(func(line []byte, pos int64) {
		emit(Line{Data: line, Pos: queue.Position{Inode: inode, Offset: pos}})
	}, func(int64) {
		t.oversizeLines.Add(1)
	})
	if lr.hasPending() {
		lr.discardPending()
		t.discardedPartial.Add(1)
	}
}
