package tailer

import (
	"context"
	"os"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// followLive tails the live file, starting from r (already positioned at
// its current end by catchUp) and inode, until ctx is done. r may be nil
// if the live file did not exist when catchUp finished; the loop below
// opens it once it appears.
//
// Every condition #48 requires this package to handle -- rotation,
// truncation, replacement by a new inode, brief absence -- is a case in
// the switch below, and every one of them resolves to "keep trying",
// never to returning an error: only ctx being done ends this loop.
func (t *Tailer) followLive(ctx context.Context, r *lineReader, inode uint64, emit func(Line)) error {
	defer func() {
		if r != nil {
			_ = r.f.Close()
		}
	}()

	onEmit := func(line []byte, pos int64) {
		emit(Line{Data: line, Pos: queue.Position{Inode: inode, Offset: pos}})
	}
	onReject := func(int64) { t.oversizeLines.Add(1) }

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if r == nil {
			// Absent: OpenCanary hasn't been deployed yet, the log hasn't
			// been created yet, or it's mid-rotation. Retry on the poll
			// cadence rather than treating this as fatal (#48 fail-closed:
			// "the heartbeat's log-read status says so ... Never silent" --
			// a caller concern, not a reason for this loop to give up).
			nf, err := openNoFollow(t.path)
			if err != nil {
				if err := t.sleep(ctx); err != nil {
					return err
				}
				continue
			}
			ino, err := fileInode(nf)
			if err != nil {
				_ = nf.Close()
				if err := t.sleep(ctx); err != nil {
					return err
				}
				continue
			}
			nr, err := newLineReader(nf, 0, t.cfg.MaxLineBytes, make([]byte, readChunkSize))
			if err != nil {
				_ = nf.Close()
				if err := t.sleep(ctx); err != nil {
					return err
				}
				continue
			}
			r, inode = nr, ino
			onEmit = func(line []byte, pos int64) {
				emit(Line{Data: line, Pos: queue.Position{Inode: inode, Offset: pos}})
			}
		}

		if err := r.fill(onEmit, onReject); err != nil {
			// Unexpected I/O error on an already-open fd -- rare on
			// Linux (e.g. the underlying device vanished). Not one of
			// the documented recoverable cases specifically, but the
			// same response applies: close, retry from scratch, never
			// give up.
			_ = r.f.Close()
			r = nil
			if err := t.sleep(ctx); err != nil {
				return err
			}
			continue
		}

		st, statErr := os.Lstat(t.path)
		switch {
		case statErr != nil:
			// Briefly absent: the rename-then-create window of a
			// rotation, or a deletion that may yet be replaced. Keep the
			// old fd open -- still fully readable up to its own EOF --
			// and check again next poll.
		case !sameInode(st, inode):
			// Rotated (or replaced by a new inode at the same path).
			// Drain whatever final bytes the old fd still has -- written
			// before rotation, not yet read -- before switching.
			_ = r.fill(onEmit, onReject)
			if r.hasPending() {
				r.discardPending()
				t.discardedPartial.Add(1)
			}
			_ = r.f.Close()
			r = nil
			continue // reopen the new file immediately, no need to wait out a poll
		default:
			if fi, err := r.f.Stat(); err == nil && fi.Size() < r.offset {
				// Truncated in place (defence in depth -- #47's policy is
				// rotate-by-rename, never copytruncate, but a hostile or
				// misbehaving writer could still shrink the file under
				// us). The old offset can't be trusted against whatever
				// is there now, so restart this same fd from 0; any line
				// re-sent that was already acknowledged is a dedup no-op
				// downstream, which is always safer than skipping.
				r.discardPending()
				t.discardedPartial.Add(1)
				nr, err := newLineReader(r.f, 0, t.cfg.MaxLineBytes, r.buf)
				if err != nil {
					_ = r.f.Close()
					r = nil
					continue
				}
				r = nr
				continue
			}
		}

		if err := t.sleep(ctx); err != nil {
			return err
		}
	}
}

// sleep waits out one PollInterval, returning early with ctx's error if
// ctx is cancelled first -- the only way this loop, and therefore
// Follow, ever stops before a fatal setup error.
func (t *Tailer) sleep(ctx context.Context) error {
	timer := time.NewTimer(t.cfg.PollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
