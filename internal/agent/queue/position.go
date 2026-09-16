package queue

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Position is how far the agent has read OpenCanary's log and birdcage
// has acknowledged everything up to: inode plus byte offset (#48: "The
// position is inode plus offset."). Saving the inode alongside the
// offset is what makes a rotation across a restart detectable -- an
// offset alone can't distinguish a rotated-away file from the live one,
// and the Durability section requires the restart scan to "scan rotated
// siblings back to the acknowledged position before tailing the live
// file", which needs to know which file the offset belongs to.
type Position struct {
	Inode  uint64
	Offset int64
}

// positionRecordLen is the fixed size of the on-disk record: inode (8
// bytes) + offset (8 bytes) + a SHA-256 checksum over those 16 bytes.
// Fixed width plus a checksum is what lets Load tell a whole, genuine
// record apart from a torn or otherwise corrupted one without needing a
// delimiter or parser -- there is exactly one valid length, and exactly
// one valid checksum for whatever bytes are actually at that length.
const positionRecordLen = 8 + 8 + sha256.Size

// encodePosition serialises pos into the fixed-width, checksummed record
// format Save writes and Load verifies.
func encodePosition(pos Position) []byte {
	buf := make([]byte, positionRecordLen)
	binary.BigEndian.PutUint64(buf[0:8], pos.Inode)
	binary.BigEndian.PutUint64(buf[8:16], uint64(pos.Offset))
	sum := sha256.Sum256(buf[0:16])
	copy(buf[16:], sum[:])
	return buf
}

// decodePosition parses buf as a Position record, reporting ok=false for
// anything that isn't a whole, checksum-valid record -- wrong length
// (truncated, or padded by something else entirely) or a checksum
// mismatch (a torn write, or any other corruption). #48 requires both
// cases be treated as "no saved position", never misread as a real one:
// a wrongly-decoded position could skip unacknowledged events instead of
// merely re-reading them, which is the one direction this design must
// never fail toward.
func decodePosition(buf []byte) (pos Position, ok bool) {
	if len(buf) != positionRecordLen {
		return Position{}, false
	}
	sum := sha256.Sum256(buf[0:16])
	if !bytes.Equal(sum[:], buf[16:]) {
		return Position{}, false
	}
	return Position{
		Inode:  binary.BigEndian.Uint64(buf[0:8]),
		Offset: int64(binary.BigEndian.Uint64(buf[8:16])),
	}, true
}

// PositionStore persists the acknowledged Position to a single file.
// Save must be called only once the caller has confirmed birdcage
// acknowledged the events up to that point -- never on mere read -- per
// #48's "Durability" section: saving the read position instead would
// silently lose everything read-but-unacknowledged across a restart
// during a birdcage outage, which is the exact case this file exists to
// cover.
//
// PositionStore is safe for concurrent Save/Load calls from different
// goroutines (each call takes its own consistent view via the
// filesystem, and Save's rename is atomic), but the package brief's
// single-writer model means in practice only the sender goroutine that
// owns acknowledgement ever calls Save.
type PositionStore struct {
	path string
}

// NewPositionStore returns a store backed by path. The directory
// containing path must already exist; Save creates the file itself
// (mode 0600 -- #48: "The token file is unreadable by any other user on
// the box", the same rule applied here to the position file) on first
// use.
func NewPositionStore(path string) *PositionStore {
	return &PositionStore{path: path}
}

// Save atomically persists pos: write a checksummed record to a temp
// file in the same directory as path, fsync the temp file's contents,
// rename it over path, then fsync the directory so the rename itself is
// durable. A same-directory temp file keeps source and destination on
// one filesystem, which is what makes the rename atomic rather than a
// copy; fsyncing the directory closes the remaining window where a
// crash could leave a completed rename not yet durable on disk.
//
// On any failure before the rename, path is left completely untouched --
// the previous saved position (or its absence) stands, and the caller
// re-saves on its own retry cadence. #48's fail-closed rule for this
// path: "Acknowledged position unwritable ... keep forwarding, report
// it; on restart, re-read from the last written position."
func (s *PositionStore) Save(pos Position) error {
	dir := filepath.Dir(s.path)

	tmp, err := os.CreateTemp(dir, ".position-*.tmp")
	if err != nil {
		return fmt.Errorf("queue: create temp position file: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup on any early return. Once the rename below
	// succeeds, tmpPath no longer exists under this name and Remove
	// fails with "not exist", which is expected and not worth reporting --
	// the rename already did the job Remove would have.
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("queue: chmod temp position file: %w", err)
	}
	if _, err := tmp.Write(encodePosition(pos)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("queue: write temp position file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("queue: fsync temp position file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("queue: close temp position file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("queue: rename position file: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("queue: fsync position directory: %w", err)
	}
	return nil
}

// syncDir fsyncs a directory's own metadata (e.g. the rename that just
// landed in it) rather than any file inside it.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Load reads the last saved Position. ok is false, with err nil, both
// when nothing has ever been saved and when the file on disk cannot be
// read back as a single whole record (see decodePosition) -- #48 treats
// a torn or truncated position file as "no saved position", not a
// misread one, so callers should react to ok==false exactly as they
// would to a fresh install: replay the log from the start (or from
// whatever earlier bound the caller independently tracks), never guess.
// A non-nil err is reserved for filesystem trouble other than "the file
// doesn't exist" (permissions, I/O errors), which the caller should
// report rather than silently treat as "no position".
func (s *PositionStore) Load() (pos Position, ok bool, err error) {
	buf, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Position{}, false, nil
	}
	if err != nil {
		return Position{}, false, fmt.Errorf("queue: read position file: %w", err)
	}
	pos, valid := decodePosition(buf)
	if !valid {
		return Position{}, false, nil
	}
	return pos, true, nil
}
