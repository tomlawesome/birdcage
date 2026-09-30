package tailer

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// candidate is one file found in the log's directory that might be the
// live log or one of its rotated siblings, as of one directory listing.
// It is discovery metadata only -- inode included -- never the
// authoritative identity for a read; the actual read reopens the path
// with O_NOFOLLOW and re-checks its fd's own inode (see catchUp).
type candidate struct {
	path  string
	inode uint64
	size  int64
	mtime time.Time
}

// listCandidates returns every regular, non-symlink file in dir whose
// name is exactly base or begins with base, oldest mtime first.
//
// #47 owns the rotation policy -- "size-based, keeping enough to cover
// the stated recovery window" -- but not its naming grammar: issue #48
// does not fix whether rotated siblings get a numeric suffix, a date
// suffix, compression, or something else, and no such convention exists
// elsewhere in this repo (nothing under #47's namespace has been built
// yet). Matching by shared name prefix and ordering by mtime is
// deliberately agnostic to whatever suffix grammar #47's deploy script
// ends up using, as long as rotation renames within the same directory
// rather than moving files elsewhere -- which the Durability section
// already requires ("rotate by rename, never copytruncate").
//
// Symlinks are skipped outright here; this is candidate discovery, not
// the trust boundary. The real defence against a symlink at a rotated
// name is openNoFollow at actual read time.
func listCandidates(dir, base string) ([]candidate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var out []candidate
	for _, entry := range entries {
		name := entry.Name()
		if name != base && !strings.HasPrefix(name, base) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			// Vanished between ReadDir and Info (benign race with
			// rotation or cleanup); just not a candidate this scan.
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		inode, ok := lstatInode(info)
		if !ok {
			continue
		}
		out = append(out, candidate{
			path:  filepath.Join(dir, name),
			inode: inode,
			size:  info.Size(),
			mtime: info.ModTime(),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if !out[i].mtime.Equal(out[j].mtime) {
			return out[i].mtime.Before(out[j].mtime)
		}
		return out[i].path < out[j].path // deterministic tie-break
	})
	return out, nil
}
