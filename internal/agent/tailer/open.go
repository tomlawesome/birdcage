package tailer

import (
	"fmt"
	"os"
	"syscall"
)

// openNoFollow opens path read-only, refusing to follow a symlink at the
// final path component. #48, "What the research changed" #3: "Log files
// and rotated siblings are opened O_NOFOLLOW" -- the log directory is
// owned by #47's deploy script, not this agent, and any local uid can
// share the box (#48 threat model); O_NOFOLLOW is what stops a symlink
// planted at the log path or a rotated name from redirecting a read
// somewhere the agent was never meant to look.
func openNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// fileInode returns f's inode, the identity half of queue.Position. Read
// from the open file descriptor (fstat), never from the path (stat) --
// the fd's identity can't be raced by a rename or a replace happening
// after open, which is exactly the distinction Position exists to make.
func fileInode(f *os.File) (uint64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("tailer: no inode available for %s (unsupported platform)", f.Name())
	}
	return st.Ino, nil
}

// lstatInode is fileInode's counterpart for a path that is not (yet)
// open -- used only for the best-effort candidate discovery in scan.go,
// never as the authoritative check for a read. Lstat, not Stat: a
// symlink is reported as itself rather than followed, so the caller can
// skip it before ever trying to open it.
func lstatInode(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ino, true
}

// sameInode reports whether fi (from an Lstat of a path) names the same
// file as inode (from an already-open fd's fstat). A stat that can't
// yield an inode is treated as "different" -- the conservative direction,
// since it costs at most one extra reopen, while treating it as "same"
// could paper over a real rotation.
func sameInode(fi os.FileInfo, inode uint64) bool {
	ino, ok := lstatInode(fi)
	return ok && ino == inode
}
