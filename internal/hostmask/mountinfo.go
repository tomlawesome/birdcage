package hostmask

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Mount is the subset of one /proc/self/mountinfo line (proc(5)) this
// package needs: where it is mounted, and whether it is read-only.
// mountinfo's own escaping (spaces, tabs, newlines and backslashes in a
// path are octal-escaped, e.g. "\040" for a space) is undone by
// ParseMountinfo before this struct is built, so callers never see an
// escaped path.
type Mount struct {
	MountPoint string
	ReadOnly   bool
}

// ParseMountinfo parses /proc/self/mountinfo's own format. Each line has
// a fixed prefix (mount ID, parent ID, major:minor, root, mount point,
// per-mount options), zero or more optional fields, a literal "-"
// separator, then filesystem type, mount source and per-superblock
// options -- this package reads only the mount point (field 5) and the
// per-mount options (field 6, before the optional fields): that is
// where Docker's own `--tmpfs foo:ro` and `-v host:container:ro` show up
// as "ro", which is the flag both checks in Check below rely on.
//
// A line that does not have at least six fields is skipped rather than
// treated as a parse error: mountinfo is kernel-generated, not
// attacker-controlled input this package must validate strictly, and a
// short line here would only mean a kernel/format this package has not
// seen -- failing the whole read over one unparseable line would turn a
// forward-compatible kernel change into a scan-blocking bug, the
// opposite of this package's own fail-closed intent (its job is to
// refuse when a mask is missing, not when its own parser is surprised).
func ParseMountinfo(r io.Reader) ([]Mount, error) {
	var mounts []Mount
	scanner := bufio.NewScanner(r)
	// Generous per-line cap: /proc/self/mountinfo is kernel-generated,
	// but a container with an unusually deep mount table (many
	// overlayfs layers) can still produce long lines, and bufio.Scanner's
	// own 64 KiB default has been hit by real overlay stacks elsewhere in
	// this project's tooling.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		mounts = append(mounts, Mount{
			MountPoint: unescapeMountinfo(fields[4]),
			ReadOnly:   isReadOnly(fields[5]),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("hostmask: read mountinfo: %w", err)
	}
	return mounts, nil
}

// isReadOnly reports whether opts (mountinfo's comma-separated
// per-mount option field) contains "ro".
func isReadOnly(opts string) bool {
	for _, o := range strings.Split(opts, ",") {
		if o == "ro" {
			return true
		}
	}
	return false
}

// unescapeMountinfo undoes mountinfo's own octal escaping of space, tab,
// newline and backslash in a path field (kernel fs/seq_file.c,
// mangle()). Any other "\NNN" sequence is left as-is rather than
// guessed at.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
