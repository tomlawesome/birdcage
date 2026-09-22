package hostmask

import (
	"fmt"
	"strings"
)

// CheckFailure is the concrete reason Check refused, letting a caller
// build a reason string without re-deriving what went wrong.
type CheckFailure struct {
	// Path is the offending host mount point under root, e.g.
	// "/host/etc/ssh" -- always an absolute path under root, never a
	// bare mask path, so the failure names exactly what a `mount` command
	// on the running container would show.
	Path string
	// NotCovered is true when Path is a mask-list entry that exists
	// under root but has no mount covering it; false when Path is a
	// mount under root that is not read-only.
	NotCovered bool
	// RootMissing is true when root itself is not a mount point at all
	// -- see Check's own doc comment, point 0.
	RootMissing bool
}

func (f *CheckFailure) Error() string {
	switch {
	case f.RootMissing:
		return fmt.Sprintf("hostmask: %s is not mounted at all -- the run command's -v /:%s:ro flag is missing", f.Path, f.Path)
	case f.NotCovered:
		return fmt.Sprintf("hostmask: %s exists but is not covered by a mount", f.Path)
	default:
		return fmt.Sprintf("hostmask: mount %s is not read-only", f.Path)
	}
}

// Check is the agent-side half of issue #108's host-mount decision
// ("The covering is enforced by the agent, not only by the run
// command"): given root (Nightjar always calls this with "/host"), the
// mounts currently in effect (ParseMountinfo's own output) and exists
// (os.Stat-backed in production; a fixture map in tests), it requires
// all of:
//
//  0. root itself is a mount point. Without this, an operator who
//     dropped `-v /:/host:ro` from the run command entirely would sail
//     through both checks below with nothing to fail on -- no mask path
//     would "exist" under an empty/absent root, and no mount would be
//     found under root to flag as writable -- and Grype would then walk
//     an empty directory and report a clean scan it did not earn
//     (exactly what ADR-0010 decision 8 exists to prevent).
//  1. every Masks entry that exists under root is covered by some mount
//     at exactly its host mount point -- a mask over a path the host
//     does not have is not a failure (the run command's own printed
//     flag would already have refused to start the container in that
//     case; see cmd/birdcage's renderer doc comment), but a path that
//     does exist and is NOT covered means the run command was edited
//     and the covering silently lost;
//  2. every mount under root is read-only -- the backstop for engines
//     older than Docker 25, where `ro` on a root bind is not recursive
//     and a host submount (a separate /home partition, /boot, /run) can
//     stay writable underneath /host even though the top-level bind
//     itself reports ro.
//
// The first failure found is returned as a *CheckFailure, in Masks'
// declaration order for the coverage check and mounts' own order for
// the read-only check -- deterministic, so the same broken state always
// names the same path first. A nil error means the covering holds and
// the caller may scan.
func Check(root string, mounts []Mount, exists func(path string) bool) error {
	covered := make(map[string]bool, len(mounts))
	for _, m := range mounts {
		covered[m.MountPoint] = true
	}

	if !covered[root] {
		return &CheckFailure{Path: root, RootMissing: true}
	}

	for _, mk := range Masks {
		hp := HostMountPoint(mk, root)
		if !exists(hp) {
			// Legitimately absent on this host -- the operator already
			// dropped this flag from the run command (the "mask over a
			// path that does not exist" trap), or it never existed here.
			// Nothing to cover.
			continue
		}
		if !covered[hp] {
			return &CheckFailure{Path: hp, NotCovered: true}
		}
	}

	prefix := strings.TrimRight(root, "/") + "/"
	for _, m := range mounts {
		if m.MountPoint != root && !strings.HasPrefix(m.MountPoint, prefix) {
			continue
		}
		if !m.ReadOnly {
			return &CheckFailure{Path: m.MountPoint}
		}
	}

	return nil
}
