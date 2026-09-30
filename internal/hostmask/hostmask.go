// Package hostmask is the single shared record of which host paths
// Nightjar's read-only root mount (`-v /:/host:ro`) covers over, and the
// startup check that proves the covering actually took effect.
//
// It exists so the printed run command (cmd/birdcage's enrol renderer)
// and the running check (cmd/nightjar, before every scan) cannot drift:
// both read Masks from here rather than each keeping its own copy. The
// owner's ratified path list and the reasoning behind it are recorded on
// issue #108 (the "second opinion on the host mount" comment,
// 2026-09-22) -- this package is that decision expressed in code, not a
// place to re-derive it.
//
// This is a leaf package: it imports nothing else of birdcage's, so it
// sits alongside internal/agentkind in scripts/agent-deps-check.sh's
// shared-plumbing set and is importable by cmd/birdcage (the server
// binary, unfenced) and by cmd/nightjar (fenced to its own allowed set)
// alike, with nothing for either side to disagree about.
package hostmask

import "path/filepath"

// Kind is whether a masked path is a single file (bound over with
// /dev/null) or a directory (covered with a read-only tmpfs).
type Kind int

const (
	// File paths are bound over with /dev/null: `-v /dev/null:<mount>:ro`.
	File Kind = iota
	// Dir paths are covered with a read-only tmpfs: `--tmpfs <mount>:ro`.
	Dir
)

// Mask is one host path the run command covers over.
type Mask struct {
	// Path is the absolute path on the host, e.g. "/etc/shadow".
	Path string
	Kind Kind
	// Why is one line explaining the mask, reused by both the docs and
	// (were it ever needed) a verbose CLI listing -- kept beside the
	// path rather than only in the issue thread, so the reasoning ships
	// with the code that acts on it.
	Why string
}

// Masks is the owner-ratified list (issue #108, "Owner confirms the mask
// list, /home included", 2026-09-22): bound over with /dev/null,
// `/etc/shadow` and `/etc/gshadow`; covered with a read-only tmpfs,
// `/etc/ssh`, `/root`, `/proc`, `/run`, `/sys`, `/dev`, `/tmp`,
// `/var/tmp` and `/home`. Deliberately excludes `/etc` as a whole,
// `/etc/os-release` and `/var/lib/docker` -- Grype needs the first two to
// identify the distribution, and the third is unreadable to a non-root
// process regardless (M4's container-scanning issue is what will read
// it, and not from disk).
//
// Order is declaration order, stable across a process's lifetime: both
// the run-command renderer and RunFlags below rely on that for
// deterministic, reviewable output.
var Masks = []Mask{
	{Path: "/etc/shadow", Kind: File, Why: "password hashes; no package data"},
	{Path: "/etc/gshadow", Kind: File, Why: "group password hashes; no package data"},
	{Path: "/etc/ssh", Kind: Dir, Why: "host private keys; no package data"},
	{Path: "/root", Kind: Dir, Why: "root's keys, shell history and tokens"},
	{Path: "/proc", Kind: Dir, Why: "command-line secrets (world-readable /proc/*/cmdline) and kernel pseudo-files"},
	{Path: "/run", Kind: Dir, Why: "runtime secrets, including /run/secrets and systemd credentials; covers /var/run through the usual symlink"},
	{Path: "/sys", Kind: Dir, Why: "hygiene; no package data"},
	{Path: "/dev", Kind: Dir, Why: "hygiene; no package data"},
	{Path: "/tmp", Kind: Dir, Why: "transient leaked secrets; no legitimate installs"},
	{Path: "/var/tmp", Kind: Dir, Why: "transient leaked secrets; no legitimate installs"},
	{Path: "/home", Kind: Dir, Why: "modern distributions default home directories to 700 (unreadable to uid 65532 regardless); where they are 755, secrets outweigh the lost package-manager coverage"},
}

// Paths returns every Masks entry's Path, in the same declaration
// order -- the shape POST /ingest/scans' masked_paths field and
// client.Snapshot.MaskedPaths both want: a flat list, independent of
// Kind, recording the blind spot on the snapshot exactly as it was
// configured, whether or not a given path happened to exist on this
// particular host (issue #108: "any path we cover is a path the scanner
// cannot scan").
func Paths() []string {
	paths := make([]string, len(Masks))
	for i, m := range Masks {
		paths[i] = m.Path
	}
	return paths
}

// HostMountPoint is where mask m lands under root, the container's view
// of the host bind mount (e.g. HostMountPoint(m, "/host") for
// "/etc/shadow" is "/host/etc/shadow"). Both the run-command renderer
// and the startup check (mountinfo.go) call this so the two can never
// compute the mount point differently.
func HostMountPoint(m Mask, root string) string {
	return filepath.Join(root, m.Path)
}
