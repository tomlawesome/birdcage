package hostmask

import "fmt"

// RunFlags renders the `docker run` flags that cover every entry in
// Masks over root (cmd/birdcage's enrol renderer calls this with
// "/host", matching -v /:/host:ro). A File mask is bound over with
// /dev/null; a Dir mask is covered with a read-only tmpfs -- issue #108:
// "The tmpfs masks are mounted read-only deliberately: a default
// read-write tmpfs under /host would hand a compromised scanner free
// scratch space."
//
// Docker sorts mount destinations by depth before applying them, so a
// mask nested inside the root bind (e.g. /host/home under /host) takes
// effect after the root bind itself, which is what makes covering a
// path inside a bind mount work at all.
func RunFlags(root string) []string {
	flags := make([]string, 0, len(Masks))
	for _, m := range Masks {
		dest := HostMountPoint(m, root)
		switch m.Kind {
		case File:
			flags = append(flags, fmt.Sprintf("-v /dev/null:%s:ro", dest))
		case Dir:
			flags = append(flags, fmt.Sprintf("--tmpfs %s:ro", dest))
		}
	}
	return flags
}
