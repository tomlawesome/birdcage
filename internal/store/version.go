// Issue #54: "an agent is behind only when both versions parse as
// release versions and the agent's MAJOR.MINOR.PATCH is strictly lower
// than birdcage's." This file is the one place that comparison is made,
// so applyAgentOutOfDateHealth (health.go) and internal/driftsched's
// daily mail check can never disagree about what "behind" means.
package store

import (
	"regexp"
	"strconv"
	"strings"
)

// releaseVersion is a parsed MAJOR.MINOR.PATCH core, with any build
// metadata (the "+<commit>" scripts/release-version.sh appends) already
// stripped -- issue #54: "build metadata is ignored".
type releaseVersion struct {
	major, minor, patch int
}

// releaseVersionPart matches one strict, unsigned decimal component --
// digits only, so a value like "+5" or "1e3" (which strconv.Atoi would
// otherwise accept or reject inconsistently across Go versions) is
// refused the same way every other input this file cannot parse is.
var releaseVersionPart = regexp.MustCompile(`^[0-9]+$`)

// parseReleaseVersion parses raw the way scripts/release-version.sh
// stamps a release build: plain MAJOR.MINOR.PATCH, optionally suffixed
// with "+<build-metadata>". ok is false for anything else -- "dev" (a
// non-release build's own honest answer, cmd/birdcage/version.go and
// cmd/mockingbird's own equivalent), empty (no heartbeat has ever
// reported a version), or a string that simply doesn't parse. Every
// caller of this function stands on ok=false meaning "unknown", never
// "old": issue #54's own rule is that unknown is never reported as
// behind.
func parseReleaseVersion(raw string) (releaseVersion, bool) {
	core := raw
	if i := strings.IndexByte(raw, '+'); i >= 0 {
		core = raw[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return releaseVersion{}, false
	}
	var v releaseVersion
	nums := make([]int, 3)
	for i, p := range parts {
		if !releaseVersionPart.MatchString(p) {
			return releaseVersion{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return releaseVersion{}, false
		}
		nums[i] = n
	}
	v.major, v.minor, v.patch = nums[0], nums[1], nums[2]
	return v, true
}

// less reports whether a's release core is strictly older than b's --
// major, then minor, then patch, the ordinary semver-core ordering
// (build metadata already stripped by parseReleaseVersion).
func (a releaseVersion) less(b releaseVersion) bool {
	if a.major != b.major {
		return a.major < b.major
	}
	if a.minor != b.minor {
		return a.minor < b.minor
	}
	return a.patch < b.patch
}

// agentBehindBirdcage reports whether agentVersion is a release version
// strictly older than birdcageVersion's own release core (issue #54).
// Both sides must parse as plain MAJOR.MINOR.PATCH, build metadata
// ignored; "dev", empty, missing or otherwise unparseable on either side
// answers false, never true -- an unknown version is never behind, and
// neither is an agent whose version is equal to or newer than
// birdcage's own.
func agentBehindBirdcage(agentVersion, birdcageVersion string) bool {
	a, ok := parseReleaseVersion(agentVersion)
	if !ok {
		return false
	}
	b, ok := parseReleaseVersion(birdcageVersion)
	if !ok {
		return false
	}
	return a.less(b)
}
