package main

import (
	"fmt"
	"io"
)

// version is stamped at build time (-ldflags "-X main.version=...") from
// the VERSION build argument in build/birdcage/Dockerfile, the way
// cmd/mockingbird already does it. An unstamped build says "dev", which
// is the honest answer for one: a binary that claims a release number it
// was not cut from is worse than one that admits it is a development
// build.
var version = "dev"

// runVersion implements `birdcage version` (issue #90): prints the stamped
// version and nothing else, so a release job can compare the output with
// the tag it built from. It writes to an io.Writer rather than straight to
// stdout so the test can read what a release job would see, and it stays
// out of the log stream deliberately -- a caller parsing this wants one
// line, not a banner and a level prefix.
func runVersion(w io.Writer) error {
	_, err := fmt.Fprintln(w, version)
	return err
}
