package main

import (
	"fmt"
	"io"
)

// runVersion implements `mockingbird version` (issue #97), matching
// cmd/birdcage's own `version` argument (issue #90, cmd/birdcage/main.go
// and version.go) exactly: prints the stamped version variable and nothing
// else, so a release job can compare the output with the tag it built
// from. It writes to an io.Writer rather than straight to stdout so the
// test can read what a release job would see, and it stays out of the log
// stream deliberately -- a caller parsing this wants one line, not a
// level prefix.
//
// version itself is declared in main.go, stamped at build time the same
// way for both binaries.
func runVersion(w io.Writer) error {
	_, err := fmt.Fprintln(w, version)
	return err
}
