package main

import (
	"fmt"
	"io"
)

// runVersion implements `nightjar version`, matching cmd/mockingbird's
// own `version` argument (issue #97) and cmd/birdcage's (issue #90)
// exactly: prints the stamped version variable and nothing else, so a
// release job can compare the output with the tag it built from.
//
// version itself is declared in main.go, stamped at build time the same
// way as the other two binaries.
func runVersion(w io.Writer) error {
	_, err := fmt.Fprintln(w, version)
	return err
}
