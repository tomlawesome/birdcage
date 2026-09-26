package main

import (
	"fmt"
	"io"
)

// runVersion implements `holder version`, matching cmd/birdcage,
// cmd/mockingbird and cmd/nightjar's own `version` argument exactly:
// prints the stamped version variable and nothing else, so a release job
// can compare the output with the tag it built from.
//
// version itself is declared in main.go, stamped at build time the same
// way as the other three binaries.
func runVersion(w io.Writer) error {
	_, err := fmt.Fprintln(w, version)
	return err
}
