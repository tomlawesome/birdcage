package main

import (
	"os"

	"github.com/tomlawesome/birdcage/internal/agent/atomicfile"
)

// writeFileAtomic durably writes data to path -- see
// internal/agent/atomicfile.Write, factored out so a second agent kind
// (#108) shares this rather than copy-pasting it.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	return atomicfile.Write(path, data, mode)
}
