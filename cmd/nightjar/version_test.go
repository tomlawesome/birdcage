package main

import (
	"bytes"
	"testing"
)

// Mirrors cmd/mockingbird/version_test.go's own tests -- the release job
// compares `nightjar version` with the tag it built from.
func TestRunVersionPrintsTheStampedValue(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })
	version = "v9.9.9-stamped"

	var out bytes.Buffer
	if err := runVersion(&out); err != nil {
		t.Fatalf("runVersion: %v", err)
	}

	if got, want := out.String(), "v9.9.9-stamped\n"; got != want {
		t.Fatalf("runVersion wrote %q, want %q", got, want)
	}
}

func TestUnstampedBuildReportsDev(t *testing.T) {
	if version != "dev" {
		t.Fatalf("the unstamped default is %q, want \"dev\"", version)
	}
}
