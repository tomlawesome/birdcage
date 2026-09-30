package main

import (
	"bytes"
	"testing"
)

// The release job compares `holder version` with the tag it built from,
// matching cmd/mockingbird/version_test.go's own
// TestRunVersionPrintsTheStampedValue.
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

// An unstamped build must admit it is one, the same reasoning
// cmd/mockingbird/version_test.go's own TestUnstampedBuildReportsDev
// gives: a default that looks like a release string would let a build
// outside the release pipeline claim a version it was not cut from.
func TestUnstampedBuildReportsDev(t *testing.T) {
	if version != "dev" {
		t.Fatalf("the unstamped default is %q, want \"dev\"", version)
	}
}
