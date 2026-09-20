package main

import (
	"bytes"
	"testing"
)

// The release job compares `birdcage version` with the tag it built from,
// so what matters is that the command prints the stamped variable and
// nothing else: a banner, a log prefix or a hardcoded string would all
// pass a naive "it printed something" check and fail the comparison.
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

// An unstamped build must admit it is one. If this default is ever edited
// to a release-looking string, every binary built outside the release job
// starts claiming a version it was not cut from.
func TestUnstampedBuildReportsDev(t *testing.T) {
	if version != "dev" {
		t.Fatalf("the unstamped default is %q, want \"dev\"", version)
	}
}
