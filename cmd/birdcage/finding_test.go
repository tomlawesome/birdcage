package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

func TestFindingsListNoneYet(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	insertTestCanary(t, database, "scanner-a")

	out, err := captureStdout(t, func() error { return runFindingsList([]string{"scanner-a"}) })
	if err != nil {
		t.Fatalf("runFindingsList: %v", err)
	}
	if !strings.Contains(out, "no findings recorded") {
		t.Fatalf("output = %q, want it to say no findings are recorded", out)
	}
}

// TestFindingsAcceptThenListRoundTrips proves the CLI write path end to
// end -- issue #109's own acceptance mechanism, since AcceptFinding has
// no dashboard route: accept stores the decision (via
// store.AcceptFinding), and list reads it back with the right state and
// who/when.
func TestFindingsAcceptThenListRoundTrips(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	insertTestCanary(t, database, "scanner-a")

	observed := []store.ObservedFinding{{
		Target: store.BuildFindingTarget("deb", "openssl"), VulnerabilityID: "CVE-2014-0160", Severity: "critical",
	}}
	if err := store.ApplyFindingSnapshot(context.Background(), database, "scanner-a", observed, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("ApplyFindingSnapshot: %v", err)
	}

	acceptOut, err := captureStdout(t, func() error {
		return runFindingsAccept([]string{"scanner-a", "deb:openssl", "CVE-2014-0160", "tom"})
	})
	if err != nil {
		t.Fatalf("runFindingsAccept: %v", err)
	}
	if !strings.Contains(acceptOut, "accepted") || !strings.Contains(acceptOut, "by=tom") {
		t.Fatalf("accept output = %q, want it to confirm acceptance by tom", acceptOut)
	}

	listOut, err := captureStdout(t, func() error { return runFindingsList([]string{"scanner-a"}) })
	if err != nil {
		t.Fatalf("runFindingsList: %v", err)
	}
	if !strings.Contains(listOut, "state=accepted") || !strings.Contains(listOut, "accepted_by=tom") {
		t.Fatalf("list output = %q, want state=accepted and accepted_by=tom", listOut)
	}
}

// TestFindingsAcceptUnknownReturnsError proves accepting a target/
// vulnerability pair the agent has never reported (or no longer
// reports) is refused rather than silently creating a row.
func TestFindingsAcceptUnknownReturnsError(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	insertTestCanary(t, database, "scanner-a")

	if err := runFindingsAccept([]string{"scanner-a", "deb:openssl", "CVE-2014-0160", "tom"}); err == nil {
		t.Fatal("runFindingsAccept(unknown finding) returned no error")
	}
}
