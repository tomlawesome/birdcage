package store

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// TestGradeForService_KnownAndDefault pins the ratified table (notes
// 19897, 20740) for one representative of each grade, plus the
// unmapped-service default: gradeForService's own doc comment says an
// unrecognised service defaults to GradeMarked rather than an empty
// value.
func TestGradeForService_KnownAndDefault(t *testing.T) {
	cases := []struct {
		service string
		want    Grade
	}{
		{"ssh", GradeMarked},
		{"vnc", GradeChallengeMarked},
		{"ntp", GradeAttributed},
		{"portscan", GradeAttributed},
		{"llmnr", GradeAttributed},
		{"something-this-build-has-never-heard-of", GradeMarked},
	}
	for _, c := range cases {
		if got := gradeForService(c.service); got != c.want {
			t.Errorf("gradeForService(%q) = %q, want %q", c.service, got, c.want)
		}
	}
}

// TestSelfTestServiceResults_MultipleGradesAndOrdering is item 4 of the
// slice 2 brief, exercised directly against store.SelfTestServiceResults
// rather than only through internal/api's handler test: three targets at
// three different grades, one matched, two not, returned service-sorted.
func TestSelfTestServiceResults_MultipleGradesAndOrdering(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "22,123,5900", EnrolledAt: time.Now()})
		if err := SetCanaryLastSeenAddr(context.Background(), database, "canary-a", "192.0.2.10"); err != nil {
			t.Fatalf("SetCanaryLastSeenAddr: %v", err)
		}
		idx := NewSelfTestIndex()
		now := time.Now().UTC()
		cmd, err := MintSelfTestCommand(context.Background(), database, idx, "canary-a", "192.0.2.10",
			[]SelfTestTarget{
				{Service: "ssh", DestPort: 22},
				{Service: "vnc", DestPort: 5900},
				{Service: "ntp", DestPort: 123},
			}, now, now.Add(10*time.Minute))
		if err != nil {
			t.Fatalf("MintSelfTestCommand: %v", err)
		}
		params := mustDecodeParams(t, cmd)

		// Only ssh (marked) actually matches; vnc and ntp are left
		// unmatched so their results read "failed", not "passed".
		var sshMarker string
		for _, tgt := range params.Targets {
			if tgt.Service == "ssh" {
				sshMarker = tgt.Marker
			}
		}
		alert := AlertInsert{InstanceID: "canary-a", Service: "ssh", DestPort: 22, Raw: `{"probe":"` + sshMarker + `"}`}
		if matched, err := MatchSelfTest(context.Background(), database, idx, alert, now); err != nil || !matched {
			t.Fatalf("MatchSelfTest(ssh) = %v, %v, want true, nil", matched, err)
		}

		afterDeadline := now.Add(11 * time.Minute)
		if _, err := SweepExpiredSelfTestRuns(context.Background(), database, afterDeadline); err != nil {
			t.Fatalf("SweepExpiredSelfTestRuns: %v", err)
		}

		results, ok, err := SelfTestServiceResults(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("SelfTestServiceResults: %v", err)
		}
		if !ok {
			t.Fatal("ok = false, want true (the run has completed)")
		}
		want := []SelfTestServiceResult{
			{Service: "ntp", Grade: GradeAttributed, Passed: false},
			{Service: "ssh", Grade: GradeMarked, Passed: true},
			{Service: "vnc", Grade: GradeChallengeMarked, Passed: false},
		}
		if len(results) != len(want) {
			t.Fatalf("results = %+v, want %+v", results, want)
		}
		for i := range want {
			if results[i] != want[i] {
				t.Errorf("results[%d] = %+v, want %+v", i, results[i], want[i])
			}
		}
	})
}

// TestSelfTestServiceResults_NeverRunIsNotOK matches
// LatestCompletedSelfTestRun's own "never run is not a failure" stance:
// a canary with no completed self-test at all reports ok=false, not an
// empty-but-present result.
func TestSelfTestServiceResults_NeverRunIsNotOK(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "a", Lane: "l", Ports: "22", EnrolledAt: time.Now()})
		results, ok, err := SelfTestServiceResults(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("SelfTestServiceResults: %v", err)
		}
		if ok || results != nil {
			t.Fatalf("SelfTestServiceResults = %+v, %v, want nil, false", results, ok)
		}
	})
}
