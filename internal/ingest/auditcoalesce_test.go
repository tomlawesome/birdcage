package ingest

import (
	"testing"
	"time"
)

// TestAuditCoalescerFirstOccurrenceAlwaysWrites is the design's
// non-negotiable case: a health state must never wait out a coalescing
// interval for its first signal.
func TestAuditCoalescerFirstOccurrenceAlwaysWrites(t *testing.T) {
	c := newAuditCoalescer()
	write, occurrences := c.admit("canary-a", "ingest.rate_limited", time.Now())
	if !write {
		t.Fatal("first occurrence for a key must always write")
	}
	if occurrences != 1 {
		t.Fatalf("occurrences = %d, want 1", occurrences)
	}
}

// TestAuditCoalescerSuppressesWithinIntervalThenFoldsCount proves the
// three-part shape issue #57 requires: writes once, suppresses every
// repeat inside auditCoalesceInterval, then writes again once the
// interval elapses with the folded count -- including the suppressed
// occurrences -- attached.
func TestAuditCoalescerSuppressesWithinIntervalThenFoldsCount(t *testing.T) {
	c := newAuditCoalescer()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if write, occ := c.admit("canary-a", "ingest.rate_limited", base); !write || occ != 1 {
		t.Fatalf("first admit: write=%v occurrences=%d, want true/1", write, occ)
	}

	for i := 1; i <= 4; i++ {
		at := base.Add(time.Duration(i) * 10 * time.Second) // stays under 1 minute
		if write, occ := c.admit("canary-a", "ingest.rate_limited", at); write || occ != 0 {
			t.Fatalf("suppressed admit %d: write=%v occurrences=%d, want false/0", i, write, occ)
		}
	}

	// Five occurrences arrived (the first write plus four suppressed);
	// the next one after the interval elapses must report all five.
	after := base.Add(auditCoalesceInterval)
	write, occ := c.admit("canary-a", "ingest.rate_limited", after)
	if !write {
		t.Fatal("admit after the interval elapsed must write")
	}
	if occ != 5 {
		t.Fatalf("occurrences = %d, want 5 (1 that wrote + 4 suppressed)", occ)
	}

	// And the cycle resets: the very next occurrence is suppressed again.
	if write, occ := c.admit("canary-a", "ingest.rate_limited", after.Add(time.Second)); write || occ != 0 {
		t.Fatalf("admit right after a write: write=%v occurrences=%d, want false/0", write, occ)
	}
}

// TestAuditCoalescerKeysAreIndependent proves the coalescer's key is the
// (canaryID, action) pair, not just one or the other: a different canary
// or a different action gets its own first-occurrence write even while
// another key is mid-suppression.
func TestAuditCoalescerKeysAreIndependent(t *testing.T) {
	c := newAuditCoalescer()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	if write, _ := c.admit("canary-a", "ingest.rate_limited", base); !write {
		t.Fatal("canary-a/ingest.rate_limited first admit must write")
	}
	if write, _ := c.admit("canary-a", "ingest.rate_limited", base.Add(time.Second)); write {
		t.Fatal("canary-a/ingest.rate_limited second admit inside the interval must not write")
	}
	if write, occ := c.admit("canary-b", "ingest.rate_limited", base.Add(time.Second)); !write || occ != 1 {
		t.Fatalf("canary-b/ingest.rate_limited first admit: write=%v occurrences=%d, want true/1", write, occ)
	}
	if write, occ := c.admit("canary-a", "ingest.token_conflict", base.Add(time.Second)); !write || occ != 1 {
		t.Fatalf("canary-a/ingest.token_conflict first admit: write=%v occurrences=%d, want true/1", write, occ)
	}
}

// TestCoalescedReasonOmitsClauseForASoloOccurrence proves the "1 of 1"
// awkwardness call-out: a row that represents only itself must read
// naturally, not carry a degenerate count clause.
func TestCoalescedReasonOmitsClauseForASoloOccurrence(t *testing.T) {
	got := coalescedReason("requests/min limit exceeded", 1, "crossings")
	want := "requests/min limit exceeded"
	if got != want {
		t.Fatalf("coalescedReason(1) = %q, want %q", got, want)
	}
}

// TestCoalescedReasonStatesScaleForAFoldedRow proves a reader can see
// the real scale of the flood from the row: the base reason text is kept
// verbatim and the fold count is both present and comma-formatted for a
// large flood.
func TestCoalescedReasonStatesScaleForAFoldedRow(t *testing.T) {
	got := coalescedReason("requests/min limit exceeded", 4175, "crossings")
	want := "requests/min limit exceeded (1 of 4,175 crossings since the previous entry)"
	if got != want {
		t.Fatalf("coalescedReason(4175) = %q, want %q", got, want)
	}
}

func TestFormatCount(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{2, "2"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{4175, "4,175"},
		{1234567, "1,234,567"},
	}
	for _, tc := range cases {
		if got := formatCount(tc.n); got != tc.want {
			t.Errorf("formatCount(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
