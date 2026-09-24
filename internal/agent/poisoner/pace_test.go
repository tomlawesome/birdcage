package poisoner

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// base is a fixed instant every pacing test counts from, so bucket
// boundaries are predictable.
var base = time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)

// TestPaceCounterTakesTheMedianNotTheBusiest is the heart of issue #86
// decision 35: one very chatty host must not set the canary's rate.
func TestPaceCounterTakesTheMedianNotTheBusiest(t *testing.T) {
	c := newPaceCounter(base)
	// Four quiet hosts and one shouting one. The mean would be 208; the
	// maximum 1000; the median 4.
	for _, host := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		for i := 0; i < 4; i++ {
			c.Observe(host, base)
		}
	}
	for i := 0; i < 1000; i++ {
		c.Observe("10.0.0.9", base)
	}

	queries, hosts := c.Median(base)
	if hosts != 5 {
		t.Errorf("hosts = %d, want 5", hosts)
	}
	if queries != 4 {
		t.Errorf("median = %d, want 4 -- the busiest host must not set the rate", queries)
	}
}

// TestPaceCounterTakesTheLowerMiddleValue pins the even-count rule: the
// answer is always a rate some real host actually had.
func TestPaceCounterTakesTheLowerMiddleValue(t *testing.T) {
	c := newPaceCounter(base)
	for i, host := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		for n := 0; n <= i; n++ {
			c.Observe(host, base)
		}
	}
	// Counts are 1, 2, 3, 4: the two middle values are 2 and 3.
	queries, hosts := c.Median(base)
	if hosts != 4 || queries != 2 {
		t.Errorf("Median = (%d, %d), want (2, 4)", queries, hosts)
	}
}

// TestPaceCounterRollsTheWindow proves the window really is a rolling day:
// counts inside it are kept, counts older than it are gone, and a counter
// that has heard nothing for a day reports an empty window rather than
// day-old numbers.
func TestPaceCounterRollsTheWindow(t *testing.T) {
	c := newPaceCounter(base)
	c.Observe("10.0.0.1", base)
	c.Observe("10.0.0.2", base)

	// Most of a day later, both are still counted.
	nearly := base.Add(paceWindow - paceBucketWidth)
	if _, hosts := c.Median(nearly); hosts != 2 {
		t.Errorf("hosts after %v = %d, want 2", paceWindow-paceBucketWidth, hosts)
	}

	// A day and a bit later, nothing is.
	past := base.Add(paceWindow + paceBucketWidth)
	if queries, hosts := c.Median(past); hosts != 0 || queries != 0 {
		t.Errorf("Median after the window = (%d, %d), want (0, 0)", queries, hosts)
	}

	// And it still counts afterwards, rather than having wedged.
	c.Observe("10.0.0.3", past)
	if _, hosts := c.Median(past); hosts != 1 {
		t.Errorf("hosts after a fresh observation = %d, want 1", hosts)
	}
}

// TestPaceCounterExpiresOneBucketAtATime walks the ring hour by hour, which
// is the case a whole-window reset would hide.
func TestPaceCounterExpiresOneBucketAtATime(t *testing.T) {
	c := newPaceCounter(base)
	// One host per hour for the whole window.
	for i := 0; i < paceBuckets; i++ {
		c.Observe(fmt.Sprintf("10.0.1.%d", i), base.Add(time.Duration(i)*paceBucketWidth))
	}
	at := base.Add(time.Duration(paceBuckets-1) * paceBucketWidth)
	if _, hosts := c.Median(at); hosts != paceBuckets {
		t.Fatalf("hosts = %d, want %d", hosts, paceBuckets)
	}
	// One hour on, the oldest bucket falls out.
	if _, hosts := c.Median(at.Add(paceBucketWidth)); hosts != paceBuckets-1 {
		t.Errorf("hosts one hour later = %d, want %d", hosts, paceBuckets-1)
	}
}

// TestPaceCounterCapsTrackedHosts proves a spoofed flood of source
// addresses cannot make this map the reason the canary runs out of memory,
// and that going over the cap can only lower the median -- the safe
// direction, because a lower median means a quieter canary.
func TestPaceCounterCapsTrackedHosts(t *testing.T) {
	c := newPaceCounter(base)
	for i := 0; i < maxTrackedHosts+500; i++ {
		c.Observe(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), base)
	}
	_, hosts := c.Median(base)
	if hosts > maxTrackedHosts {
		t.Errorf("tracked %d hosts, over the %d cap", hosts, maxTrackedHosts)
	}
	if !c.Overflowed() {
		t.Error("the counter did not record that it dropped hosts")
	}
}

// TestPaceCounterIgnoresAClockGoingBackwards keeps real counts from being
// thrown away over something the canary cannot verify.
func TestPaceCounterIgnoresAClockGoingBackwards(t *testing.T) {
	c := newPaceCounter(base)
	c.Observe("10.0.0.1", base)
	c.Observe("10.0.0.1", base.Add(-time.Hour))
	if queries, hosts := c.Median(base); queries != 2 || hosts != 1 {
		t.Errorf("Median = (%d, %d), want (2, 1)", queries, hosts)
	}
}

// TestMatchedGapUsesTheFloorOnAQuietSegment is the floor's whole purpose:
// pace-matching has nothing to match on an all-Linux segment with no LLMNR
// traffic, and a canary that never asks can never be answered.
func TestMatchedGapUsesTheFloorOnAQuietSegment(t *testing.T) {
	s := DefaultPaceSettings()
	tests := []struct {
		name    string
		queries int
		hosts   int
	}{
		{name: "nothing at all", queries: 0, hosts: 0},
		{name: "one host talking", queries: 500, hosts: 1},
		{name: "two hosts talking", queries: 500, hosts: minTalkingHosts - 1},
		{name: "three hosts but no queries", queries: 0, hosts: minTalkingHosts},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchedGap(tc.queries, tc.hosts, s); got != s.FloorGap {
				t.Errorf("matchedGap = %v, want the floor %v", got, s.FloorGap)
			}
		})
	}
}

// TestMatchedGapStaysInsideTheBounds is the ceiling's purpose: matching the
// median is only safe while the median is sane.
func TestMatchedGapStaysInsideTheBounds(t *testing.T) {
	s := DefaultPaceSettings()
	for _, queries := range []int{1, 7, 50, 500, 5000, 1 << 20} {
		got := matchedGap(queries, minTalkingHosts, s)
		if got > s.FloorGap {
			t.Errorf("median %d gave %v, past the floor %v", queries, got, s.FloorGap)
		}
		if got < s.CeilingGap {
			t.Errorf("median %d gave %v, past the ceiling %v", queries, got, s.CeilingGap)
		}
	}
}

// TestMatchedGapFollowsTheSegment proves the rate really does come from the
// segment between the two bounds: a busier median must mean a shorter gap.
func TestMatchedGapFollowsTheSegment(t *testing.T) {
	// A wide floor and a tight ceiling, so the matched value is what is
	// being read rather than a clamp.
	s := PaceSettings{FloorGap: 24 * time.Hour, CeilingGap: time.Second, Hours: AllHours()}
	quieter := matchedGap(10, minTalkingHosts, s)
	busier := matchedGap(100, minTalkingHosts, s)
	if !(busier < quieter) {
		t.Errorf("a busier segment gave %v, not shorter than the quieter segment's %v", busier, quieter)
	}

	// And the arithmetic is the one the comment claims: a median of 70
	// queries a day is 20 bursts of 3.5, spread over a 24-hour working day.
	want := 24 * time.Hour / 20
	if got := matchedGap(70, minTalkingHosts, s); got != want {
		t.Errorf("matchedGap(70) = %v, want %v", got, want)
	}
}

// TestPaceSettingsNormalise fills in zero fields and resolves the one
// contradiction an operator can express.
func TestPaceSettingsNormalise(t *testing.T) {
	got := PaceSettings{}.normalise()
	want := DefaultPaceSettings()
	if got.FloorGap != want.FloorGap || got.CeilingGap != want.CeilingGap {
		t.Errorf("a zero value normalised to %+v, want the defaults %+v", got, want)
	}
	if got.Hours != want.Hours {
		t.Errorf("hours normalised to %+v, want %+v", got.Hours, want.Hours)
	}

	// A ceiling looser than the floor asks for two contradictory things.
	// The quieter one wins: being too quiet only costs detection latency.
	odd := PaceSettings{FloorGap: time.Hour, CeilingGap: 6 * time.Hour, Hours: AllHours()}.normalise()
	if odd.CeilingGap != odd.FloorGap {
		t.Errorf("ceiling %v is still looser than floor %v", odd.CeilingGap, odd.FloorGap)
	}
}

// TestProvisionalNumbersAreMarked is a check on the code, not the maths.
// Issue #86's "Done when" requires the provisional floor and ceiling to be
// marked as provisional in the code -- this fails if somebody quietly turns
// a guess into a stated fact.
func TestProvisionalNumbersAreMarked(t *testing.T) {
	// The values themselves, as decision 36 settled them: one burst every
	// two hours at the floor, two bursts an hour at the ceiling.
	if DefaultFloorGap != 2*time.Hour {
		t.Errorf("DefaultFloorGap = %v, want 2h", DefaultFloorGap)
	}
	if DefaultCeilingGap != 30*time.Minute {
		t.Errorf("DefaultCeilingGap = %v, want 30m (two bursts an hour)", DefaultCeilingGap)
	}
	if minTalkingHosts != 3 {
		t.Errorf("minTalkingHosts = %d, want 3", minTalkingHosts)
	}

	// And they are still marked as guesses where somebody changing them
	// will read it. Issue #86's "Done when" asks for exactly this, and the
	// only way to check a comment is to read it: a number that has quietly
	// become a stated fact is the failure being guarded against.
	source, err := os.ReadFile("pace.go")
	if err != nil {
		t.Fatalf("read pace.go: %v", err)
	}
	text := string(source)
	if want := strings.Count(text, "PROVISIONAL"); want < 4 {
		t.Errorf("pace.go marks PROVISIONAL %d times, want one for the block and one per number", want)
	}
	if !strings.Contains(text, "#121") {
		t.Error("pace.go does not name #121 as what replaces the provisional numbers")
	}
}
