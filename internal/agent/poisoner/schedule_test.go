package poisoner

import (
	"testing"
	"time"
)

// TestParseWorkingHours covers the forms an operator may write and the ones
// that must be refused rather than silently falling back -- a canary that
// asked around the clock because a setting was mistyped would be doing the
// one thing this setting exists to prevent.
func TestParseWorkingHours(t *testing.T) {
	mondayToFriday := [7]bool{time.Monday: true, time.Tuesday: true, time.Wednesday: true, time.Thursday: true, time.Friday: true}

	tests := []struct {
		raw       string
		wantStart int
		wantEnd   int
		wantDays  [7]bool
		wantErr   bool
	}{
		{raw: "", wantStart: 8 * 60, wantEnd: 18 * 60, wantDays: mondayToFriday},
		{raw: "09:00-17:00", wantStart: 9 * 60, wantEnd: 17 * 60, wantDays: mondayToFriday},
		{raw: " 09:30-17:45 ", wantStart: 9*60 + 30, wantEnd: 17*60 + 45, wantDays: mondayToFriday},
		{raw: "00:00-24:00", wantStart: 0, wantEnd: 24 * 60, wantDays: mondayToFriday},
		{
			raw: "06:00-22:00/Mon,Sat,Sun", wantStart: 6 * 60, wantEnd: 22 * 60,
			wantDays: [7]bool{time.Monday: true, time.Saturday: true, time.Sunday: true},
		},
		{
			// Case-insensitive day names, because an operator will type
			// them however they type them.
			raw: "08:00-18:00/mon,TUE", wantStart: 8 * 60, wantEnd: 18 * 60,
			wantDays: [7]bool{time.Monday: true, time.Tuesday: true},
		},
		{
			// A window that wraps midnight: a shift, not an office.
			raw: "22:00-06:00", wantStart: 22 * 60, wantEnd: 6 * 60, wantDays: mondayToFriday,
		},
		{raw: "nonsense", wantErr: true},
		{raw: "09:00", wantErr: true},
		{raw: "9-17", wantErr: true},
		{raw: "25:00-26:00", wantErr: true},
		{raw: "09:60-17:00", wantErr: true},
		{raw: "09:00-09:00", wantErr: true},
		{raw: "09:00-17:00/Funday", wantErr: true},
		{raw: "09:00-17:00/", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := ParseWorkingHours(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want an error: %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got.Start != tc.wantStart || got.End != tc.wantEnd {
				t.Errorf("window = %d-%d minutes, want %d-%d", got.Start, got.End, tc.wantStart, tc.wantEnd)
			}
			if got.Days != tc.wantDays {
				t.Errorf("days = %v, want %v", got.Days, tc.wantDays)
			}
		})
	}
}

// TestWorkingHoursContains walks the edges: the first minute in, the last
// minute in, the minute after, a weekend, and a window that wraps midnight.
func TestWorkingHoursContains(t *testing.T) {
	office, err := ParseWorkingHours("09:00-17:00")
	if err != nil {
		t.Fatalf("ParseWorkingHours: %v", err)
	}
	// 2026-09-23 is a Wednesday; 2026-09-26 a Saturday.
	at := func(day, hour, minute int) time.Time {
		return time.Date(2026, 9, day, hour, minute, 0, 0, time.UTC)
	}
	tests := []struct {
		name string
		when time.Time
		want bool
	}{
		{name: "the first minute", when: at(23, 9, 0), want: true},
		{name: "the last minute", when: at(23, 16, 59), want: true},
		{name: "the minute it closes", when: at(23, 17, 0), want: false},
		{name: "before it opens", when: at(23, 8, 59), want: false},
		{name: "the middle of the night", when: at(23, 3, 0), want: false},
		{name: "a Saturday in hours", when: at(26, 12, 0), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := office.Contains(tc.when); got != tc.want {
				t.Errorf("Contains(%v) = %v, want %v", tc.when, got, tc.want)
			}
		})
	}

	// A wrapping window belongs to the day its shift started on, so the
	// small hours of Saturday are part of Friday's shift and the small
	// hours of Monday are not part of anything.
	night, err := ParseWorkingHours("22:00-06:00")
	if err != nil {
		t.Fatalf("ParseWorkingHours: %v", err)
	}
	if !night.Contains(at(25, 23, 0)) {
		t.Error("Friday 23:00 is not inside a Mon-Fri 22:00-06:00 shift")
	}
	if !night.Contains(at(26, 2, 0)) {
		t.Error("Saturday 02:00 is not counted as part of Friday's shift")
	}
	if night.Contains(at(26, 23, 0)) {
		t.Error("Saturday 23:00 is inside a Mon-Fri shift")
	}
	if night.Contains(at(21, 2, 0)) {
		t.Error("Monday 02:00 is inside a Mon-Fri shift, but Sunday has no shift to spill from")
	}

	// AllHours is inside at every moment tested above.
	all := AllHours()
	for _, tc := range tests {
		if !all.Contains(tc.when) {
			t.Errorf("AllHours does not contain %v", tc.when)
		}
	}
}

// TestWorkingHoursNextStart proves the sleep-through-the-night calculation
// lands on the first minute of the window and never before the time asked
// about.
func TestWorkingHoursNextStart(t *testing.T) {
	office, err := ParseWorkingHours("09:00-17:00")
	if err != nil {
		t.Fatalf("ParseWorkingHours: %v", err)
	}
	at := func(day, hour, minute int) time.Time {
		return time.Date(2026, 9, day, hour, minute, 0, 0, time.UTC)
	}

	tests := []struct {
		name string
		from time.Time
		want time.Time
	}{
		{name: "already inside", from: at(23, 10, 0), want: at(23, 10, 0)},
		{name: "before opening", from: at(23, 6, 0), want: at(23, 9, 0)},
		{name: "after closing", from: at(23, 18, 0), want: at(24, 9, 0)},
		// Friday evening waits the whole weekend out.
		{name: "Friday evening", from: at(25, 18, 0), want: at(28, 9, 0)},
		{name: "Saturday", from: at(26, 12, 0), want: at(28, 9, 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := office.NextStart(tc.from)
			if !got.Equal(tc.want) {
				t.Errorf("NextStart(%v) = %v, want %v", tc.from, got, tc.want)
			}
			if got.Before(tc.from.Truncate(time.Minute)) {
				t.Errorf("NextStart went backwards: %v before %v", got, tc.from)
			}
		})
	}

	// AllHours is always now.
	if got := AllHours().NextStart(at(23, 3, 0)); !got.Equal(at(23, 3, 0)) {
		t.Errorf("AllHours().NextStart = %v, want the time asked about", got)
	}
}

// TestWorkingHoursDailySpan is the denominator matchedGap divides a day's
// bursts across. A Monday-to-Friday nine-to-five is 8 hours on 5 days in 7.
func TestWorkingHoursDailySpan(t *testing.T) {
	office, err := ParseWorkingHours("09:00-17:00")
	if err != nil {
		t.Fatalf("ParseWorkingHours: %v", err)
	}
	if want := 8 * time.Hour * 5 / 7; office.DailySpan() != want {
		t.Errorf("DailySpan = %v, want %v", office.DailySpan(), want)
	}
	if want := 24 * time.Hour; AllHours().DailySpan() != want {
		t.Errorf("AllHours().DailySpan = %v, want %v", AllHours().DailySpan(), want)
	}
	// A window naming no days has no span, which is what makes matchedGap
	// fall back to the floor rather than divide by zero.
	if got := (WorkingHours{Start: 0, End: 60}).DailySpan(); got != 0 {
		t.Errorf("a window with no days has span %v, want 0", got)
	}
	// A wrapping shift spans the hours it actually covers.
	night, err := ParseWorkingHours("22:00-06:00")
	if err != nil {
		t.Fatalf("ParseWorkingHours: %v", err)
	}
	if want := 8 * time.Hour * 5 / 7; night.DailySpan() != want {
		t.Errorf("wrapping DailySpan = %v, want %v", night.DailySpan(), want)
	}
}

// TestScheduleIsSeededPerCanary is issue #86 decision 33's "seeded per
// canary so no two canaries share a rhythm", and its other half: the same
// canary keeps its rhythm across a restart.
func TestScheduleIsSeededPerCanary(t *testing.T) {
	draw := func(identity string) []int {
		s := NewSchedule(identity)
		var out []int
		for i := 0; i < 20; i++ {
			out = append(out, s.BurstSize())
		}
		return out
	}
	same := draw("canary-a")
	again := draw("canary-a")
	other := draw("canary-b")

	for i := range same {
		if same[i] != again[i] {
			t.Fatalf("the same canary drew %v then %v", same, again)
		}
	}
	differs := false
	for i := range same {
		if same[i] != other[i] {
			differs = true
			break
		}
	}
	if !differs {
		t.Errorf("two canaries drew the same rhythm: %v", same)
	}

	// Seed is a stored value, not a draw: asking for it must not shift the
	// rhythm, or the derived names would depend on when the caller asked.
	s := NewSchedule("canary-a")
	firstSeed := s.Seed()
	secondSeed := s.Seed()
	if firstSeed != secondSeed {
		t.Error("Seed changes between calls")
	}
	if got := s.BurstSize(); got != same[0] {
		t.Errorf("asking for the seed shifted the rhythm: first burst %d, want %d", got, same[0])
	}
}

// TestScheduleBurstSize holds the burst to decision 33's two-to-five range,
// and proves the whole range is actually reachable rather than one value
// being drawn every time.
func TestScheduleBurstSize(t *testing.T) {
	s := NewSchedule("canary")
	seen := map[int]bool{}
	for i := 0; i < 2000; i++ {
		n := s.BurstSize()
		if n < minBurstLookups || n > maxBurstLookups {
			t.Fatalf("BurstSize = %d, outside %d-%d", n, minBurstLookups, maxBurstLookups)
		}
		seen[n] = true
	}
	for n := minBurstLookups; n <= maxBurstLookups; n++ {
		if !seen[n] {
			t.Errorf("burst size %d never came up", n)
		}
	}
}

// TestScheduleBurstGapsStayInsideTheMinute is decision 33's "within a
// minute": even the largest burst with every gap at its widest fits.
func TestScheduleBurstGapsStayInsideTheMinute(t *testing.T) {
	s := NewSchedule("canary")
	if got := s.BurstGaps(1); got != nil {
		t.Errorf("BurstGaps(1) = %v, want nil -- one lookup has no gaps", got)
	}
	for i := 0; i < 500; i++ {
		for n := minBurstLookups; n <= maxBurstLookups; n++ {
			gaps := s.BurstGaps(n)
			if len(gaps) != n-1 {
				t.Fatalf("BurstGaps(%d) returned %d gaps, want %d", n, len(gaps), n-1)
			}
			var total time.Duration
			for _, g := range gaps {
				if g < 0 {
					t.Fatalf("a gap was negative: %v", g)
				}
				total += g
			}
			if total >= burstSpread {
				t.Fatalf("a %d-lookup burst spanned %v, past the %v it must fit in", n, total, burstSpread)
			}
		}
	}
}

// TestScheduleJitterStaysInsideTheBounds proves jitter is not a way round a
// bound the operator set.
func TestScheduleJitterStaysInsideTheBounds(t *testing.T) {
	s := NewSchedule("canary")
	settings := DefaultPaceSettings()
	spread := map[time.Duration]bool{}
	for i := 0; i < 2000; i++ {
		got := s.Jitter(time.Hour, settings)
		if got > settings.FloorGap {
			t.Fatalf("jitter gave %v, past the floor %v", got, settings.FloorGap)
		}
		if got < settings.CeilingGap {
			t.Fatalf("jitter gave %v, past the ceiling %v", got, settings.CeilingGap)
		}
		spread[got.Round(time.Minute)] = true
	}
	if len(spread) < 5 {
		t.Errorf("jitter produced only %d distinct values: a fixed interval is itself a signature", len(spread))
	}

	// A gap already at the floor stays at the floor rather than being
	// jittered past it.
	if got := s.Jitter(settings.FloorGap, settings); got > settings.FloorGap {
		t.Errorf("jittering the floor gave %v, past %v", got, settings.FloorGap)
	}
}

// TestScheduleStartupDelayIsBounded keeps the boot-time burst from landing in
// the same instant the container came up, and from waiting so long that a
// self-test would miss it.
func TestScheduleStartupDelayIsBounded(t *testing.T) {
	s := NewSchedule("canary")
	settings := DefaultPaceSettings()
	for i := 0; i < 500; i++ {
		got := s.StartupDelay(settings)
		if got < 0 || got >= startupDelayMax {
			t.Fatalf("StartupDelay = %v, outside 0 to %v", got, startupDelayMax)
		}
	}
}

// TestScheduleStartupDelayRespectsTheFloor: a canary told to burst every
// few seconds must not wait three minutes for its first burst, which would
// be the canary being quieter than its own settings ask. This is also what
// makes the e2e journey deterministic -- see scripts/e2e/poisoner.sh.
func TestScheduleStartupDelayRespectsTheFloor(t *testing.T) {
	s := NewSchedule("canary")
	tight := PaceSettings{FloorGap: 5 * time.Second, CeilingGap: time.Second, Hours: AllHours()}
	for i := 0; i < 500; i++ {
		got := s.StartupDelay(tight)
		if got < 0 || got >= tight.FloorGap {
			t.Fatalf("StartupDelay = %v, outside 0 to the %v floor", got, tight.FloorGap)
		}
	}
	// A floor wider than startupDelayMax leaves startupDelayMax the bound,
	// so the shipped default is unchanged by this.
	wide := PaceSettings{FloorGap: 24 * time.Hour, CeilingGap: time.Hour, Hours: AllHours()}
	for i := 0; i < 200; i++ {
		if got := s.StartupDelay(wide); got >= startupDelayMax {
			t.Fatalf("StartupDelay = %v, outside 0 to %v", got, startupDelayMax)
		}
	}
}

// TestScheduleNextNameUsesEveryName proves the rotation really rotates: a
// canary that always asked for wpad first would make the other names easy to
// spot as the invented ones.
func TestScheduleNextNameUsesEveryName(t *testing.T) {
	s := NewSchedule("canary")
	names := Names{"a", "b", WPADName}
	seen := map[string]int{}
	for i := 0; i < 3000; i++ {
		seen[s.NextName(names)]++
	}
	for _, name := range names {
		if seen[name] == 0 {
			t.Errorf("%q was never asked for", name)
		}
	}
	if got := s.NextName(nil); got != "" {
		t.Errorf("NextName(nil) = %q, want the empty string", got)
	}
}
