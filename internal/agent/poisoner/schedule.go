package poisoner

import (
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// WorkingHours is when a canary asks anything at all: the hours of the day,
// in the canary's own timezone, and the days of the week.
//
// The point is not politeness. A workstation asks for names when somebody
// is using it, so a host that asks for the same handful of names at three
// in the morning is the odd one out on the segment -- one of the giveaways
// issue #86's research note lists. Outside these hours the canary asks
// nothing and only listens.
type WorkingHours struct {
	// Start and End are minutes from midnight, local time. End is
	// exclusive. End may be less than Start, which means the window wraps
	// midnight -- a shift pattern rather than an office.
	Start, End int

	// Days are the weekdays the window applies to, indexed by
	// time.Weekday (Sunday is 0).
	Days [7]bool
}

// Working-hours geometry.
const (
	minutesPerDay  = 24 * 60
	minutesPerHour = 60
)

// DefaultWorkingHours is Monday to Friday, 08:00 to 18:00. A plain default
// rather than a measured one: it is the window most offices the product is
// aimed at are staffed for, and it is a per-canary setting precisely
// because no single window is right everywhere.
func DefaultWorkingHours() WorkingHours {
	w := WorkingHours{Start: 8 * minutesPerHour, End: 18 * minutesPerHour}
	for d := time.Monday; d <= time.Friday; d++ {
		w.Days[d] = true
	}
	return w
}

// AllHours is every hour of every day: what an operator asks for when the
// segment they are watching is a datacentre with no working day.
func AllHours() WorkingHours {
	w := WorkingHours{Start: 0, End: minutesPerDay}
	for d := range w.Days {
		w.Days[d] = true
	}
	return w
}

// ParseWorkingHours reads an operator's working-hours setting.
//
// The form is `HH:MM-HH:MM`, optionally followed by `/` and a comma-separated
// list of three-letter day names: `08:00-18:00`, or
// `06:00-22:00/Mon,Tue,Wed,Thu,Fri,Sat`. With no day list, Monday to
// Friday. `00:00-24:00` with every day is AllHours.
//
// An empty string is DefaultWorkingHours. Anything else that does not parse
// is an error rather than a fallback: a canary that silently asked around
// the clock because a setting was mistyped would be doing the one thing
// this setting exists to prevent.
func ParseWorkingHours(raw string) (WorkingHours, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultWorkingHours(), nil
	}

	window, dayList, hasDays := strings.Cut(raw, "/")
	startText, endText, ok := strings.Cut(strings.TrimSpace(window), "-")
	if !ok {
		return WorkingHours{}, fmt.Errorf("poisoner: working hours %q is not of the form HH:MM-HH:MM", raw)
	}
	start, err := parseClock(startText)
	if err != nil {
		return WorkingHours{}, err
	}
	end, err := parseClock(endText)
	if err != nil {
		return WorkingHours{}, err
	}
	if start == end {
		return WorkingHours{}, fmt.Errorf("poisoner: working hours %q start and end at the same minute, which is no window at all", raw)
	}

	w := WorkingHours{Start: start, End: end}
	if !hasDays {
		for d := time.Monday; d <= time.Friday; d++ {
			w.Days[d] = true
		}
		return w, nil
	}
	for _, field := range strings.Split(dayList, ",") {
		day, err := parseWeekday(field)
		if err != nil {
			return WorkingHours{}, err
		}
		w.Days[day] = true
	}
	if w.zero() {
		return WorkingHours{}, fmt.Errorf("poisoner: working hours %q names no days", raw)
	}
	return w, nil
}

// parseClock reads `HH:MM` into minutes from midnight. 24:00 is accepted as
// the end of a day, which is how `00:00-24:00` says "all day"; nothing
// beyond it is.
func parseClock(raw string) (int, error) {
	hourText, minuteText, ok := strings.Cut(strings.TrimSpace(raw), ":")
	if !ok {
		return 0, fmt.Errorf("poisoner: %q is not a time of the form HH:MM", raw)
	}
	hour, err := strconv.Atoi(hourText)
	if err != nil {
		return 0, fmt.Errorf("poisoner: %q is not a time of the form HH:MM", raw)
	}
	minute, err := strconv.Atoi(minuteText)
	if err != nil {
		return 0, fmt.Errorf("poisoner: %q is not a time of the form HH:MM", raw)
	}
	if hour < 0 || hour > 24 || minute < 0 || minute > 59 || hour*minutesPerHour+minute > minutesPerDay {
		return 0, fmt.Errorf("poisoner: %q is not a time of day", raw)
	}
	return hour*minutesPerHour + minute, nil
}

// parseWeekday reads a three-letter day name, case-insensitively.
func parseWeekday(raw string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "sun":
		return time.Sunday, nil
	case "mon":
		return time.Monday, nil
	case "tue":
		return time.Tuesday, nil
	case "wed":
		return time.Wednesday, nil
	case "thu":
		return time.Thursday, nil
	case "fri":
		return time.Friday, nil
	case "sat":
		return time.Saturday, nil
	default:
		return 0, fmt.Errorf("poisoner: %q is not a three-letter day name", raw)
	}
}

// Contains reports whether t falls inside the window. t is used in its own
// location, which for a canary is the container's timezone -- the canary's
// timezone, as issue #86 decision 33 asks.
func (w WorkingHours) Contains(t time.Time) bool {
	if w.zero() {
		return false
	}
	minute := t.Hour()*minutesPerHour + t.Minute()
	if w.Start < w.End {
		return w.Days[t.Weekday()] && minute >= w.Start && minute < w.End
	}
	// A window that wraps midnight belongs to the day it started on, so
	// the small hours of Saturday are part of Friday's shift.
	if minute >= w.Start {
		return w.Days[t.Weekday()]
	}
	return w.Days[(t.Weekday()+6)%7] && minute < w.End
}

// NextStart returns the first moment at or after t that Contains accepts.
// Used to sleep through the night rather than waking every few minutes to
// ask whether the working day has begun.
//
// It steps minute by minute over at most eight days, which is a few
// thousand cheap comparisons once a night, against the alternative of
// reimplementing the wrap-midnight and weekday rules a second time and
// having the two disagree.
func (w WorkingHours) NextStart(t time.Time) time.Time {
	if w.zero() {
		// No window at all: nothing will ever be inside it. The caller
		// treats a time far in the future as "never", and a week is far
		// enough that the surrounding context will have been cancelled.
		return t.Add(7 * 24 * time.Hour)
	}
	at := t.Truncate(time.Minute)
	for i := 0; i <= 8*minutesPerDay; i++ {
		if w.Contains(at) {
			return at
		}
		at = at.Add(time.Minute)
	}
	return t.Add(7 * 24 * time.Hour)
}

// DailySpan is how long the window is on a day it applies to, multiplied by
// the share of the week it applies to -- in other words, the working time
// an average day holds. matchedGap spreads a day's bursts across it.
//
// A Monday-to-Friday nine-to-five is 8 hours on 5 days in 7, so 40/7 of an
// hour under six hours of average day. That is the right denominator for a
// rate measured over a rolling week-shaped day, and keeps a canary on a
// weekdays-only window from cramming a whole week's bursts into Monday.
func (w WorkingHours) DailySpan() time.Duration {
	span := w.End - w.Start
	if span < 0 {
		span += minutesPerDay
	}
	days := 0
	for _, on := range w.Days {
		if on {
			days++
		}
	}
	if days == 0 || span <= 0 {
		return 0
	}
	return time.Duration(span) * time.Minute * time.Duration(days) / 7
}

// zero reports whether the window names no days, which is the only way to
// be empty -- parseClock refuses a zero-length time range.
func (w WorkingHours) zero() bool {
	for _, on := range w.Days {
		if on {
			return false
		}
	}
	return true
}

// Schedule turns a canary's seed into its own rhythm: how many lookups a
// burst has, where inside the minute they fall, and how much the gap
// between bursts is jittered.
//
// Seeded per canary, as issue #86 decision 33 asks, so no two canaries on
// the same segment share a rhythm -- two hosts asking in lockstep would be
// more obvious than either of them asking too often. Seeded rather than
// random so a canary keeps its own rhythm across a restart.
type Schedule struct {
	rand *rand.Rand
	seed uint64
}

// jitterFraction is how far either side of the matched gap a burst may
// actually fall: a quarter. Enough that the interval is not a signature,
// little enough that the floor and ceiling still mean something.
const jitterFraction = 4

// startupDelayMax bounds the wait before the first burst after start-up.
// Issue #86 decision 33 asks for one burst "once after the agent starts, as
// a machine does on boot"; a machine does not ask in the same instant it
// finishes booting, and a canary that asked the moment its container came
// up would be timestamped against its own start.
const startupDelayMax = 3 * time.Minute

// NewSchedule seeds a schedule from a canary's own identity. Anything
// stable and per-canary works; the node id from OpenCanary's configuration
// is what the caller passes, because it is the same value the canary's
// events are attributed to.
func NewSchedule(identity string) *Schedule {
	h := fnv.New64a()
	_, _ = h.Write([]byte(identity))
	seed := h.Sum64()
	return &Schedule{rand: rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15)), seed: seed}
}

// Seed is the value NewSchedule derived, so the name generator can share
// one canary's identity rather than inventing a second. It is a stored
// value, not a draw: taking it from the random stream would make the
// generated names depend on when the caller happened to ask for the seed.
func (s *Schedule) Seed() uint64 { return s.seed }

// BurstSize is how many lookups the next burst makes: minBurstLookups to
// maxBurstLookups inclusive.
func (s *Schedule) BurstSize() int {
	return minBurstLookups + s.rand.IntN(maxBurstLookups-minBurstLookups+1)
}

// BurstGaps returns the waits between the lookups of one burst of size n,
// summing to less than burstSpread.
//
// Unevenly spaced on purpose: a person who cannot reach a share tries
// again straight away, then again after a think, which is nothing like a
// timer firing every twelve seconds. The gaps are drawn independently, so
// their sum is well inside the minute even at the top of the burst-size
// range.
func (s *Schedule) BurstGaps(n int) []time.Duration {
	if n <= 1 {
		return nil
	}
	gaps := make([]time.Duration, n-1)
	// The whole minute divided by the largest burst there can be, so even
	// a five-lookup burst with every gap at its widest stays inside it.
	widest := burstSpread / time.Duration(maxBurstLookups)
	for i := range gaps {
		gaps[i] = time.Duration(s.rand.Int64N(int64(widest)))
	}
	return gaps
}

// Jitter spreads gap by up to a quarter either way, then keeps the result
// inside the floor and the ceiling -- jitter must not be a way round a
// bound the operator set.
func (s *Schedule) Jitter(gap time.Duration, settings PaceSettings) time.Duration {
	settings = settings.normalise()
	swing := gap / jitterFraction
	if swing > 0 {
		gap += time.Duration(s.rand.Int64N(int64(2*swing))) - swing
	}
	if gap > settings.FloorGap {
		gap = settings.FloorGap
	}
	if gap < settings.CeilingGap {
		gap = settings.CeilingGap
	}
	return gap
}

// StartupDelay is the wait before the boot-time burst.
//
// Bounded by the floor as well as by startupDelayMax, because a canary
// whose settings say "a burst at least every N" should not wait longer
// than N for its first one: on a segment configured to burst every few
// seconds, a three-minute wait before the first is the canary being
// quieter than its own settings ask. With the shipped floor of two hours
// the bound is startupDelayMax and this changes nothing.
func (s *Schedule) StartupDelay(settings PaceSettings) time.Duration {
	settings = settings.normalise()
	longest := startupDelayMax
	if settings.FloorGap < longest {
		longest = settings.FloorGap
	}
	if longest <= 0 {
		return 0
	}
	return time.Duration(s.rand.Int64N(int64(longest)))
}

// NextName picks which name in the rotation the next lookup asks for.
// Random rather than round-robin: a fixed cycle through three names is
// itself a pattern, and a canary that always asks for wpad first would
// make the other two names easy to spot as the invented ones.
func (s *Schedule) NextName(names Names) string {
	if len(names) == 0 {
		return ""
	}
	return names[s.rand.IntN(len(names))]
}
