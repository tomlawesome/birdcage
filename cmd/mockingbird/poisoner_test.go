package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
	"github.com/tomlawesome/birdcage/internal/agent/probe"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// swapSelftestLog points the package's selftest logger at log for one
// test, returning the restore. The logger is a package-level var (see
// command.go), which is what makes runAgentHandledTarget's own output
// testable without threading a logger through the command runner.
func swapSelftestLog(log *slog.Logger) func() {
	prev := selftestLog
	selftestLog = log
	return func() { selftestLog = prev }
}

// TestPoisonerEnabled is the one switch, no levels: only "0" turns the
// road off, the same rule envPortscan and envSNMP state.
func TestPoisonerEnabled(t *testing.T) {
	tests := map[string]bool{
		"":      true,
		"0":     false,
		"1":     true,
		"off":   true, // the profile, not this switch, is how "off" is said
		"false": true,
	}
	for value, want := range tests {
		t.Run("value="+value, func(t *testing.T) {
			if value == "" {
				t.Setenv(envPoisoner, "")
			} else {
				t.Setenv(envPoisoner, value)
			}
			if got := poisonerEnabled(); got != want {
				t.Errorf("poisonerEnabled() with %q = %v, want %v", value, got, want)
			}
		})
	}
}

// TestPoisonerSettingsDefaults is a canary with nothing set: the default
// profile, no operator names, and the provisional floor and ceiling.
func TestPoisonerSettingsDefaults(t *testing.T) {
	cfg, warnings := poisonerSettings()
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings with nothing set: %v", warnings)
	}
	if cfg.Profile != poisoner.DefaultProfile {
		t.Errorf("profile = %q, want %q", cfg.Profile, poisoner.DefaultProfile)
	}
	if len(cfg.OperatorNames) != 0 {
		t.Errorf("operator names = %v, want none", cfg.OperatorNames)
	}
	if cfg.Pace.FloorGap != poisoner.DefaultFloorGap || cfg.Pace.CeilingGap != poisoner.DefaultCeilingGap {
		t.Errorf("pacing = %+v, want the provisional defaults", cfg.Pace)
	}
}

// TestPoisonerSettingsReadsEveryVariable is the per-canary settings issue
// #86 design point 3 asks for: an operator changes one and restarts the
// container, without waiting for a release.
func TestPoisonerSettingsReadsEveryVariable(t *testing.T) {
	t.Setenv(envPoisonerProfile, "linux")
	t.Setenv(envPoisonerNames, "old-fs-01,printer-7")
	t.Setenv(envPoisonerFloor, "4h")
	t.Setenv(envPoisonerCeiling, "15m")
	t.Setenv(envPoisonerHours, "06:00-22:00/Mon,Sat")

	cfg, warnings := poisonerSettings()
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if cfg.Profile != poisoner.ProfileLinux {
		t.Errorf("profile = %q, want linux", cfg.Profile)
	}
	if len(cfg.OperatorNames) != 2 {
		t.Errorf("operator names = %v, want two", cfg.OperatorNames)
	}
	if cfg.Pace.FloorGap != 4*time.Hour {
		t.Errorf("floor = %v, want 4h", cfg.Pace.FloorGap)
	}
	if cfg.Pace.CeilingGap != 15*time.Minute {
		t.Errorf("ceiling = %v, want 15m", cfg.Pace.CeilingGap)
	}
	if cfg.Pace.Hours.Start != 6*60 || cfg.Pace.Hours.End != 22*60 {
		t.Errorf("hours = %d-%d minutes, want 360-1320", cfg.Pace.Hours.Start, cfg.Pace.Hours.End)
	}
	if !cfg.Pace.Hours.Days[time.Monday] || !cfg.Pace.Hours.Days[time.Saturday] || cfg.Pace.Hours.Days[time.Sunday] {
		t.Errorf("days = %v, want Monday and Saturday only", cfg.Pace.Hours.Days)
	}
}

// TestPoisonerSettingsWarnsRatherThanFailing: a typo in an optional
// tuning variable must not take the honeypot down, the same call
// parseIgnorePorts makes in portscan.go.
func TestPoisonerSettingsWarnsRatherThanFailing(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		check func(t *testing.T, cfg poisoner.Config)
	}{
		{
			name: "an unknown profile", key: envPoisonerProfile, value: "solaris",
			check: func(t *testing.T, cfg poisoner.Config) {
				if cfg.Profile != poisoner.DefaultProfile {
					t.Errorf("profile = %q, want the default", cfg.Profile)
				}
			},
		},
		{
			name: "a floor that is not a duration", key: envPoisonerFloor, value: "two hours",
			check: func(t *testing.T, cfg poisoner.Config) {
				if cfg.Pace.FloorGap != poisoner.DefaultFloorGap {
					t.Errorf("floor = %v, want the default", cfg.Pace.FloorGap)
				}
			},
		},
		{
			name: "a negative ceiling", key: envPoisonerCeiling, value: "-5m",
			check: func(t *testing.T, cfg poisoner.Config) {
				if cfg.Pace.CeilingGap != poisoner.DefaultCeilingGap {
					t.Errorf("ceiling = %v, want the default", cfg.Pace.CeilingGap)
				}
			},
		},
		{
			name: "working hours that do not parse", key: envPoisonerHours, value: "nine to five",
			check: func(t *testing.T, cfg poisoner.Config) {
				if cfg.Pace.Hours != poisoner.DefaultWorkingHours() {
					t.Errorf("hours = %+v, want the default", cfg.Pace.Hours)
				}
			},
		},
		{
			name: "no usable bait name", key: envPoisonerNames, value: "_,__,-",
			check: func(t *testing.T, cfg poisoner.Config) {
				if len(cfg.OperatorNames) != 0 {
					t.Errorf("operator names = %v, want none", cfg.OperatorNames)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			cfg, warnings := poisonerSettings()
			if len(warnings) == 0 {
				t.Fatalf("%s=%q produced no warning", tc.key, tc.value)
			}
			if !strings.Contains(strings.Join(warnings, " "), tc.key) {
				t.Errorf("the warning does not name the variable to fix: %v", warnings)
			}
			tc.check(t, cfg)
		})
	}
}

// TestPoisonerSettingsNeverLogsABaitName is this road's half of the rule
// the detector package enforces on its own side: a warning about an
// unusable name says how many and what the rule is, never which name.
// This binary's stdout is readable by whoever breaks into the box, and
// the bait only works while nobody knows which names it uses.
func TestPoisonerSettingsNeverLogsABaitName(t *testing.T) {
	// A mix: two usable, two not, and one over the length limit.
	t.Setenv(envPoisonerNames, "old-fs-01,printer-7,bad_name,also bad,"+strings.Repeat("z", 40))
	cfg, warnings := poisonerSettings()
	joined := strings.Join(warnings, " ")
	if joined == "" {
		t.Fatal("no warning for the refused entries")
	}
	for _, name := range []string{"old-fs-01", "printer-7", "bad_name", "also bad", strings.Repeat("z", 40)} {
		if strings.Contains(joined, name) {
			t.Errorf("the warning quotes %q: %s", name, joined)
		}
	}
	// The usable ones are still used -- a bad entry must not throw away
	// the good ones.
	if len(cfg.OperatorNames) != 2 {
		t.Errorf("operator names = %v, want the two usable entries", cfg.OperatorNames)
	}
}

// TestPoisonerSettingsKeepsAtMostThree is decision 31's "two or three
// names": a longer list is not more convincing, and every extra name is
// more traffic from a host meant to look ordinary.
func TestPoisonerSettingsKeepsAtMostThree(t *testing.T) {
	t.Setenv(envPoisonerNames, "a,b,c,d,e")
	cfg, warnings := poisonerSettings()
	if len(cfg.OperatorNames) != poisoner.MaxOperatorNames {
		t.Errorf("operator names = %v, want %d", cfg.OperatorNames, poisoner.MaxOperatorNames)
	}
	if len(warnings) == 0 {
		t.Error("the extra names were dropped silently")
	}
}

// TestPoisonerInventoryLine covers what main prints at startup: enough
// for an operator to tell a quiet segment from a missing capability, and
// nothing an attacker reading this box's stdout can use.
func TestPoisonerInventoryLine(t *testing.T) {
	tests := []struct {
		name string
		inv  poisonerInventory
		want string
	}{
		{name: "off", inv: poisonerInventory{}, want: "poisoner detection off"},
		{
			name: "active",
			inv:  poisonerInventory{Active: true, Profile: poisoner.ProfileWindows, Sending: true, Counting: 3},
			want: "poisoner detection active (profile windows), counting 3 of 3 ports",
		},
		{
			name: "listening only",
			inv:  poisonerInventory{Active: true, Profile: poisoner.ProfileOff, Counting: 2},
			want: "poisoner detection listening only (profile off), counting 2 of 3 ports",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.inv.line(); got != tc.want {
				t.Errorf("line() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPlural keeps the warnings reading as English rather than as
// "1 entries were".
func TestPlural(t *testing.T) {
	if got := plural(1, "y", "ies"); got != "y" {
		t.Errorf("plural(1) = %q, want %q", got, "y")
	}
	for _, n := range []int{0, 2, 7} {
		if got := plural(n, "y", "ies"); got != "ies" {
			t.Errorf("plural(%d) = %q, want %q", n, got, "ies")
		}
	}
}

// TestRunPoisonerRoadWithNoDetector is the no-op main depends on: a nil
// detector must not panic, so main can start the same goroutine whether
// or not the road opened.
func TestRunPoisonerRoadWithNoDetector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runPoisonerRoad(ctx, nil, discardLogger())
}

// TestSubmitPoisonerEventQueuesWithAnID proves the fifth road into the
// queue mints an id the same way the other four do, so Push's
// deduplication works across all of them.
func TestSubmitPoisonerEventQueuesWithAnID(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{})
	message := []byte(`{"dst_host":"10.0.0.5","logtype":30001,"src_host":"10.0.0.66"}`)
	if err := in.SubmitPoisonerEvent(message); err != nil {
		t.Fatalf("SubmitPoisonerEvent: %v", err)
	}
	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
	// The same event twice is one event: the id is the SHA-256 of the
	// bytes, so a repeat deduplicates rather than double-alerting.
	if err := in.SubmitPoisonerEvent(message); err != nil {
		t.Fatalf("SubmitPoisonerEvent again: %v", err)
	}
	if got := in.Queue.Depth(); got != 1 {
		t.Errorf("queue depth after the same event twice = %d, want 1", got)
	}
}

// TestNewPoisonerRoadOffReturnsNoDetector is the switch's whole effect:
// nothing is built, nothing is opened, and main's goroutine is a no-op.
func TestNewPoisonerRoadOffReturnsNoDetector(t *testing.T) {
	t.Setenv(envPoisoner, "0")
	in, _ := newTestIntake(t, queue.Config{})
	detector, inv := newPoisonerRoad(in, discardLogger())
	if detector != nil {
		t.Error("a detector was built with the road switched off")
	}
	if inv.Active {
		t.Error("the inventory claims the road is active")
	}
	if got := inv.line(); got != "poisoner detection off" {
		t.Errorf("startup line = %q", got)
	}
}

// TestNewPoisonerRoadBuildsTheDetector runs the real startup path. It uses
// the "off" profile deliberately: this test runs on a developer's machine
// and in CI, and a profile that sends would put real bait queries on
// whatever network those are attached to. "off" exercises everything the
// road does except the sending, which is what the detector's own package
// tests cover.
//
// It does not require the three low ports to bind -- an ordinary test host
// has no lowered privileged-port floor, so they will not -- and asserts
// only what is true either way.
func TestNewPoisonerRoadBuildsTheDetector(t *testing.T) {
	t.Setenv(envPoisonerProfile, "off")
	t.Setenv(envPoisonerHours, "00:00-24:00/Mon,Tue,Wed,Thu,Fri,Sat,Sun")
	in, _ := newTestIntake(t, queue.Config{})
	log, buf := captureLogger()

	detector, inv := newPoisonerRoad(in, log)
	if detector == nil {
		// Only reachable on a host with no interface to ask on and no port
		// that would bind, which is a real state (a container run with
		// --network none) and not a failure of this code.
		t.Skipf("nothing opened on this host: %s", buf.String())
	}
	if !inv.Active {
		t.Error("a detector was built but the inventory says the road is off")
	}
	if inv.Profile != poisoner.ProfileOff {
		t.Errorf("inventory profile = %q, want off", inv.Profile)
	}
	if inv.Sending {
		t.Error("the off profile reports that it is sending")
	}
	if inv.Counting != detector.Listening() {
		t.Errorf("inventory counts %d ports, detector has %d", inv.Counting, detector.Listening())
	}

	// And the run goroutine returns cleanly when its context ends, rather
	// than holding shutdown up.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	runPoisonerRoad(ctx, detector, log)

	// Nothing this road logs at startup may name a bait name. There are
	// none configured here, so the check is that the derived ones -- which
	// the detector does know -- did not reach the log either.
	if strings.Contains(buf.String(), poisoner.WPADName+",") {
		t.Errorf("the startup log lists the name rotation: %s", buf.String())
	}
}

// fakeBait stands in for the poisoner detector in the self-test tests, so
// both outcomes can be driven without opening a multicast socket.
type fakeBait struct {
	answers []poisoner.Answer
	err     error
	calls   int
	proto   poisoner.Protocol
	name    string
}

func (f *fakeBait) LookupOnce(_ context.Context, proto poisoner.Protocol, name string) ([]poisoner.Answer, error) {
	f.calls++
	f.proto, f.name = proto, name
	return f.answers, f.err
}

// TestRunAgentHandledTargetGradesSilenceAsAPass is #86 slice C's grading,
// which is inverted from every other self-test target: the names the
// detector asks for do not exist, so the only correct answer is none.
func TestRunAgentHandledTargetGradesSilenceAsAPass(t *testing.T) {
	log, buf := captureLogger()
	restore := swapSelftestLog(log)
	defer restore()

	bait := &fakeBait{}
	runAgentHandledTarget(context.Background(), bait, "run-1", poisoner.Service())

	if bait.calls != 1 {
		t.Fatalf("LookupOnce called %d times, want 1 -- a self-test is one lookup, not a burst", bait.calls)
	}
	// An empty protocol and name let the detector choose from its own
	// profile and rotation, so this caller never handles a bait name.
	if bait.proto != "" || bait.name != "" {
		t.Errorf("LookupOnce called with (%q, %q), want both empty", bait.proto, bait.name)
	}
	line := buf.String()
	if !strings.Contains(line, "nothing answered") {
		t.Errorf("silence was not reported as the pass: %q", line)
	}
	if strings.Contains(line, "ANSWERED") {
		t.Errorf("silence was reported as an answer: %q", line)
	}
}

// TestRunAgentHandledTargetReportsAnAnswer: an answer is the worst result
// there is, not a better one than silence, and the log names the
// answering address without naming the bait.
func TestRunAgentHandledTargetReportsAnAnswer(t *testing.T) {
	log, buf := captureLogger()
	restore := swapSelftestLog(log)
	defer restore()

	bait := &fakeBait{answers: []poisoner.Answer{{
		Source:   "10.0.0.66",
		Protocol: poisoner.ProtocolLLMNR,
		Name:     "fs-lon-02",
		MAC:      "aa:bb:cc:dd:ee:ff",
	}}}
	runAgentHandledTarget(context.Background(), bait, "run-1", poisoner.Service())

	line := buf.String()
	if !strings.Contains(line, "ANSWERED") || !strings.Contains(line, "10.0.0.66") {
		t.Errorf("the answer was not reported with its source: %q", line)
	}
	// The bait name and the MAC belong in the event, not on this box's
	// stdout -- see internal/agent/poisoner's package comment.
	if strings.Contains(line, "fs-lon-02") {
		t.Errorf("the log names the bait name: %q", line)
	}
	if strings.Contains(line, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("the log names the MAC: %q", line)
	}
}

// TestRunAgentHandledTargetWithNoDetector: the poisoner road being off
// must read as skipped, never as a pass. A canary that never asked must
// not report the silence that means "asked, and nothing answered".
func TestRunAgentHandledTargetWithNoDetector(t *testing.T) {
	log, buf := captureLogger()
	restore := swapSelftestLog(log)
	defer restore()

	runAgentHandledTarget(context.Background(), nil, "run-1", poisoner.Service())
	line := buf.String()
	if !strings.Contains(line, "skipped") {
		t.Errorf("a missing detector was not reported as skipped: %q", line)
	}
	if strings.Contains(line, "nothing answered") {
		t.Errorf("a missing detector was graded as a pass: %q", line)
	}
}

// TestRunAgentHandledTargetWithALookupFailure: a bait lookup that never
// reached the wire is not silence either.
func TestRunAgentHandledTargetWithALookupFailure(t *testing.T) {
	log, buf := captureLogger()
	restore := swapSelftestLog(log)
	defer restore()

	runAgentHandledTarget(context.Background(), &fakeBait{err: poisoner.ErrNotSending}, "run-1", poisoner.Service())
	line := buf.String()
	if !strings.Contains(line, "did not go out") {
		t.Errorf("a failed lookup was not reported: %q", line)
	}
	if strings.Contains(line, "nothing answered") {
		t.Errorf("a failed lookup was graded as a pass: %q", line)
	}
}

// TestRunAgentHandledTargetRefusesAnUnknownService guards the dispatch:
// if probe ever reports another service as agent-handled, this binary says
// so rather than running a bait lookup for it.
func TestRunAgentHandledTargetRefusesAnUnknownService(t *testing.T) {
	log, buf := captureLogger()
	restore := swapSelftestLog(log)
	defer restore()

	bait := &fakeBait{}
	runAgentHandledTarget(context.Background(), bait, "run-1", "smb")
	if bait.calls != 0 {
		t.Error("a bait lookup ran for a service that is not the poisoner")
	}
	if !strings.Contains(buf.String(), "nothing to run") {
		t.Errorf("the unknown service was not reported: %q", buf.String())
	}
}

// TestProbeReportsThePoisonerAsAgentHandled ties the two halves together:
// internal/agent/probe must report a poisoner target as this binary's work
// rather than as a missing carrier, or the target would read as a gap.
func TestProbeReportsThePoisonerAsAgentHandled(t *testing.T) {
	if !probe.AgentHandled(poisoner.Service()) {
		t.Errorf("probe.AgentHandled(%q) = false, want true", poisoner.Service())
	}
	for _, other := range []string{"ssh", "portscan", "snmp", "smb"} {
		if probe.AgentHandled(other) {
			t.Errorf("probe.AgentHandled(%q) = true, want false", other)
		}
	}
}

// fakeBaitNames stands in for the detector in the heartbeat tests.
type fakeBaitNames struct{ names poisoner.Names }

func (f fakeBaitNames) BaitNames() poisoner.Names { return f.names }

// TestReportedBaitNames is #86 slice D's agent half: the canary page shows
// an operator what their canaries are baiting with, so the heartbeat has to
// carry it.
func TestReportedBaitNames(t *testing.T) {
	tests := []struct {
		name string
		bait baitNames
		want string
	}{
		// A nil interface is the road switched off. Reporting nothing is not
		// the same as reporting an empty list, and birdcage stores the
		// difference (internal/store's poisoner_names is NULL for one and
		// never the other), so the facts column can leave the row out.
		{name: "the road off", bait: nil, want: ""},
		{name: "a detector with no names", bait: fakeBaitNames{}, want: ""},
		{name: "one name", bait: fakeBaitNames{names: poisoner.Names{"wpad"}}, want: "wpad"},
		{
			name: "the whole rotation, in order",
			bait: fakeBaitNames{names: poisoner.Names{"old-fs-01", "printer-7", "wpad"}},
			want: "old-fs-01,printer-7,wpad",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := reportedBaitNames(tc.bait); got != tc.want {
				t.Errorf("reportedBaitNames = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReportedBaitNamesHandlesATypedNilDetector: main hands the real
// *poisoner.Detector straight in, and a nil one of those is not a nil
// interface. The detector's own BaitNames is nil-safe, so this must come
// back empty rather than panicking.
func TestReportedBaitNamesHandlesATypedNilDetector(t *testing.T) {
	var d *poisoner.Detector
	if got := reportedBaitNames(d); got != "" {
		t.Errorf("reportedBaitNames(typed nil) = %q, want the empty string", got)
	}
}

// TestCurrentSelfReportCarriesTheBaitNames proves the wiring, not just the
// helper: what main builds for the heartbeat has the names on it.
func TestCurrentSelfReportCarriesTheBaitNames(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{})
	report := currentSelfReport("v9.9.9", in, fakeBaitNames{names: poisoner.Names{"old-fs-01", "wpad"}})
	if report.PoisonerNames != "old-fs-01,wpad" {
		t.Errorf("SelfReport.PoisonerNames = %q, want \"old-fs-01,wpad\"", report.PoisonerNames)
	}
	// And a canary with the road off reports none, rather than an empty list
	// birdcage would have to store.
	if got := currentSelfReport("v9.9.9", in, nil).PoisonerNames; got != "" {
		t.Errorf("SelfReport.PoisonerNames with no detector = %q, want the empty string", got)
	}
}
