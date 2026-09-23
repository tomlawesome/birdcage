package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

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
