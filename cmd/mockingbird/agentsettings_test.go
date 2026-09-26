package main

import (
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
)

// fakeLiveSettable records SetLiveSettings calls without opening any
// socket, so Apply's own logic is testable in isolation from the real
// Detector.
type fakeLiveSettable struct {
	calls   int
	profile poisoner.Profile
	names   poisoner.Names
	pace    poisoner.PaceSettings
}

func (f *fakeLiveSettable) SetLiveSettings(profile poisoner.Profile, names poisoner.Names, pace poisoner.PaceSettings) {
	f.calls++
	f.profile = profile
	f.names = names
	f.pace = pace
}

func TestAgentSettingsHashEmptyUntilFirstPush(t *testing.T) {
	s := newAgentSettings(poisoner.Config{Profile: poisoner.ProfileWindows})
	if got := s.Hash(); got != "" {
		t.Fatalf("Hash() before any push = %q, want empty", got)
	}
}

func TestAgentSettingsApplyValidatesAndApplies(t *testing.T) {
	s := newAgentSettings(poisoner.Config{Profile: poisoner.ProfileWindows, Pace: poisoner.DefaultPaceSettings()})
	fake := &fakeLiveSettable{}

	s.Apply(map[string]string{
		"segment_profile": "off",
		"bait_names":      "custom-fs-01,custom-fs-02",
		"pace_floor":      "3h",
	}, fake, discardLogger())

	if fake.calls != 1 {
		t.Fatalf("SetLiveSettings was called %d times, want 1", fake.calls)
	}
	if fake.profile != poisoner.ProfileOff {
		t.Errorf("applied profile = %q, want off", fake.profile)
	}
	wantNames := poisoner.Names{"custom-fs-01", "custom-fs-02"}
	if len(fake.names) != len(wantNames) || fake.names[0] != wantNames[0] || fake.names[1] != wantNames[1] {
		t.Errorf("applied names = %v, want %v", fake.names, wantNames)
	}
	if fake.pace.FloorGap.String() != "3h0m0s" {
		t.Errorf("applied pace floor = %v, want 3h", fake.pace.FloorGap)
	}

	hash := s.Hash()
	if hash == "" {
		t.Fatal("Hash() after a successful push is empty, want a real digest")
	}

	// Applying the identical values again must report the identical
	// hash -- SettingsHash is a pure function of content.
	s2 := newAgentSettings(poisoner.Config{})
	s2.Apply(map[string]string{
		"segment_profile": "off",
		"bait_names":      "custom-fs-01,custom-fs-02",
		"pace_floor":      "3h",
	}, &fakeLiveSettable{}, discardLogger())
	if s2.Hash() != hash {
		t.Errorf("two agents applying the identical push produced different hashes: %q != %q", s2.Hash(), hash)
	}
}

func TestAgentSettingsApplyRejectsUnknownAndInvalidKeys(t *testing.T) {
	s := newAgentSettings(poisoner.Config{Profile: poisoner.ProfileWindows})
	fake := &fakeLiveSettable{}

	s.Apply(map[string]string{
		"segment_profile": "not-a-real-profile",
		"not_a_real_key":  "x",
	}, fake, discardLogger())

	if fake.calls != 0 {
		t.Fatalf("SetLiveSettings was called %d times for an all-invalid push, want 0", fake.calls)
	}
	if s.Hash() != "" {
		t.Fatalf("Hash() after an all-invalid push = %q, want empty (nothing was ever validly applied)", s.Hash())
	}
}

// TestAgentSettingsApplyKeepsUnpushedKeysInForce proves a push naming
// only one key never reverts the others to their startup defaults.
func TestAgentSettingsApplyKeepsUnpushedKeysInForce(t *testing.T) {
	s := newAgentSettings(poisoner.Config{Profile: poisoner.ProfileWindows, Pace: poisoner.DefaultPaceSettings()})
	fake := &fakeLiveSettable{}

	s.Apply(map[string]string{"segment_profile": "linux"}, fake, discardLogger())
	s.Apply(map[string]string{"pace_floor": "90m"}, fake, discardLogger())

	if fake.profile != poisoner.ProfileLinux {
		t.Errorf("profile after the second push = %q, want linux (unchanged by a push that did not name it)", fake.profile)
	}
	if fake.pace.FloorGap.String() != "1h30m0s" {
		t.Errorf("pace floor after the second push = %v, want 1h30m", fake.pace.FloorGap)
	}
}

func TestAgentSettingsApplyNilDetectorOrEmptyPushIsNoop(t *testing.T) {
	s := newAgentSettings(poisoner.Config{})
	s.Apply(nil, &fakeLiveSettable{}, discardLogger())
	s.Apply(map[string]string{"segment_profile": "off"}, nil, discardLogger())
	if s.Hash() != "" {
		t.Fatalf("Hash() = %q after a nil detector/empty push, want empty", s.Hash())
	}
}
