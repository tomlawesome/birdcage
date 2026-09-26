package client

import "testing"

// TestSettingsHashIsOrderIndependent proves SettingsHash is a pure
// function of content, not of map iteration order -- required for it to
// agree with internal/store's own identical algorithm regardless of
// which order either side happens to range over a map.
func TestSettingsHashIsOrderIndependent(t *testing.T) {
	a := map[string]string{"segment_profile": "off", "bait_names": "old-fs-01,old-fs-02"}
	b := map[string]string{"bait_names": "old-fs-01,old-fs-02", "segment_profile": "off"}
	if SettingsHash(a) != SettingsHash(b) {
		t.Fatalf("SettingsHash depends on map order: %s != %s", SettingsHash(a), SettingsHash(b))
	}
}

// TestSettingsHashChangesWithContent proves a different value or a
// different key set produces a different hash -- the whole point of
// hashing an agent's effective settings.
func TestSettingsHashChangesWithContent(t *testing.T) {
	base := map[string]string{"segment_profile": "windows"}
	changedValue := map[string]string{"segment_profile": "off"}
	extraKey := map[string]string{"segment_profile": "windows", "pace_floor": "2h"}

	baseHash := SettingsHash(base)
	if baseHash == SettingsHash(changedValue) {
		t.Error("SettingsHash did not change when a value changed")
	}
	if baseHash == SettingsHash(extraKey) {
		t.Error("SettingsHash did not change when a key was added")
	}
}

// TestSettingsHashEmpty proves an empty map hashes to a fixed, non-empty
// value (sha256 of the empty string), the same as a nil map -- callers
// (agentSettings.Hash in cmd/mockingbird) rely on treating "nothing ever
// applied" as its own state rather than calling this function at all,
// but SettingsHash itself must not panic or behave differently for nil
// versus empty.
func TestSettingsHashEmpty(t *testing.T) {
	const wantEmptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := SettingsHash(map[string]string{}); got != wantEmptyHash {
		t.Errorf("SettingsHash(empty map) = %s, want %s (sha256 of the empty string)", got, wantEmptyHash)
	}
	if got := SettingsHash(nil); got != wantEmptyHash {
		t.Errorf("SettingsHash(nil) = %s, want %s", got, wantEmptyHash)
	}
}
