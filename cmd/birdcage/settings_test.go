package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/store"
)

// TestSettingsListShowsDefaultsWhenUnset is issue #46's "a setting that
// has never been written must read as its documented default" proved
// through the CLI path specifically: a fresh database, never touched by
// `settings set`, still lists every known key with its default value.
func TestSettingsListShowsDefaultsWhenUnset(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	out, err := captureStdout(t, func() error { return runSettingsList(nil) })
	if err != nil {
		t.Fatalf("runSettingsList: %v", err)
	}
	for _, want := range []string{
		"selftest_enabled=true",
		"selftest_schedule=00:00",
		"selftest_use_rotation_schedule=true",
		"rotation_schedule=00:00",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("settings list output = %q, want it to contain %q", out, want)
		}
	}
}

// TestSettingsSetThenGetRoundTrips is the CLI's own "write and read back"
// behaviour: `settings set` followed by `settings get` on the same key
// returns exactly what was set, and `settings list` reflects it too.
func TestSettingsSetThenGetRoundTrips(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	setOut, err := captureStdout(t, func() error {
		return runSettingsSet([]string{"rotation_schedule", "04:30"})
	})
	if err != nil {
		t.Fatalf("runSettingsSet: %v", err)
	}
	if !strings.Contains(setOut, "rotation_schedule=04:30") {
		t.Errorf("settings set output = %q, want it to echo rotation_schedule=04:30", setOut)
	}

	getOut, err := captureStdout(t, func() error {
		return runSettingsGet([]string{"rotation_schedule"})
	})
	if err != nil {
		t.Fatalf("runSettingsGet: %v", err)
	}
	if strings.TrimSpace(getOut) != "04:30" {
		t.Errorf("settings get output = %q, want %q", getOut, "04:30")
	}

	listOut, err := captureStdout(t, func() error { return runSettingsList(nil) })
	if err != nil {
		t.Fatalf("runSettingsList: %v", err)
	}
	if !strings.Contains(listOut, "rotation_schedule=04:30") {
		t.Errorf("settings list output = %q, want it to contain rotation_schedule=04:30", listOut)
	}
}

// TestSettingsGetUnknownKeyFailsLoudly and
// TestSettingsSetUnknownKeyFailsLoudly are #46's "a typo in an operator's
// CLI call must fail loudly, not silently store a setting nothing reads",
// proved through the CLI commands rather than store.GetSetting/SetSetting
// directly.
func TestSettingsGetUnknownKeyFailsLoudly(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	_, err := captureStdout(t, func() error {
		return runSettingsGet([]string{"selftest_enable"}) // typo: missing 'd'
	})
	if !errors.Is(err, store.ErrSettingUnknown) {
		t.Fatalf("runSettingsGet(typo) error = %v, want store.ErrSettingUnknown", err)
	}
}

func TestSettingsSetUnknownKeyFailsLoudly(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	_, err := captureStdout(t, func() error {
		return runSettingsSet([]string{"selftest_enable", "true"}) // typo: missing 'd'
	})
	if !errors.Is(err, store.ErrSettingUnknown) {
		t.Fatalf("runSettingsSet(typo) error = %v, want store.ErrSettingUnknown", err)
	}

	// Nothing typo'd was stored: listing afterward still shows only
	// documented defaults, none of them under the typo'd name.
	out, err := captureStdout(t, func() error { return runSettingsList(nil) })
	if err != nil {
		t.Fatalf("runSettingsList: %v", err)
	}
	if strings.Contains(out, "selftest_enable=") {
		t.Errorf("settings list output = %q, should not contain the typo'd key", out)
	}
}

// TestSettingsSetInvalidValueFailsWithUsefulMessage is #46's "a value that
// is not valid for its setting must be rejected with a message that says
// what was wrong", proved through the CLI command.
func TestSettingsSetInvalidValueFailsWithUsefulMessage(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	_, err := captureStdout(t, func() error {
		return runSettingsSet([]string{"selftest_enabled", "definitely"})
	})
	if !errors.Is(err, store.ErrSettingInvalidValue) {
		t.Fatalf("runSettingsSet(bad bool) error = %v, want store.ErrSettingInvalidValue", err)
	}
	if !strings.Contains(err.Error(), `"definitely"`) {
		t.Errorf("runSettingsSet(bad bool) error = %q, want it to mention the bad value", err.Error())
	}
}

// TestSettingsSetUsageErrors covers the argument-count checks each
// subcommand does before ever touching the database.
func TestSettingsSetUsageErrors(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	if err := runSettingsGet(nil); err == nil {
		t.Error("runSettingsGet(no args) = nil error, want a usage error")
	}
	if err := runSettingsGet([]string{"a", "b"}); err == nil {
		t.Error("runSettingsGet(two args) = nil error, want a usage error")
	}
	if err := runSettingsSet([]string{"only_one"}); err == nil {
		t.Error("runSettingsSet(one arg) = nil error, want a usage error")
	}
	if err := runSettingsList([]string{"unexpected"}); err == nil {
		t.Error("runSettingsList(unexpected arg) = nil error, want a usage error")
	}
}
