package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/db"
)

func TestSettingKeysCoversEveryDefault(t *testing.T) {
	keys := SettingKeys()
	if len(keys) != len(settingDefs) {
		t.Fatalf("SettingKeys() has %d keys, settingDefs has %d", len(keys), len(settingDefs))
	}
	for _, k := range keys {
		if _, ok := settingDefs[k]; !ok {
			t.Errorf("SettingKeys() includes %q, absent from settingDefs", k)
		}
	}
}

// TestGetSettingDefaultWhenUnset is #46's "a setting that has never been
// written must read as its documented default, not as an error or an empty
// value" -- proved for every known key, against a database no test in this
// file has written to yet.
func TestGetSettingDefaultWhenUnset(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		for key, def := range settingDefs {
			got, err := GetSetting(context.Background(), database, key)
			if err != nil {
				t.Fatalf("GetSetting(%q): %v", key, err)
			}
			if got != def.defaultValue {
				t.Errorf("GetSetting(%q) = %q, want default %q", key, got, def.defaultValue)
			}
		}
	})
}

// TestSetSettingThenGetSettingRoundTrips covers a bool-shaped and a
// schedule-shaped setting, proving SetSetting's write is exactly what
// GetSetting reads back, and that a second SetSetting overwrites rather
// than erroring or adding a second row.
func TestSetSettingThenGetSettingRoundTrips(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		firstWrite := mustParse(t, "2026-01-01T00:00:00Z")
		secondWrite := mustParse(t, "2026-01-02T00:00:00Z")

		if err := SetSetting(ctx, database, SettingSelfTestEnabled, "false", firstWrite); err != nil {
			t.Fatalf("SetSetting(selftest_enabled, false): %v", err)
		}
		got, err := GetSetting(ctx, database, SettingSelfTestEnabled)
		if err != nil {
			t.Fatalf("GetSetting(selftest_enabled): %v", err)
		}
		if got != "false" {
			t.Fatalf("GetSetting(selftest_enabled) = %q, want %q", got, "false")
		}

		if err := SetSetting(ctx, database, SettingRotationSchedule, "03:30", firstWrite); err != nil {
			t.Fatalf("SetSetting(rotation_schedule, 03:30): %v", err)
		}
		got, err = GetSetting(ctx, database, SettingRotationSchedule)
		if err != nil {
			t.Fatalf("GetSetting(rotation_schedule): %v", err)
		}
		if got != "03:30" {
			t.Fatalf("GetSetting(rotation_schedule) = %q, want %q", got, "03:30")
		}

		// Overwrite: the second write for the same key replaces the first
		// rather than erroring or leaving both readable.
		if err := SetSetting(ctx, database, SettingSelfTestEnabled, "true", secondWrite); err != nil {
			t.Fatalf("SetSetting(selftest_enabled, true) overwrite: %v", err)
		}
		got, err = GetSetting(ctx, database, SettingSelfTestEnabled)
		if err != nil {
			t.Fatalf("GetSetting(selftest_enabled) after overwrite: %v", err)
		}
		if got != "true" {
			t.Fatalf("GetSetting(selftest_enabled) after overwrite = %q, want %q", got, "true")
		}

		var n int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM settings WHERE key = ?`, string(SettingSelfTestEnabled)).Scan(&n); err != nil {
			t.Fatalf("count settings rows: %v", err)
		}
		if n != 1 {
			t.Fatalf("settings has %d rows for %q, want 1 (overwrite, not a second row)", n, SettingSelfTestEnabled)
		}
	})
}

// TestGetSettingUnknownKeyRejected and TestSetSettingUnknownKeyRejected are
// #46's "unknown keys must be rejected" -- a typo'd setting name must fail
// loudly on both the read and the write path, not silently return an empty
// value or store something nothing reads.
func TestGetSettingUnknownKeyRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		_, err := GetSetting(context.Background(), database, SettingKey("selftest_enable")) // typo: missing 'd'
		if !errors.Is(err, ErrSettingUnknown) {
			t.Fatalf("GetSetting(typo'd key) error = %v, want ErrSettingUnknown", err)
		}
	})
}

func TestSetSettingUnknownKeyRejected(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		err := SetSetting(context.Background(), database, SettingKey("selftest_enable"), "true", mustParse(t, "2026-01-01T00:00:00Z"))
		if !errors.Is(err, ErrSettingUnknown) {
			t.Fatalf("SetSetting(typo'd key) error = %v, want ErrSettingUnknown", err)
		}

		// Rejected before it ever reaches SQL: nothing was stored under the
		// typo'd name.
		var n int
		if qerr := database.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM settings`).Scan(&n); qerr != nil {
			t.Fatalf("count settings rows: %v", qerr)
		}
		if n != 0 {
			t.Fatalf("settings has %d rows after a rejected SetSetting, want 0", n)
		}
	})
}

// TestSetSettingInvalidValueRejected is #46's "a value that is not valid
// for its setting must be rejected with a message that says what was
// wrong" -- covered for both shapes of validator this slice has: a bool
// setting and a schedule-time setting.
func TestSetSettingInvalidValueRejected(t *testing.T) {
	cases := []struct {
		name        string
		key         SettingKey
		value       string
		wantMessage string
	}{
		{"bool typo", SettingSelfTestEnabled, "tru", `"tru"`},
		{"bool wrong spelling", SettingSelfTestUseRotationSchedule, "yes", `"yes"`},
		{"schedule bad format", SettingRotationSchedule, "3:00", `"3:00"`},
		{"schedule out of range hour", SettingSelfTestSchedule, "24:00", `"24:00"`},
		{"schedule out of range minute", SettingSelfTestSchedule, "12:60", `"12:60"`},
		{"schedule garbage", SettingRotationSchedule, "whenever", `"whenever"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachEngine(t, func(t *testing.T, database *db.DB) {
				err := SetSetting(context.Background(), database, tc.key, tc.value, mustParse(t, "2026-01-01T00:00:00Z"))
				if !errors.Is(err, ErrSettingInvalidValue) {
					t.Fatalf("SetSetting(%q, %q) error = %v, want ErrSettingInvalidValue", tc.key, tc.value, err)
				}
				if !strings.Contains(err.Error(), tc.wantMessage) {
					t.Errorf("SetSetting(%q, %q) error = %q, want it to mention %s", tc.key, tc.value, err.Error(), tc.wantMessage)
				}

				// A rejected value never lands in the table: GetSetting
				// still reads the default afterward.
				got, gerr := GetSetting(context.Background(), database, tc.key)
				if gerr != nil {
					t.Fatalf("GetSetting(%q) after rejected write: %v", tc.key, gerr)
				}
				if got != settingDefs[tc.key].defaultValue {
					t.Errorf("GetSetting(%q) after rejected write = %q, want default %q", tc.key, got, settingDefs[tc.key].defaultValue)
				}
			})
		})
	}
}

// TestSetSettingValidValuesAccepted rounds out the validator coverage with
// every value this slice's own defaults and examples use, so the
// validators are proven to accept the values GetSetting's own doc comment
// and the CLI's usage text promise work.
func TestSetSettingValidValuesAccepted(t *testing.T) {
	cases := []struct {
		key   SettingKey
		value string
	}{
		{SettingSelfTestEnabled, "true"},
		{SettingSelfTestEnabled, "false"},
		{SettingSelfTestUseRotationSchedule, "true"},
		{SettingSelfTestUseRotationSchedule, "false"},
		{SettingSelfTestSchedule, "00:00"},
		{SettingSelfTestSchedule, "23:59"},
		{SettingRotationSchedule, "09:05"},
	}
	for _, tc := range cases {
		t.Run(string(tc.key)+"="+tc.value, func(t *testing.T) {
			forEachEngine(t, func(t *testing.T, database *db.DB) {
				if err := SetSetting(context.Background(), database, tc.key, tc.value, mustParse(t, "2026-01-01T00:00:00Z")); err != nil {
					t.Fatalf("SetSetting(%q, %q): %v", tc.key, tc.value, err)
				}
				got, err := GetSetting(context.Background(), database, tc.key)
				if err != nil {
					t.Fatalf("GetSetting(%q): %v", tc.key, err)
				}
				if got != tc.value {
					t.Errorf("GetSetting(%q) = %q, want %q", tc.key, got, tc.value)
				}
			})
		})
	}
}
