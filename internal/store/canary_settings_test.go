package store

import (
	"context"
	"errors"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

func TestCanarySettingKeysCoversEveryDefault(t *testing.T) {
	keys := CanarySettingKeys()
	if len(keys) != len(canarySettingDefs) {
		t.Fatalf("CanarySettingKeys() has %d keys, canarySettingDefs has %d", len(keys), len(canarySettingDefs))
	}
	for _, k := range keys {
		if _, ok := canarySettingDefs[k]; !ok {
			t.Errorf("CanarySettingKeys() includes %q, absent from canarySettingDefs", k)
		}
	}
}

func TestListCanarySettingsEmptyForUnknownCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		got, err := ListCanarySettings(context.Background(), database, "canary-a")
		if err != nil {
			t.Fatalf("ListCanarySettings: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("ListCanarySettings on an unwritten canary = %v, want empty", got)
		}
	})
}

func TestSetCanarySettingsRoundTripsAndVersions(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		insertCanary(t, database, Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z")})

		firstWrite := mustParse(t, "2026-01-01T00:00:00Z")
		if err := SetCanarySettings(ctx, database, "canary-a", agentkind.Honeypot, map[CanarySettingKey]string{
			CanarySettingSegmentProfile: "linux",
		}, firstWrite); err != nil {
			t.Fatalf("SetCanarySettings: %v", err)
		}

		got, err := ListCanarySettings(ctx, database, "canary-a")
		if err != nil {
			t.Fatalf("ListCanarySettings: %v", err)
		}
		if len(got) != 1 || got[0].Key != CanarySettingSegmentProfile || got[0].Value != "linux" || got[0].Version != 1 {
			t.Fatalf("ListCanarySettings after first write = %+v, want one row (segment_profile=linux, version=1)", got)
		}

		secondWrite := mustParse(t, "2026-01-02T00:00:00Z")
		if err := SetCanarySettings(ctx, database, "canary-a", agentkind.Honeypot, map[CanarySettingKey]string{
			CanarySettingSegmentProfile: "off",
		}, secondWrite); err != nil {
			t.Fatalf("SetCanarySettings (second write): %v", err)
		}
		got, err = ListCanarySettings(ctx, database, "canary-a")
		if err != nil {
			t.Fatalf("ListCanarySettings: %v", err)
		}
		if len(got) != 1 || got[0].Value != "off" || got[0].Version != 2 {
			t.Fatalf("ListCanarySettings after second write = %+v, want one row (segment_profile=off, version=2)", got)
		}
	})
}

func TestSetCanarySettingsRejectsUnknownKey(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z")})
		err := SetCanarySettings(context.Background(), database, "canary-a", agentkind.Honeypot,
			map[CanarySettingKey]string{"not_a_real_key": "x"}, mustParse(t, "2026-01-01T00:00:00Z"))
		if !errors.Is(err, ErrCanarySettingUnknown) {
			t.Fatalf("SetCanarySettings(unknown key) = %v, want ErrCanarySettingUnknown", err)
		}
		if got, err := ListCanarySettings(context.Background(), database, "canary-a"); err != nil || len(got) != 0 {
			t.Fatalf("a rejected write must store nothing: got=%v err=%v", got, err)
		}
	})
}

func TestSetCanarySettingsRejectsInvalidValue(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z")})
		err := SetCanarySettings(context.Background(), database, "canary-a", agentkind.Honeypot,
			map[CanarySettingKey]string{CanarySettingSegmentProfile: "not-a-profile"}, mustParse(t, "2026-01-01T00:00:00Z"))
		if !errors.Is(err, ErrCanarySettingInvalidValue) {
			t.Fatalf("SetCanarySettings(bad value) = %v, want ErrCanarySettingInvalidValue", err)
		}
	})
}

// TestSetCanarySettingsRejectsWrongKindAtomically proves the "one API
// write path" refuses a whole batch, not just the offending key, when
// one key doesn't apply to the canary's kind -- a valid segment_profile
// alongside it must not be partially applied.
func TestSetCanarySettingsRejectsWrongKindAtomically(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "scanner-a", Name: "scanner-a", Lane: "lan", Kind: agentkind.Scanner, HeartbeatIntervalS: 60, EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z")})
		err := SetCanarySettings(context.Background(), database, "scanner-a", agentkind.Scanner,
			map[CanarySettingKey]string{CanarySettingSegmentProfile: "windows"}, mustParse(t, "2026-01-01T00:00:00Z"))
		if !errors.Is(err, ErrCanarySettingWrongKind) {
			t.Fatalf("SetCanarySettings(segment_profile on a scanner) = %v, want ErrCanarySettingWrongKind", err)
		}
		if got, err := ListCanarySettings(context.Background(), database, "scanner-a"); err != nil || len(got) != 0 {
			t.Fatalf("a wrong-kind write must store nothing: got=%v err=%v", got, err)
		}
	})
}

func TestSettingsHashChangesWithContentNotOrder(t *testing.T) {
	a := []CanarySetting{
		{Key: CanarySettingSegmentProfile, Value: "windows"},
		{Key: CanarySettingBaitNames, Value: "old-fs-01,old-fs-02"},
	}
	b := []CanarySetting{
		{Key: CanarySettingBaitNames, Value: "old-fs-01,old-fs-02"},
		{Key: CanarySettingSegmentProfile, Value: "windows"},
	}
	if SettingsHash(a) != SettingsHash(b) {
		t.Fatalf("SettingsHash must not depend on slice order: %s != %s", SettingsHash(a), SettingsHash(b))
	}
	c := []CanarySetting{
		{Key: CanarySettingSegmentProfile, Value: "linux"},
		{Key: CanarySettingBaitNames, Value: "old-fs-01,old-fs-02"},
	}
	if SettingsHash(a) == SettingsHash(c) {
		t.Fatalf("SettingsHash must change when a value changes")
	}
}

func TestRecordAndGetCanarySettingsHash(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		insertCanary(t, database, Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z")})

		hash, at, err := GetCanarySettingsHash(ctx, database, "canary-a")
		if err != nil {
			t.Fatalf("GetCanarySettingsHash before any heartbeat: %v", err)
		}
		if hash != "" || at != nil {
			t.Fatalf("GetCanarySettingsHash before any heartbeat = (%q, %v), want (\"\", nil)", hash, at)
		}

		reportedAt := mustParse(t, "2026-01-01T01:00:00Z")
		if err := RecordCanarySettingsHash(ctx, database, "canary-a", "deadbeef", reportedAt); err != nil {
			t.Fatalf("RecordCanarySettingsHash: %v", err)
		}
		hash, at, err = GetCanarySettingsHash(ctx, database, "canary-a")
		if err != nil {
			t.Fatalf("GetCanarySettingsHash: %v", err)
		}
		if hash != "deadbeef" || at == nil || !at.Equal(reportedAt) {
			t.Fatalf("GetCanarySettingsHash = (%q, %v), want (\"deadbeef\", %v)", hash, at, reportedAt)
		}

		// An empty hash (an agent that predates issue #124, or one
		// mid-rollout) must never overwrite a previously recorded one.
		if err := RecordCanarySettingsHash(ctx, database, "canary-a", "", mustParse(t, "2026-01-01T02:00:00Z")); err != nil {
			t.Fatalf("RecordCanarySettingsHash(empty): %v", err)
		}
		hash, _, err = GetCanarySettingsHash(ctx, database, "canary-a")
		if err != nil {
			t.Fatalf("GetCanarySettingsHash: %v", err)
		}
		if hash != "deadbeef" {
			t.Fatalf("an empty settings_hash overwrote the previous value: got %q", hash)
		}
	})
}

func TestGetCanaryKind(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertCanary(t, database, Canary{ID: "scanner-a", Name: "scanner-a", Lane: "lan", Kind: agentkind.Scanner, HeartbeatIntervalS: 60, EnrolledAt: mustParse(t, "2026-01-01T00:00:00Z")})
		kind, err := GetCanaryKind(context.Background(), database, "scanner-a")
		if err != nil {
			t.Fatalf("GetCanaryKind: %v", err)
		}
		if kind != agentkind.Scanner {
			t.Fatalf("GetCanaryKind = %q, want %q", kind, agentkind.Scanner)
		}
		if _, err := GetCanaryKind(context.Background(), database, "unknown"); !errors.Is(err, ErrCanaryNotFound) {
			t.Fatalf("GetCanaryKind(unknown) = %v, want ErrCanaryNotFound", err)
		}
	})
}
