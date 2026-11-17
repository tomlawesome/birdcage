package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

type clampRow struct {
	agent, key, value string
	version           int
}

func seedClampRows(t *testing.T, database *db.DB, rows []clampRow) {
	t.Helper()
	for _, r := range rows {
		if _, err := database.Exec(`INSERT INTO canary_settings (agent_id, key, value, version, updated_at) VALUES (?, ?, ?, ?, ?)`,
			r.agent, r.key, r.value, r.version, "2026-01-01T00:00:00Z"); err != nil {
			t.Fatalf("seed %+v: %v", r, err)
		}
	}
}

func readClampRow(t *testing.T, database *db.DB, agent, key string) (string, int) {
	t.Helper()
	var v string
	var ver int
	if err := database.QueryRow(`SELECT value, version FROM canary_settings WHERE agent_id = ? AND key = ?`, agent, key).Scan(&v, &ver); err != nil {
		t.Fatalf("read %s/%s: %v", agent, key, err)
	}
	return v, ver
}

func countAudit(t *testing.T, database *db.DB) int {
	t.Helper()
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

// auditText returns each audit row as one "action target reason" string.
func auditText(t *testing.T, database *db.DB) []string {
	t.Helper()
	rs, err := database.Query(`SELECT action, target, reason FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	defer func() { _ = rs.Close() }()
	var out []string
	for rs.Next() {
		var a, tg, r string
		if err := rs.Scan(&a, &tg, &r); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		out = append(out, a+" "+tg+" "+r)
	}
	return out
}

func clampSeed() []clampRow {
	return []clampRow{
		{"canary-c", "pace_ceiling", "500ms", 3},
		{"canary-a", "pace_floor", "2h", 2},
		{"canary-b", "pace_floor", "999ms", 1},
		{"canary-a", "segment_profile", "linux", 4},
		{"canary-b", "pace_ceiling", "1s", 5},
		{"canary-c", "pace_floor", "", 7},
		{"canary-a", "pace_ceiling", "30ms", 6},
		{"canary-d", "bait_names", "100ms", 9},
	}
}

func TestClampLegacyPaceSettingsRaisesSub1sValues(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		seedClampRows(t, database, clampSeed())
		auditBefore := countAudit(t, database)

		changed, err := ClampLegacyPaceSettings(ctx, database, mustParse(t, "2026-02-01T00:00:00Z"))
		if err != nil {
			t.Fatalf("ClampLegacyPaceSettings: %v", err)
		}
		if changed != 3 {
			t.Errorf("changed = %d, want 3", changed)
		}
		want := []clampRow{
			{"canary-c", "pace_ceiling", "1s", 4},
			{"canary-b", "pace_floor", "1s", 2},
			{"canary-a", "pace_ceiling", "1s", 7},
			// untouched, versions included
			{"canary-a", "pace_floor", "2h", 2},
			{"canary-a", "segment_profile", "linux", 4},
			{"canary-b", "pace_ceiling", "1s", 5},
			{"canary-c", "pace_floor", "", 7},
			{"canary-d", "bait_names", "100ms", 9},
		}
		for _, w := range want {
			if v, ver := readClampRow(t, database, w.agent, w.key); v != w.value || ver != w.version {
				t.Errorf("%s/%s = (%q, v%d), want (%q, v%d)", w.agent, w.key, v, ver, w.value, w.version)
			}
		}
		if got := countAudit(t, database) - auditBefore; got != 3 {
			t.Errorf("audit rows added = %d, want 3 (one per changed setting)", got)
		}
	})
}

func TestClampLegacyPaceSettingsAuditNamesAgentKeyOldAndNew(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		seedClampRows(t, database, clampSeed())
		auditBefore := countAudit(t, database)
		if _, err := ClampLegacyPaceSettings(context.Background(), database, mustParse(t, "2026-02-01T00:00:00Z")); err != nil {
			t.Fatalf("ClampLegacyPaceSettings: %v", err)
		}
		rows := auditText(t, database)[auditBefore:]
		for _, w := range []struct{ agent, key, old string }{
			{"canary-c", "pace_ceiling", "500ms"},
			{"canary-b", "pace_floor", "999ms"},
			{"canary-a", "pace_ceiling", "30ms"},
		} {
			found := false
			for _, r := range rows {
				if strings.Contains(r, w.agent) && strings.Contains(r, w.key) && strings.Contains(r, w.old) && strings.Contains(r, "1s") {
					found = true
				}
			}
			if !found {
				t.Errorf("no audit row names %s, %s, old %q and new \"1s\"; rows: %q", w.agent, w.key, w.old, rows)
			}
		}
	})
}

func TestClampLegacyPaceSettingsIsIdempotent(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		seedClampRows(t, database, clampSeed())
		now := mustParse(t, "2026-02-01T00:00:00Z")
		if _, err := ClampLegacyPaceSettings(ctx, database, now); err != nil {
			t.Fatalf("first run: %v", err)
		}
		auditAfterFirst := countAudit(t, database)
		_, verBefore := readClampRow(t, database, "canary-a", "pace_ceiling")

		changed, err := ClampLegacyPaceSettings(ctx, database, now.Add(time.Hour))
		if err != nil {
			t.Fatalf("second run: %v", err)
		}
		if changed != 0 {
			t.Errorf("second run changed = %d, want 0", changed)
		}
		if got := countAudit(t, database); got != auditAfterFirst {
			t.Errorf("second run added %d audit rows, want 0", got-auditAfterFirst)
		}
		if _, ver := readClampRow(t, database, "canary-a", "pace_ceiling"); ver != verBefore {
			t.Errorf("second run bumped version %d -> %d", verBefore, ver)
		}
	})
}

func TestClampLegacyPaceSettingsNothingToDo(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		seedClampRows(t, database, []clampRow{
			{"canary-b", "pace_floor", "1s", 2},
			{"canary-a", "pace_ceiling", "4h", 1},
			{"canary-a", "pace_floor", "", 3},
		})
		auditBefore := countAudit(t, database)
		changed, err := ClampLegacyPaceSettings(context.Background(), database, mustParse(t, "2026-02-01T00:00:00Z"))
		if err != nil || changed != 0 {
			t.Fatalf("ClampLegacyPaceSettings = (%d, %v), want (0, nil)", changed, err)
		}
		if countAudit(t, database) != auditBefore {
			t.Errorf("audit rows written when nothing changed")
		}
	})
}

func TestClampLegacyPaceSettingsFloorAndCeilingBothClampedAndValid(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		seedClampRows(t, database, []clampRow{
			{"canary-a", "pace_ceiling", "200ms", 1},
			{"canary-a", "pace_floor", "100ms", 1},
		})
		changed, err := ClampLegacyPaceSettings(ctx, database, mustParse(t, "2026-02-01T00:00:00Z"))
		if err != nil || changed != 2 {
			t.Fatalf("ClampLegacyPaceSettings = (%d, %v), want (2, nil)", changed, err)
		}
		for _, k := range []string{"pace_floor", "pace_ceiling"} {
			if v, ver := readClampRow(t, database, "canary-a", k); v != "1s" || ver != 2 {
				t.Errorf("%s = (%q, v%d), want (\"1s\", v2)", k, v, ver)
			}
			if err := validatePaceDuration("1s"); err != nil {
				t.Fatalf("validatePaceDuration(1s): %v", err)
			}
		}
		// The result must pass today's validation as a whole settings write:
		// a no-op re-write of the stored values is accepted.
		stored, err := ListCanarySettings(ctx, database, "canary-a")
		if err != nil {
			t.Fatalf("ListCanarySettings: %v", err)
		}
		updates := map[CanarySettingKey]string{}
		for _, s := range stored {
			updates[s.Key] = s.Value
		}
		if err := SetCanarySettings(ctx, database, "canary-a", "honeypot", updates, mustParse(t, "2026-02-02T00:00:00Z"), "test"); err != nil {
			t.Errorf("SetCanarySettings with the clamped values = %v, want nil", err)
		}
	})
}

func TestClampLegacyPaceSettingsLeavesUnparseableAndFixesOthers(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		seedClampRows(t, database, []clampRow{
			{"canary-b", "pace_floor", "soon", 3},
			{"canary-a", "pace_ceiling", "250ms", 1},
			{"canary-c", "pace_floor", "0s", 1},
			{"canary-c", "pace_ceiling", "-5s", 1},
		})
		changed, err := ClampLegacyPaceSettings(context.Background(), database, mustParse(t, "2026-02-01T00:00:00Z"))
		if err != nil {
			t.Fatalf("ClampLegacyPaceSettings: %v", err)
		}
		if v, ver := readClampRow(t, database, "canary-b", "pace_floor"); v != "soon" || ver != 3 {
			t.Errorf("unparseable row = (%q, v%d), want untouched (\"soon\", v3)", v, ver)
		}
		if v, ver := readClampRow(t, database, "canary-a", "pace_ceiling"); v != "1s" || ver != 2 {
			t.Errorf("parseable sub-1s row = (%q, v%d), want (\"1s\", v2)", v, ver)
		}
		// Zero and negative durations are "below 1s" and parse; they are raised too.
		for _, k := range []string{"pace_floor", "pace_ceiling"} {
			if v, ver := readClampRow(t, database, "canary-c", k); v != "1s" || ver != 2 {
				t.Errorf("canary-c/%s = (%q, v%d), want (\"1s\", v2)", k, v, ver)
			}
		}
		if changed != 3 {
			t.Errorf("changed = %d, want 3", changed)
		}
	})
}
