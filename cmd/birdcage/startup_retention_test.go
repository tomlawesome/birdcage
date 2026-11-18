package main

import (
	"strings"
	"testing"
)

// Issue #213 (retention): BIRDCAGE_FINDINGS_RETENTION_DAYS defaults to
// 90, 0 keeps for good, and a negative or non-number value refuses to
// start with an error that names the setting. The parsed value is
// startupConfig.findingsRetentionDays; the constant is
// envFindingsRetentionDays.

func TestLoadStartupConfigFindingsRetentionDays(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want int
	}{
		{"unset defaults to 90", map[string]string{}, 90},
		{"empty defaults to 90", map[string]string{envFindingsRetentionDays: ""}, 90},
		{"explicit", map[string]string{envFindingsRetentionDays: "30"}, 30},
		{"zero keeps for good", map[string]string{envFindingsRetentionDays: "0"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := loadStartupConfig(startupEnv(t, c.env), discardLog(), discardLog(), discardLog(), discardLog())
			if err != nil {
				t.Fatalf("loadStartupConfig: %v", err)
			}
			if cfg.findingsRetentionDays != c.want {
				t.Errorf("findingsRetentionDays = %d, want %d", cfg.findingsRetentionDays, c.want)
			}
		})
	}
}

func TestLoadStartupConfigRefusesBadFindingsRetentionDays(t *testing.T) {
	for _, v := range []string{"-1", "-5", "-90", "+30", "+0", "abc", "1.5", "90d", "9999999999999999999999"} {
		t.Run(v, func(t *testing.T) {
			_, err := loadStartupConfig(startupEnv(t, map[string]string{envFindingsRetentionDays: v}), discardLog(), discardLog(), discardLog(), discardLog())
			if err == nil {
				t.Fatalf("loadStartupConfig with %s=%q = nil error, want a refusal", envFindingsRetentionDays, v)
			}
			if !strings.Contains(err.Error(), envFindingsRetentionDays) || !strings.Contains(err.Error(), v) {
				t.Errorf("error = %q, want it to name %s and the value %q", err.Error(), envFindingsRetentionDays, v)
			}
		})
	}
}
