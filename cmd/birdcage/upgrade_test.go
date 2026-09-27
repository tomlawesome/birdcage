package main

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/runcmd"
	"github.com/tomlawesome/birdcage/internal/store"
)

// TestStartupUpgradeConfig: issue #54's server-side facts come from the
// same configuration enrolment uses, and are withheld entirely whenever
// enrolment itself would refuse -- a command naming no reachable address
// is worse than none.
func TestStartupUpgradeConfig(t *testing.T) {
	birdcageCA := testCA(t)
	full := startupConfig{ingestAddr: ":8443", enrolAddr: ":8444", advertiseHost: "birdcage.example.test"}
	noEnv := func(string) string { return "" }

	t.Run("defaults", func(t *testing.T) {
		got := startupUpgradeConfig(full, birdcageCA, noEnv)
		mockingbird, _ := agentkind.Lookup(agentkind.Honeypot)
		nightjar, _ := agentkind.Lookup(agentkind.Scanner)
		if got.AdvertiseHost != "birdcage.example.test" || got.EnrolPort != "8444" || got.Pin != birdcageCA.Pin() {
			t.Errorf("host/port/pin = %q/%q/%q, want birdcage.example.test/8444/%s", got.AdvertiseHost, got.EnrolPort, got.Pin, birdcageCA.Pin())
		}
		if got.AgentImages[agentkind.Honeypot] != mockingbird.DefaultImage || got.AgentImages[agentkind.Scanner] != nightjar.DefaultImage {
			t.Errorf("agent images = %v, want the profiles' defaults", got.AgentImages)
		}
		if got.HolderImage != runcmd.DefaultHolderImage || got.OpenCanaryImage != runcmd.DefaultOpenCanaryImage || got.SMBLureImage != runcmd.DefaultSMBLureImage {
			t.Errorf("holder/opencanary/lure = %q/%q/%q, want runcmd's defaults", got.HolderImage, got.OpenCanaryImage, got.SMBLureImage)
		}
	})

	t.Run("environment overrides, as enrolment reads them", func(t *testing.T) {
		env := map[string]string{
			"MOCKINGBIRD_IMAGE":       "r/mockingbird:1",
			"NIGHTJAR_IMAGE":          "r/nightjar:1",
			runcmd.EnvHolderImage:     "r/holder:1",
			runcmd.EnvOpenCanaryImage: "r/opencanary:1",
			runcmd.EnvSMBLureImage:    "r/smb-lure:1",
		}
		got := startupUpgradeConfig(full, birdcageCA, func(k string) string { return env[k] })
		if got.AgentImages[agentkind.Honeypot] != "r/mockingbird:1" || got.AgentImages[agentkind.Scanner] != "r/nightjar:1" ||
			got.HolderImage != "r/holder:1" || got.OpenCanaryImage != "r/opencanary:1" || got.SMBLureImage != "r/smb-lure:1" {
			t.Errorf("images ignored the environment: %+v", got)
		}
	})

	for _, tc := range []struct {
		name string
		cfg  startupConfig
		ca   *ca.CA
	}{
		{"ingest off", startupConfig{enrolAddr: ":8444", advertiseHost: "birdcage.example.test"}, birdcageCA},
		{"no advertise host", startupConfig{ingestAddr: ":8443", enrolAddr: ":8444"}, birdcageCA},
		{"no CA", full, nil},
		{"enrol address without a port", startupConfig{ingestAddr: ":8443", enrolAddr: "nope", advertiseHost: "birdcage.example.test"}, birdcageCA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := startupUpgradeConfig(tc.cfg, tc.ca, noEnv)
			if got.AdvertiseHost != "" || got.Pin != "" || got.EnrolPort != "" || got.AgentImages != nil {
				t.Errorf("got %+v, want the zero value (no command printed)", got)
			}
			var zero api.UpgradeConfig
			if got.HolderImage != zero.HolderImage {
				t.Errorf("got %+v, want the zero value", got)
			}
		})
	}
}

// upgradeCLIEnv is a getenv for runAgentUpgradeCommand: the settings a
// real `docker exec` inherits from the server's own container.
func upgradeCLIEnv(t *testing.T) func(string) string {
	t.Helper()
	env := map[string]string{
		envIngestAddr:    ":8443",
		envAdvertiseHost: "birdcage.example.test",
		envCADir:         filepath.Join(t.TempDir(), "ca"),
	}
	return func(k string) string { return env[k] }
}

// behindAgent inserts a honeypot whose agent last reported agentVersion,
// with birdcage's own version set to 1.2.0+new for the test.
func behindAgent(t *testing.T, id, agentVersion string) *db.DB {
	t.Helper()
	t.Setenv(envDBPath, testDBPath(t))
	old := version
	version = "1.2.0+new"
	t.Cleanup(func() { version = old })
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	t.Cleanup(func() { closeCanaryDB(database) })
	insertTestCanary(t, database, id)
	if err := store.RecordCanaryAgentHeartbeat(context.Background(), database, id, time.Now().UTC(), store.AgentHeartbeat{LogReadOK: true, AgentVersion: agentVersion}); err != nil {
		t.Fatalf("RecordCanaryAgentHeartbeat: %v", err)
	}
	return database
}

var hexToken = regexp.MustCompile(`(?m)^echo ([0-9a-f]{64}) \| docker run --rm -i \\$`)

// TestAgentUpgradeCommandMintsAndPrints: the command on stdout alone,
// one grouped script carrying a fresh token whose hash -- never the
// token -- is stored; the note with its expiry on stderr; the mint
// audited.
func TestAgentUpgradeCommandMintsAndPrints(t *testing.T) {
	database := behindAgent(t, "agent-up", "1.1.0+old")
	var stdout, stderr strings.Builder
	if err := runAgentUpgradeCommand([]string{"agent-up"}, upgradeCLIEnv(t), &stdout, &stderr); err != nil {
		t.Fatalf("runAgentUpgradeCommand: %v", err)
	}
	script := stdout.String()
	if !strings.HasPrefix(script, "( set -e\n") || !strings.HasSuffix(script, "\n)\n") {
		t.Errorf("stdout is not one grouped script:\n%s", script)
	}
	m := hexToken.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no token line in:\n%s", script)
	}
	raw := m[1]
	for _, part := range []string{"MOCKINGBIRD_BIRDCAGE_URL=https://birdcage.example.test:8444", "upgrade-token || true", "docker run -d --name mockingbird "} {
		if !strings.Contains(script, part) {
			t.Errorf("script lacks %q", part)
		}
	}

	var hash, from, to string
	if err := database.QueryRow(`SELECT token_hash, from_version, to_version FROM upgrade_tokens WHERE agent_id = ?`, "agent-up").Scan(&hash, &from, &to); err != nil {
		t.Fatalf("read token row: %v", err)
	}
	if hash != store.HashToken(raw) || from != "1.1.0+old" || to != "1.2.0+new" {
		t.Errorf("row = %s %s %s, want the printed token's hash, 1.1.0+old, 1.2.0+new", hash, from, to)
	}

	note := stderr.String()
	if !strings.Contains(note, "single-use upgrade token, valid until ") || !strings.Contains(note, "(15 minutes)") || strings.Contains(note, raw) {
		t.Errorf("stderr note = %q", note)
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'canary.upgrade_token_minted' AND target = 'agent-up' AND triggered_by = 'cli'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("mint audit rows = %d (%v), want 1", n, err)
	}
	var reason string
	if err := database.QueryRow(`SELECT reason FROM audit_log WHERE action = 'canary.upgrade_token_minted'`).Scan(&reason); err != nil || strings.Contains(reason, raw) {
		t.Errorf("audit reason %q (%v) must not carry the token", reason, err)
	}
}

// TestAgentUpgradeCommandRefusals: nothing is minted for an agent that is
// not behind, an unknown agent, or a birdcage that cannot say where to
// connect.
func TestAgentUpgradeCommandRefusals(t *testing.T) {
	database := behindAgent(t, "agent-cur", "1.2.0+other")
	insertTestCanary(t, database, "agent-behind")
	if err := store.RecordCanaryAgentHeartbeat(context.Background(), database, "agent-behind", time.Now().UTC(), store.AgentHeartbeat{LogReadOK: true, AgentVersion: "1.0.0"}); err != nil {
		t.Fatal(err)
	}
	noHost := func(k string) string {
		if k == envAdvertiseHost {
			return ""
		}
		return upgradeCLIEnv(t)(k)
	}
	cases := []struct {
		name   string
		args   []string
		getenv func(string) string
		want   string
	}{
		{"current agent", []string{"agent-cur"}, upgradeCLIEnv(t), "is not behind birdcage"},
		{"unknown agent", []string{"nope"}, upgradeCLIEnv(t), "unknown agent nope"},
		{"no advertise host", []string{"agent-behind"}, noHost, envAdvertiseHost},
		{"no agent id", nil, upgradeCLIEnv(t), "usage:"},
	}
	for _, c := range cases {
		var stdout, stderr strings.Builder
		err := runAgentUpgradeCommand(c.args, c.getenv, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one containing %q", c.name, err, c.want)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: printed a command:\n%s", c.name, stdout.String())
		}
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM upgrade_tokens`).Scan(&n); err != nil || n != 0 {
		t.Errorf("upgrade tokens = %d (%v), want 0", n, err)
	}
}
