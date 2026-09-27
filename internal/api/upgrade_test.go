package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/runcmd"
	"github.com/tomlawesome/birdcage/internal/store"
)

// testUpgradeConfig is a complete server-side UpgradeConfig with
// distinctive values, so each one can be found (or not) in the output.
func testUpgradeConfig() UpgradeConfig {
	return UpgradeConfig{
		AdvertiseHost: "birdcage.example.test",
		EnrolPort:     "8444",
		Pin:           "sha256:0123456789abcdef",
		AgentImages: map[agentkind.Kind]string{
			agentkind.Honeypot: "registry.example.test/mockingbird:9",
			agentkind.Scanner:  "registry.example.test/nightjar:9",
		},
		HolderImage:     "registry.example.test/holder:9",
		OpenCanaryImage: "registry.example.test/opencanary:9",
		SMBLureImage:    "registry.example.test/smb-lure:9",
	}
}

// upgradeFixture is one honeypot enrolled with the SMB lure on, a bait
// names setting, a live bearer token, and an agent heartbeat reporting
// agentVersion at beatAt. It returns the canary id and the raw token, so
// a test can prove the token never reaches the command.
func upgradeFixture(t *testing.T, database *db.DB, agentVersion string, beatAt time.Time) (string, string) {
	t.Helper()
	ctx := context.Background()
	const id = "canary-up"
	insertCanary(t, database, store.Canary{
		ID: id, Name: id, Lane: "lan", Ports: "21,22",
		HeartbeatIntervalS: 60, EnrolledAt: beatAt.Add(-time.Hour),
	})
	// The lure identity store.Provision writes at enrolment (migration
	// 0026); InsertCanary is the test-only path and leaves it NULL.
	if _, err := database.ExecContext(ctx,
		`UPDATE agents SET smb_lure = 1, smb_workgroup = ?, smb_shares = ? WHERE id = ?`,
		"CORP", "public,backup,scans", id); err != nil {
		t.Fatalf("set smb lure facts: %v", err)
	}
	if err := store.SetCanarySettings(ctx, database, id, agentkind.Honeypot,
		map[store.CanarySettingKey]string{store.CanarySettingBaitNames: "fs-old,printhub"},
		beatAt.Add(-time.Minute), "cli"); err != nil {
		t.Fatalf("SetCanarySettings: %v", err)
	}
	raw, _, err := store.MintCanaryToken(ctx, database, id, beatAt.Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("MintCanaryToken: %v", err)
	}
	if err := store.RecordCanaryAgentHeartbeat(ctx, database, id, beatAt, store.AgentHeartbeat{
		QueueDepth: 0, LogReadOK: true, AgentVersion: agentVersion,
	}); err != nil {
		t.Fatalf("RecordCanaryAgentHeartbeat: %v", err)
	}
	return id, raw
}

// getCanaryPage fetches GET /api/canary for id and returns both the
// decoded response and the raw body.
func getCanaryPage(t *testing.T, h http.Handler, id string) (canaryPageResponse, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canary?id="+id, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp canaryPageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	return resp, rec.Body.String()
}

// TestHandleCanaryUpgradeCommandWhenBehind is issue #54's page half: an
// agent behind birdcage gets the full upgrade script, built from the
// server's own facts and the canary's stored ones -- byte-for-byte what
// runcmd.Upgrade prints for them -- and never carrying a deploy token.
func TestHandleCanaryUpgradeCommandWhenBehind(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	id, rawToken := upgradeFixture(t, database, "1.0.0+aaaaaaaa", beatAt)

	cfg := testUpgradeConfig()
	h := newHandlerWithUpgrade(database, fixedNow(beatAt.Add(time.Second)), "1.2.3+bbbbbbbb", cfg)
	resp, _ := getCanaryPage(t, h, id)

	if resp.Canary.Status != string(store.StateAgentOutOfDate) {
		t.Fatalf("status = %q, want %q", resp.Canary.Status, store.StateAgentOutOfDate)
	}
	got := resp.Canary.UpgradeCommand
	if got == "" {
		t.Fatal("upgrade_command is empty for an agent behind birdcage")
	}

	lure := true
	var want strings.Builder
	if err := runcmd.Upgrade(&want, runcmd.UpgradeInput{
		Kind:          agentkind.Honeypot,
		AdvertiseHost: cfg.AdvertiseHost, EnrolPort: cfg.EnrolPort, Pin: cfg.Pin,
		AgentImage:  cfg.AgentImages[agentkind.Honeypot],
		HolderImage: cfg.HolderImage, OpenCanaryImage: cfg.OpenCanaryImage, SMBLureImage: cfg.SMBLureImage,
		BaitNames: "fs-old,printhub",
		SMBLure:   &lure, SMBWorkgroup: "CORP", SMBShares: []string{"public", "backup", "scans"},
	}); err != nil {
		t.Fatalf("runcmd.Upgrade: %v", err)
	}
	if got != want.String() {
		t.Errorf("upgrade_command differs from runcmd.Upgrade's own output for the same facts\ngot:\n%s\nwant:\n%s", got, want.String())
	}

	// The parts that make it this server's and this canary's command,
	// asserted directly too, so a fixture mistake above cannot make the
	// comparison vacuous.
	for _, part := range []string{
		"docker pull registry.example.test/mockingbird:9",
		"docker pull registry.example.test/smb-lure:9",
		"MOCKINGBIRD_BIRDCAGE_URL=https://birdcage.example.test:8444",
		"MOCKINGBIRD_CA_PIN=sha256:0123456789abcdef",
		"MOCKINGBIRD_POISONER_NAMES=fs-old,printhub",
		"SMB_WORKGROUP=CORP",
		"docker rm -f mockingbird",
	} {
		if !strings.Contains(got, part) {
			t.Errorf("upgrade_command is missing %q:\n%s", part, got)
		}
	}
	if strings.Contains(got, "DEPLOY_TOKEN") {
		t.Errorf("upgrade_command carries a deploy token variable:\n%s", got)
	}
	if strings.Contains(got, rawToken) {
		t.Errorf("upgrade_command carries the canary's live bearer token")
	}
}

// TestHandleCanaryUpgradeCommandEmptyWhenCurrent: an agent at birdcage's
// own release carries the field, empty -- present so a reader can tell a
// current agent from a backend too old to send it.
func TestHandleCanaryUpgradeCommandEmptyWhenCurrent(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	id, _ := upgradeFixture(t, database, "1.2.3+aaaaaaaa", beatAt)

	h := newHandlerWithUpgrade(database, fixedNow(beatAt.Add(time.Second)), "1.2.3+bbbbbbbb", testUpgradeConfig())
	resp, body := getCanaryPage(t, h, id)

	for _, s := range resp.Canary.ActiveStates {
		if s == string(store.StateAgentOutOfDate) {
			t.Fatalf("active_states = %v includes agent_out_of_date for an agent at birdcage's own release", resp.Canary.ActiveStates)
		}
	}
	if resp.Canary.UpgradeCommand != "" {
		t.Errorf("upgrade_command = %q, want empty for a current agent", resp.Canary.UpgradeCommand)
	}
	if !strings.Contains(body, `"upgrade_command":""`) {
		t.Errorf("upgrade_command is not present (empty) on the page's canary object: %s", body)
	}
}

// TestHandleCanaryUpgradeCommandWhileSilent: agent_out_of_date under a
// worse state still gets the command -- the operator needs it most when
// the canary is also down.
func TestHandleCanaryUpgradeCommandWhileSilent(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	id, _ := upgradeFixture(t, database, "1.0.0", beatAt)

	h := newHandlerWithUpgrade(database, fixedNow(beatAt.Add(time.Hour)), "1.2.3", testUpgradeConfig())
	resp, _ := getCanaryPage(t, h, id)

	if resp.Canary.Status != string(store.StateSilent) {
		t.Fatalf("status = %q, want %q (an hour past a 60 s heartbeat)", resp.Canary.Status, store.StateSilent)
	}
	if resp.Canary.UpgradeCommand == "" {
		t.Errorf("upgrade_command is empty while silent and behind; active_states = %v", resp.Canary.ActiveStates)
	}
}

// TestHandleCanaryUpgradeCommandEmptyWithoutServerFacts: a server with
// no advertise host (ingest off, say) has no address to hand a canary,
// so it prints nothing rather than a command that cannot connect.
func TestHandleCanaryUpgradeCommandEmptyWithoutServerFacts(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	id, _ := upgradeFixture(t, database, "1.0.0", beatAt)

	h := newHandlerWithUpgrade(database, fixedNow(beatAt.Add(time.Second)), "1.2.3", UpgradeConfig{})
	resp, _ := getCanaryPage(t, h, id)

	if resp.Canary.Status != string(store.StateAgentOutOfDate) {
		t.Fatalf("status = %q, want %q", resp.Canary.Status, store.StateAgentOutOfDate)
	}
	if resp.Canary.UpgradeCommand != "" {
		t.Errorf("upgrade_command = %q, want empty with no server facts", resp.Canary.UpgradeCommand)
	}
}

// TestHandleCanariesCarriesNoUpgradeCommand: the fleet read stays
// without it -- it polls every canary every thirty seconds, and building
// the command is per-canary queries.
func TestHandleCanariesCarriesNoUpgradeCommand(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	upgradeFixture(t, database, "1.0.0", beatAt)

	h := newHandlerWithUpgrade(database, fixedNow(beatAt.Add(time.Second)), "1.2.3", testUpgradeConfig())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "upgrade_command") {
		t.Errorf("GET /api/canaries carries upgrade_command: %s", rec.Body.String())
	}
}
