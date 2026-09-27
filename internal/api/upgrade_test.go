package api

import (
	"context"
	"encoding/json"
	"errors"
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

// testToken is a well-formed upgrade token stand-in.
var testToken = strings.Repeat("0123456789abcdef", 4)

// TestUpgradeInputForBehind is the command half of issue #54: the input
// UpgradeInputFor builds from the server's own facts and the canary's
// stored ones is exactly what runcmd.Upgrade needs for this canary, and
// the printed command carries neither a deploy token nor the bearer
// token.
func TestUpgradeInputForBehind(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	id, rawToken := upgradeFixture(t, database, "1.0.0+aaaaaaaa", beatAt)
	cfg := testUpgradeConfig()

	in, err := UpgradeInputFor(context.Background(), database, cfg, id)
	if err != nil {
		t.Fatalf("UpgradeInputFor: %v", err)
	}
	lure := true
	wantIn := runcmd.UpgradeInput{
		Kind:          agentkind.Honeypot,
		AdvertiseHost: cfg.AdvertiseHost, EnrolPort: cfg.EnrolPort, Pin: cfg.Pin,
		AgentImage:  cfg.AgentImages[agentkind.Honeypot],
		HolderImage: cfg.HolderImage, OpenCanaryImage: cfg.OpenCanaryImage, SMBLureImage: cfg.SMBLureImage,
		BaitNames: "fs-old,printhub",
		SMBLure:   &lure, SMBWorkgroup: "CORP", SMBShares: []string{"public", "backup", "scans"},
	}
	in.UpgradeToken, wantIn.UpgradeToken = testToken, testToken
	var got, want strings.Builder
	if err := runcmd.Upgrade(&got, in); err != nil {
		t.Fatalf("runcmd.Upgrade(UpgradeInputFor): %v", err)
	}
	if err := runcmd.Upgrade(&want, wantIn); err != nil {
		t.Fatalf("runcmd.Upgrade(want): %v", err)
	}
	if got.String() != want.String() {
		t.Errorf("command built from UpgradeInputFor differs\ngot:\n%s\nwant:\n%s", got.String(), want.String())
	}

	// The parts that make it this server's and this canary's command,
	// asserted directly too, so a fixture mistake above cannot make the
	// comparison vacuous.
	cmd := got.String()
	for _, part := range []string{
		"docker pull registry.example.test/mockingbird:9",
		"docker pull registry.example.test/smb-lure:9",
		"MOCKINGBIRD_BIRDCAGE_URL=https://birdcage.example.test:8444",
		"MOCKINGBIRD_CA_PIN=sha256:0123456789abcdef",
		"MOCKINGBIRD_POISONER_NAMES=fs-old,printhub",
		"SMB_WORKGROUP=CORP",
		"docker rm -f mockingbird",
		"echo " + testToken + " | docker run --rm -i",
	} {
		if !strings.Contains(cmd, part) {
			t.Errorf("command is missing %q:\n%s", part, cmd)
		}
	}
	if strings.Contains(cmd, "DEPLOY_TOKEN") {
		t.Errorf("command carries a deploy token variable:\n%s", cmd)
	}
	if strings.Contains(cmd, rawToken) {
		t.Errorf("command carries the canary's live bearer token")
	}
}

// TestUpgradeInputForUnknownAgent: an unknown id is ErrCanaryNotFound,
// which the CLI turns into "unknown agent".
func TestUpgradeInputForUnknownAgent(t *testing.T) {
	database := openTempDB(t)
	if _, err := UpgradeInputFor(context.Background(), database, testUpgradeConfig(), "nope"); !errors.Is(err, store.ErrCanaryNotFound) {
		t.Fatalf("err = %v, want ErrCanaryNotFound", err)
	}
}

// TestHandleCanaryUpgradeAvailableWhenBehind is issue #54's page half:
// the page says an upgrade command can be had, and carries none -- every
// command holds a freshly minted token, and a GET mints nothing.
func TestHandleCanaryUpgradeAvailableWhenBehind(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	id, _ := upgradeFixture(t, database, "1.0.0+aaaaaaaa", beatAt)

	h := newHandlerWithUpgrade(database, fixedNow(beatAt.Add(time.Second)), "1.2.3+bbbbbbbb", testUpgradeConfig())
	resp, body := getCanaryPage(t, h, id)

	if resp.Canary.Status != string(store.StateAgentOutOfDate) {
		t.Fatalf("status = %q, want %q", resp.Canary.Status, store.StateAgentOutOfDate)
	}
	if !resp.Canary.UpgradeAvailable {
		t.Error("upgrade_available is false for an agent behind birdcage")
	}
	for _, absent := range []string{"upgrade_command", "docker ", "upgrade-token"} {
		if strings.Contains(body, absent) {
			t.Errorf("the page carries %q; it must carry no command: %s", absent, body)
		}
	}
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM upgrade_tokens`).Scan(&n); err != nil {
		t.Fatalf("count upgrade tokens: %v", err)
	}
	if n != 0 {
		t.Errorf("GET /api/canary minted %d upgrade tokens, want 0", n)
	}
}

// TestHandleCanaryUpgradeAvailableFalseWhenCurrent: an agent at
// birdcage's own release carries the field, false -- present so a reader
// can tell a current agent from a backend too old to send it.
func TestHandleCanaryUpgradeAvailableFalseWhenCurrent(t *testing.T) {
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
	if !strings.Contains(body, `"upgrade_available":false`) {
		t.Errorf("upgrade_available is not present (false) on the page's canary object: %s", body)
	}
}

// TestHandleCanaryUpgradeAvailableWhileSilent: agent_out_of_date under a
// worse state still offers the command -- the operator needs it most
// when the canary is also down.
func TestHandleCanaryUpgradeAvailableWhileSilent(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	id, _ := upgradeFixture(t, database, "1.0.0", beatAt)

	h := newHandlerWithUpgrade(database, fixedNow(beatAt.Add(time.Hour)), "1.2.3", testUpgradeConfig())
	resp, _ := getCanaryPage(t, h, id)

	if resp.Canary.Status != string(store.StateSilent) {
		t.Fatalf("status = %q, want %q (an hour past a 60 s heartbeat)", resp.Canary.Status, store.StateSilent)
	}
	if !resp.Canary.UpgradeAvailable {
		t.Errorf("upgrade_available is false while silent and behind; active_states = %v", resp.Canary.ActiveStates)
	}
}

// TestHandleCanaryUpgradeUnavailableWithoutServerFacts: a server with no
// advertise host (ingest off, say) has no address to hand a canary, so
// it offers no command rather than one that cannot connect.
func TestHandleCanaryUpgradeUnavailableWithoutServerFacts(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	id, _ := upgradeFixture(t, database, "1.0.0", beatAt)

	h := newHandlerWithUpgrade(database, fixedNow(beatAt.Add(time.Second)), "1.2.3", UpgradeConfig{})
	resp, _ := getCanaryPage(t, h, id)

	if resp.Canary.Status != string(store.StateAgentOutOfDate) {
		t.Fatalf("status = %q, want %q", resp.Canary.Status, store.StateAgentOutOfDate)
	}
	if resp.Canary.UpgradeAvailable {
		t.Error("upgrade_available is true with no server facts")
	}
}

// TestHandleCanariesCarriesNoUpgradeFields: the fleet read stays without
// the page-only field.
func TestHandleCanariesCarriesNoUpgradeFields(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	upgradeFixture(t, database, "1.0.0", beatAt)

	h := newHandlerWithUpgrade(database, fixedNow(beatAt.Add(time.Second)), "1.2.3", testUpgradeConfig())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	for _, absent := range []string{"upgrade_command", "upgrade_available"} {
		if strings.Contains(rec.Body.String(), absent) {
			t.Errorf("GET /api/canaries carries %s: %s", absent, rec.Body.String())
		}
	}
}

// TestUpgradeWindowOnTheAPI: an accepted upgrade token puts
// upgrade_in_progress in active_states and upgrade_window_until on both
// reads, ranked before agent_out_of_date; once the window ends, both go.
func TestUpgradeWindowOnTheAPI(t *testing.T) {
	database := openTempDB(t)
	beatAt := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	id, _ := upgradeFixture(t, database, "1.0.0", beatAt)
	ctx := context.Background()

	mintAt := beatAt.Add(time.Second)
	raw, _, err := store.MintUpgradeToken(ctx, database, id, "1.2.3", mintAt)
	if err != nil {
		t.Fatalf("MintUpgradeToken: %v", err)
	}
	usedAt := mintAt.Add(time.Minute)
	res, err := store.PresentUpgradeToken(ctx, database, id, raw, usedAt)
	if err != nil || res.Outcome != store.UpgradeTokenAccepted {
		t.Fatalf("PresentUpgradeToken = %+v, %v; want accepted", res, err)
	}

	h := newHandlerWithUpgrade(database, fixedNow(usedAt.Add(time.Second)), "1.2.3", testUpgradeConfig())
	resp, _ := getCanaryPage(t, h, id)
	want := []string{string(store.StateUpgradeInProgress), string(store.StateAgentOutOfDate)}
	if strings.Join(resp.Canary.ActiveStates, ",") != strings.Join(want, ",") {
		t.Errorf("active_states = %v, want %v", resp.Canary.ActiveStates, want)
	}
	if resp.Canary.UpgradeWindowUntil == nil || !resp.Canary.UpgradeWindowUntil.Equal(usedAt.Add(store.UpgradeWindow)) {
		t.Errorf("upgrade_window_until = %v, want %v", resp.Canary.UpgradeWindowUntil, usedAt.Add(store.UpgradeWindow))
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/canaries", nil))
	if !strings.Contains(rec.Body.String(), `"upgrade_window_until":"`) || !strings.Contains(rec.Body.String(), `"upgrade_in_progress"`) {
		t.Errorf("GET /api/canaries lacks the open window: %s", rec.Body.String())
	}

	after := newHandlerWithUpgrade(database, fixedNow(usedAt.Add(store.UpgradeWindow)), "1.2.3", testUpgradeConfig())
	resp, body := getCanaryPage(t, after, id)
	for _, s := range resp.Canary.ActiveStates {
		if s == string(store.StateUpgradeInProgress) {
			t.Errorf("upgrade_in_progress still active at the window's end: %v", resp.Canary.ActiveStates)
		}
	}
	if strings.Contains(body, "upgrade_window_until") {
		t.Errorf("upgrade_window_until still present at the window's end: %s", body)
	}
}
