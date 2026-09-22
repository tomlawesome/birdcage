package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/store"
)

// TestEnrolRunCommandCarriesEveryRequiredFlag pins the `docker run`
// block `birdcage canary enrol` prints. It is the product's only install
// instruction: an operator pastes it verbatim, so a flag quietly dropped
// from it is a canary that comes up missing something -- privileged
// ports, its state volume, or (issue #65) the ability to see a port scan
// at all. Each flag is asserted together with the reason it is there, so
// a future edit that removes one argues with a named expectation rather
// than with a diff nobody reads.
func TestEnrolRunCommandCarriesEveryRequiredFlag(t *testing.T) {
	var out strings.Builder
	if err := printEnrolRunCommand(&out, "203.0.113.10", "8444", "deadbeef", "cafebabe", "mockingbird:latest"); err != nil {
		t.Fatalf("printEnrolRunCommand: %v", err)
	}
	got := out.String()

	required := []struct {
		flag string
		why  string
	}{
		{"--init", "the agent supervises OpenCanary; Docker's init reaps orphans"},
		{"--sysctl net.ipv4.ip_unprivileged_port_start=0", "nothing in the container is ever root, so the privileged-port floor is lowered instead"},
		{"--cap-add NET_RAW", "issue #65: without it the agent cannot open its capture socket and port-scan detection is off"},
		{"-v mockingbird-state:/var/lib/mockingbird", "credentials and the acknowledged log position must outlive the container"},
		{"-v mockingbird-log:/var/log/opencanary", "OpenCanary's log is the durable event store the agent replays from"},
		{"--restart unless-stopped", "a canary that stops reporting is a security event (SECURITY.md)"},
	}
	for _, r := range required {
		if !strings.Contains(got, r.flag) {
			t.Errorf("printed command is missing %q -- %s\ngot:\n%s", r.flag, r.why, got)
		}
	}

	for _, want := range []string{
		"-e MOCKINGBIRD_BIRDCAGE_URL=https://203.0.113.10:8444",
		"-e MOCKINGBIRD_CA_PIN=deadbeef",
		"-e MOCKINGBIRD_DEPLOY_TOKEN=cafebabe",
		"mockingbird:latest",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("printed command is missing %q\ngot:\n%s", want, got)
		}
	}
}

// TestEnrolRunCommandEscapesOperatorSuppliedValues: the advertise host
// and the image name come from environment variables, so a control
// sequence in either must not reach the operator's terminal raw -- the
// same rule every other command in cmd/birdcage follows.
func TestEnrolRunCommandEscapesOperatorSuppliedValues(t *testing.T) {
	var out strings.Builder
	if err := printEnrolRunCommand(&out, "203.0.113.10\x1b[31m", "8444", "deadbeef", "cafebabe", "image\x07name"); err != nil {
		t.Fatalf("printEnrolRunCommand: %v", err)
	}
	got := out.String()

	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("an escape character reached the terminal unescaped:\n%q", got)
	}
	if strings.ContainsRune(got, 0x07) {
		t.Errorf("a bell character reached the terminal unescaped:\n%q", got)
	}
}

// TestRequireEnrolAddressesRefusesUntilBothAreSet is issue #47 slice
// 1b item 3, "enrolment refuses to mint until both are set", proved
// directly against requireEnrolAddresses rather than through the whole
// `canary enrol` flow (which also needs a CA directory and an
// advertise host set -- unrelated to this check). Both the "neither
// set" and "only one set" refusals are covered, since a `||` that had
// drifted into a `&&` would still refuse the "neither" case correctly
// and only be caught by the "only one" case.
func TestRequireEnrolAddressesRefusesUntilBothAreSet(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	ctx := context.Background()

	if err := requireEnrolAddresses(ctx, database); err == nil {
		t.Fatal("requireEnrolAddresses succeeded with neither address set")
	}

	if _, err := captureStdout(t, func() error {
		return runSettingsSet([]string{string(store.SettingAdminApprovalAddress), "admin@example.net"})
	}); err != nil {
		t.Fatalf("set %s: %v", store.SettingAdminApprovalAddress, err)
	}
	if err := requireEnrolAddresses(ctx, database); err == nil {
		t.Fatal("requireEnrolAddresses succeeded with only admin_approval_address set")
	} else if !strings.Contains(err.Error(), string(store.SettingAdminApprovalAddress)) || !strings.Contains(err.Error(), string(store.SettingReleaseAddress)) {
		t.Errorf("error %q does not name both settings the operator needs to set", err.Error())
	}

	if _, err := captureStdout(t, func() error {
		return runSettingsSet([]string{string(store.SettingReleaseAddress), "release@example.net"})
	}); err != nil {
		t.Fatalf("set %s: %v", store.SettingReleaseAddress, err)
	}
	if err := requireEnrolAddresses(ctx, database); err != nil {
		t.Fatalf("requireEnrolAddresses failed with both addresses set: %v", err)
	}
}

// TestCanaryEnrolStatusNeverPrintsATokenHash is runCanaryEnrolStatus's
// own doc comment, checked rather than assumed: it says the printed
// line carries id/state/timestamps only, never a hash, "since
// EnrolmentSession itself carries neither token_hash nor
// enrolment_secret_hash". This mints a real session (so there is a real
// hash in the database that could leak) and asserts it on the actual
// stored value -- store.HashToken(raw), the same hash
// MintEnrolmentSession writes to enrolment_sessions.token_hash -- not a
// guessed string.
func TestCanaryEnrolStatusNeverPrintsATokenHash(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	raw, session, err := store.MintEnrolmentSession(ctx, database, "enrol-status-test", "lane-a", agentkind.Honeypot, time.Now().UTC())
	if err != nil {
		t.Fatalf("store.MintEnrolmentSession: %v", err)
	}
	hash := store.HashToken(raw)

	out, err := captureStdout(t, func() error { return runCanaryEnrolStatus() })
	if err != nil {
		t.Fatalf("runCanaryEnrolStatus: %v", err)
	}

	if strings.Contains(out, raw) {
		t.Fatalf("enrol --status output contains the raw deploy token: %q", out)
	}
	if strings.Contains(out, hash) {
		t.Fatalf("enrol --status output contains the token's hash: %q", out)
	}
	if !strings.Contains(out, session.ID) || !strings.Contains(out, "enrol-status-test") {
		t.Fatalf("enrol --status output = %q, want it to mention the session id and name", out)
	}
}

// TestCanaryEnrolRefusesUnknownKind is issue #105's CLI-level refusal:
// an unrecognised --kind is rejected before any database write or CA
// load, with an error naming the invalid value and the valid set. It
// runs with no environment configured at all -- BIRDCAGE_ADVERTISE_HOST
// unset, no CA directory -- to prove kind validation happens first,
// ahead of every other precondition runCanaryEnrol checks; if it ran
// later, this test would instead see one of those unrelated errors.
func TestCanaryEnrolRefusesUnknownKind(t *testing.T) {
	err := runCanaryEnrol([]string{"--name", "x", "--lane", "y", "--kind", "seagull"})
	if err == nil {
		t.Fatal("runCanaryEnrol with an unregistered kind returned no error")
	}
	if !strings.Contains(err.Error(), "seagull") {
		t.Errorf("error %q does not name the rejected kind", err.Error())
	}
	if !strings.Contains(err.Error(), string(agentkind.Honeypot)) {
		t.Errorf("error %q does not list the valid kinds", err.Error())
	}
}

// TestCanaryEnrolStatusReportsNoSessions covers the empty-database
// message, so a future change to it is a deliberate edit rather than an
// accident nobody noticed.
func TestCanaryEnrolStatusReportsNoSessions(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	out, err := captureStdout(t, func() error { return runCanaryEnrolStatus() })
	if err != nil {
		t.Fatalf("runCanaryEnrolStatus: %v", err)
	}
	if !strings.Contains(out, "no enrolment sessions") {
		t.Errorf("enrol --status output on an empty database = %q, want it to say so", out)
	}
}
