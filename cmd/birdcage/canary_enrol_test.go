package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/hostmask"
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
	if err := printEnrolRunCommand(&out, "203.0.113.10", "8444", "deadbeef", "cafebabe", "mockingbird:latest", "", ""); err != nil {
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
	if err := printEnrolRunCommand(&out, "203.0.113.10\x1b[31m", "8444", "deadbeef", "cafebabe", "image\x07name", "old-fs-01\x1b[32m", "linux\x07"); err != nil {
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

// TestEnrolRunCommandOmitsThePoisonerSettingsWhenNotAskedFor: the two
// optional settings issue #86 adds print nothing at all when the operator
// did not ask for them. The agent's own defaults are the same values, and
// the run command is the product's one install instruction, not a place to
// restate defaults an operator then has to reason about.
func TestEnrolRunCommandOmitsThePoisonerSettingsWhenNotAskedFor(t *testing.T) {
	var out strings.Builder
	if err := printEnrolRunCommand(&out, "203.0.113.10", "8444", "deadbeef", "cafebabe", "mockingbird:latest", "", ""); err != nil {
		t.Fatalf("printEnrolRunCommand: %v", err)
	}
	got := out.String()
	for _, unwanted := range []string{"MOCKINGBIRD_POISONER_NAMES", "MOCKINGBIRD_POISONER_PROFILE"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("the printed command names %s without being asked:\n%s", unwanted, got)
		}
	}
}

// TestEnrolRunCommandCarriesThePoisonerSettings is the other half: when
// the operator does supply them, they reach the container, because a
// setting that has to be added by hand afterwards is one that does not
// get added.
func TestEnrolRunCommandCarriesThePoisonerSettings(t *testing.T) {
	var out strings.Builder
	if err := printEnrolRunCommand(&out, "203.0.113.10", "8444", "deadbeef", "cafebabe", "mockingbird:latest", "old-fs-01,printer-7", "linux"); err != nil {
		t.Fatalf("printEnrolRunCommand: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"-e MOCKINGBIRD_POISONER_NAMES=old-fs-01,printer-7",
		"-e MOCKINGBIRD_POISONER_PROFILE=linux",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("printed command is missing %q\ngot:\n%s", want, got)
		}
	}
	// Still one command: every line but the last ends in a continuation.
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	for i, line := range lines[:len(lines)-1] {
		if !strings.HasSuffix(line, "\\") {
			t.Errorf("line %d does not continue, so the command is broken in two:\n%s", i, got)
		}
	}
}

// TestPoisonerBaitNames is the validation that runs before a token is
// minted. A typo must not burn a live deploy token, and the error must not
// quote the name back -- this output ends up in runbooks and tickets, and
// the point of deriving bait names from the operator's own network is that
// there is nothing for an attacker to look up.
func TestPoisonerBaitNames(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "not asked for", raw: "", want: ""},
		{name: "only spaces", raw: "   ", want: ""},
		{name: "two names", raw: "old-fs-01,printer-7", want: "old-fs-01,printer-7"},
		{name: "normalised", raw: " OLD-FS-01 , Printer-7 ", want: "old-fs-01,printer-7"},
		{name: "three names", raw: "a,b,c", want: "a,b,c"},
		// A partly-good list is refused rather than silently trimmed: the
		// operator is watching this output, so they can fix it now.
		{name: "one bad entry", raw: "old-fs-01,bad_name", wantErr: true},
		{name: "four names", raw: "old-fs-01,printer-7,srv-22,extra-9", wantErr: true},
		{name: "all bad", raw: "_,-", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := poisonerBaitNames(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want an error: %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if err != nil {
				for _, field := range strings.Split(tc.raw, ",") {
					field = strings.TrimSpace(field)
					// Entries shorter than three characters are skipped:
					// "a" or "-" appears inside ordinary English, so a
					// substring check on one would fail on the wording of
					// the rule rather than on a leaked name.
					if len(field) >= 3 && strings.Contains(err.Error(), field) {
						t.Errorf("the error quotes %q: %s", field, err)
					}
				}
			}
		})
	}
}

// TestScannerEnrolRunCommandCarriesEveryRequiredFlag is
// TestEnrolRunCommandCarriesEveryRequiredFlag's own counterpart for the
// scanner kind (#108, section 3): the printed command's security posture
// -- read-only, no capabilities, no privilege escalation -- and its
// mask flags, kept in sync with internal/hostmask so this test fails the
// moment the two packages disagree, rather than a container silently
// starting with a smaller covering than the docs promise.
func TestScannerEnrolRunCommandCarriesEveryRequiredFlag(t *testing.T) {
	var out strings.Builder
	if err := printScannerEnrolRunCommand(&out, "203.0.113.10", "8444", "deadbeef", "cafebabe", "nightjar:latest"); err != nil {
		t.Fatalf("printScannerEnrolRunCommand: %v", err)
	}
	got := out.String()

	required := []struct {
		flag string
		why  string
	}{
		{"--read-only", "ADR-0010 decision 3: a scanner needs no writable filesystem of its own"},
		{"--cap-drop ALL", "the scanner needs no Linux capability at all"},
		{"--security-opt no-new-privileges", "belt-and-braces against a setuid escalation inside the container"},
		{"-v /:/host:ro", "the whole-root read-only bind the owner ratified over narrower per-distro mounts"},
		{"-v nightjar-state:/var/lib/nightjar", "credentials must outlive the container"},
		{"-v nightjar-grype-db:/var/lib/nightjar-grype-db", "the Grype vulnerability database cache, refreshed every run, never rebuilt from cold each time"},
		{"--restart unless-stopped", "a scanner that stops reporting is a security event, same as a canary"},
	}
	for _, r := range required {
		if !strings.Contains(got, r.flag) {
			t.Errorf("printed command is missing %q -- %s\ngot:\n%s", r.flag, r.why, got)
		}
	}

	for _, forbidden := range []string{"--sysctl", "--cap-add", "--publish", "-p ", "--init"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("printed command contains %q, which #108 says it must not: no sysctl, no cap-add, no published port\ngot:\n%s", forbidden, got)
		}
	}

	for _, want := range []string{
		"-e NIGHTJAR_BIRDCAGE_URL=https://203.0.113.10:8444",
		"-e NIGHTJAR_CA_PIN=deadbeef",
		"-e NIGHTJAR_DEPLOY_TOKEN=cafebabe",
		"nightjar:latest",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("printed command is missing %q\ngot:\n%s", want, got)
		}
	}

	// Every hostmask.RunFlags("/host") flag must appear verbatim -- the
	// single shared constant is the whole point (issue #108: "so the
	// printed command and the check cannot drift").
	for _, flag := range hostmask.RunFlags("/host") {
		if !strings.Contains(got, flag) {
			t.Errorf("printed command is missing mask flag %q\ngot:\n%s", flag, got)
		}
	}
}

// TestScannerEnrolRunCommandEscapesOperatorSuppliedValues mirrors
// TestEnrolRunCommandEscapesOperatorSuppliedValues for the scanner
// renderer.
func TestScannerEnrolRunCommandEscapesOperatorSuppliedValues(t *testing.T) {
	var out strings.Builder
	if err := printScannerEnrolRunCommand(&out, "203.0.113.10\x1b[31m", "8444", "deadbeef", "cafebabe", "image\x07name"); err != nil {
		t.Fatalf("printScannerEnrolRunCommand: %v", err)
	}
	got := out.String()

	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("an escape character reached the terminal unescaped:\n%q", got)
	}
	if strings.ContainsRune(got, 0x07) {
		t.Errorf("a bell character reached the terminal unescaped:\n%q", got)
	}
}

// TestCanaryEnrolScannerKindPrintsScannerCommand is #108's own trap,
// proved end-to-end through runCanaryEnrol rather than only at
// printScannerEnrolRunCommand's own level: --kind scanner must reach the
// scanner renderer, not fall into the "no install instructions
// registered" default that would otherwise mint a session and then fail
// half-way through printing.
func TestCanaryEnrolScannerKindPrintsScannerCommand(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	t.Setenv(envAdvertiseHost, "203.0.113.10")

	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	now := time.Now().UTC()
	if err := store.SetSetting(context.Background(), database, store.SettingAdminApprovalAddress, "admin@example.net", now); err != nil {
		t.Fatalf("set admin_approval_address: %v", err)
	}
	if err := store.SetSetting(context.Background(), database, store.SettingReleaseAddress, "release@example.net", now); err != nil {
		t.Fatalf("set release_address: %v", err)
	}
	closeCanaryDB(database)

	caDir := filepath.Join(t.TempDir(), "ca")
	if err := os.Mkdir(caDir, 0o700); err != nil {
		t.Fatalf("mkdir CA dir: %v", err)
	}
	t.Setenv(envCADir, caDir)
	if _, _, err := ca.Load(caDir, nil); err != nil {
		t.Fatalf("ca.Load: %v", err)
	}

	out, err := captureStdout(t, func() error {
		return runCanaryEnrol([]string{"--name", "scanner-1", "--lane", "front-door", "--kind", "scanner"})
	})
	if err != nil {
		t.Fatalf("runCanaryEnrol --kind scanner: %v", err)
	}
	if !strings.Contains(out, "docker run -d --name nightjar") {
		t.Fatalf("output does not carry the scanner's own run command:\n%s", out)
	}
	if strings.Contains(out, "mockingbird") {
		t.Fatalf("scanner enrolment output mentions mockingbird:\n%s", out)
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
