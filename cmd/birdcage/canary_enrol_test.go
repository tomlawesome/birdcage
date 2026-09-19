package main

import (
	"strings"
	"testing"
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
