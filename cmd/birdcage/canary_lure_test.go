package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSMBLureRunCommandCarriesEveryHardeningFlag pins the lure's `docker
// run` block the way TestEnrolRunCommandCarriesEveryRequiredFlag pins the
// canary's, and for a stronger reason: this is the one container the
// design expects to be attacked, and every flag below is what makes the
// root inside it worth having (#87 decision 5). Each is asserted together
// with what it holds shut, so a future edit that drops one argues with a
// named expectation rather than with a diff nobody reads.
func TestSMBLureRunCommandCarriesEveryHardeningFlag(t *testing.T) {
	var out strings.Builder
	settings, err := parseSMBSettings(defaultSMBWorkgroup, defaultSMBShares)
	if err != nil {
		t.Fatalf("parseSMBSettings on the defaults: %v", err)
	}
	if err := printSMBLureRunCommand(&out, defaultSMBLureImage, settings); err != nil {
		t.Fatalf("printSMBLureRunCommand: %v", err)
	}
	got := out.String()

	required := []struct {
		flag string
		why  string
	}{
		{"--network container:mockingbird", "decision 3: 445 sits on the canary's own address, and the lure publishes no port of its own"},
		{"--read-only", "nothing an attacker writes to the image's filesystem can even be attempted"},
		{"--cap-drop ALL", "the four-out-of-forty starting point; everything added back is added back by name"},
		{"--cap-add SETUID", "proven necessary: without it every connection dies on the per-connection uid switch"},
		{"--cap-add SETGID", "proven necessary: without it smbd dies at start on sys_setgroups"},
		{"--cap-add NET_BIND_SERVICE", "not needed under Docker's own unprivileged-port sysctl, kept because that default is Docker's and not the kernel's"},
		{"--security-opt no-new-privileges", "a setuid binary inside cannot raise privileges"},
		{"--pids-limit 128", "a fork loop cannot exhaust the host"},
		{"--memory 192m", "the same for memory"},
		{"--ulimit core=0", "Samba's own dump-core option no longer exists, so this is the layer that can still refuse core files"},
		{"--tmpfs /run:size=8m", "every path Samba writes to is memory that vanishes on restart"},
		{"--tmpfs /var/lib/samba:size=8m", "the same"},
		{"--tmpfs /var/cache/samba:size=8m", "the same"},
		{"--tmpfs /var/log:size=8m", "the same"},
		{"-v smb-audit:/audit", "the lure writes the audit file; the canary mounts the same volume read-only"},
		{"--restart unless-stopped", "a lure that stops serving is a canary that has quietly lost a service"},
		{"docker volume create", "the volume has to be created with tmpfs options before either container reaches it, or Docker makes a plain on-disk one"},
		{"--opt o=size=16m,mode=0755", "size-capped: filling it crashes the lure, never the host"},
	}
	for _, r := range required {
		if !strings.Contains(got, r.flag) {
			t.Errorf("printed command is missing %q -- %s\ngot:\n%s", r.flag, r.why, got)
		}
	}

	// DAC_OVERRIDE is absent on purpose, and CHOWN was removed once
	// testing showed it unused. Both are asserted absent so a future
	// "just add the capability" fix has to argue with this test.
	for _, forbidden := range []string{"DAC_OVERRIDE", "--cap-add CHOWN", "--privileged"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("printed command carries %q, which was deliberately left out\ngot:\n%s", forbidden, got)
		}
	}

	for _, want := range []string{
		"-e SMB_WORKGROUP=WORKGROUP",
		"-e SMB_SHARE_PUBLIC=public",
		"-e SMB_SHARE_BACKUP=backup",
		"-e SMB_SHARE_SCANS=scans",
		"smb-lure:latest",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("printed command is missing %q\ngot:\n%s", want, got)
		}
	}
}

// TestSMBLureRunCommandMatchesTheDocs is the check that keeps the three
// copies of this command identical: what the command prints, what
// docs/enrolment.md tells an operator to paste, and what
// build/smb-lure/README.md documents. There was no such check for the
// canary's own run command and the docs drifting was always possible; for
// the lure a dropped line is a dropped hardening flag, so the promise is
// enforced rather than made.
func TestSMBLureRunCommandMatchesTheDocs(t *testing.T) {
	settings, err := parseSMBSettings(defaultSMBWorkgroup, defaultSMBShares)
	if err != nil {
		t.Fatalf("parseSMBSettings on the defaults: %v", err)
	}
	var out strings.Builder
	if err := printSMBLureRunCommand(&out, defaultSMBLureImage, settings); err != nil {
		t.Fatalf("printSMBLureRunCommand: %v", err)
	}

	// The repository root, from this package's directory.
	root := filepath.Join("..", "..")
	for _, doc := range []string{
		filepath.Join(root, "docs", "enrolment.md"),
		filepath.Join(root, "build", "smb-lure", "README.md"),
	} {
		body, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		text := string(body)
		for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			if !strings.Contains(text, line) {
				t.Errorf("%s does not contain this line of the printed command:\n\t%s\n"+
					"the two must be identical -- copy the command's own output into the doc", doc, line)
			}
		}
	}
}

func TestParseSMBSettings(t *testing.T) {
	tests := []struct {
		name      string
		workgroup string
		shares    string
		wantErr   string
	}{
		{name: "the defaults", workgroup: defaultSMBWorkgroup, shares: defaultSMBShares},
		{name: "an operator's own naming", workgroup: "OFFICE", shares: "shared,archive,scanner"},
		{name: "spaces around the names are trimmed", workgroup: "OFFICE", shares: "shared, archive , scanner"},
		{name: "an empty workgroup", workgroup: "", shares: defaultSMBShares, wantErr: "--smb-workgroup"},
		{name: "a workgroup over 15 characters", workgroup: strings.Repeat("A", 16), shares: defaultSMBShares, wantErr: "--smb-workgroup"},
		{name: "a workgroup with a space", workgroup: "MY OFFICE", shares: defaultSMBShares, wantErr: "--smb-workgroup"},
		{name: "a workgroup that would break the config file", workgroup: "A\nB", shares: defaultSMBShares, wantErr: "--smb-workgroup"},
		{name: "two shares", workgroup: "OFFICE", shares: "a,b", wantErr: "exactly 3 names"},
		{name: "four shares", workgroup: "OFFICE", shares: "a,b,c,d", wantErr: "exactly 3 names"},
		{name: "an empty share name", workgroup: "OFFICE", shares: "a,,c", wantErr: "usable share name"},
		{name: "a share name with a bracket", workgroup: "OFFICE", shares: "a,[global],c", wantErr: "usable share name"},
		{name: "the same share twice", workgroup: "OFFICE", shares: "a,b,a", wantErr: "appears twice"},
		{name: "the same share in a different case", workgroup: "OFFICE", shares: "a,b,A", wantErr: "appears twice"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSMBSettings(tc.workgroup, tc.shares)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseSMBSettings accepted %q / %q", tc.workgroup, tc.shares)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to name %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSMBSettings: %v", err)
			}
			if len(got.shares) != smbShareCount {
				t.Errorf("got %d share names, want %d", len(got.shares), smbShareCount)
			}
			for _, name := range got.shares {
				if strings.TrimSpace(name) != name {
					t.Errorf("share name %q was not trimmed", name)
				}
			}
		})
	}
}

func TestLureFlag(t *testing.T) {
	tests := []struct {
		value   string
		wantOn  bool
		wantErr string
	}{
		{value: "smb=off", wantOn: false},
		{value: "smb=on", wantOn: true},
		{value: " smb=off ", wantOn: false},
		{value: "smb=off,", wantOn: false},
		{value: "smb", wantErr: "wants name=state"},
		{value: "smb=maybe", wantErr: "unknown state"},
		{value: "SMB=off", wantErr: "unknown lure"},
		{value: "telnet=off", wantErr: "unknown lure"},
	}
	for _, tc := range tests {
		t.Run(tc.value, func(t *testing.T) {
			state := lureState{smb: true}
			f := &lureFlag{state: &state}
			err := f.Set(tc.value)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Set(%q) was accepted; lures are now %+v", tc.value, state)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to name %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Set(%q): %v", tc.value, err)
			}
			if state.smb != tc.wantOn {
				t.Errorf("smb = %v, want %v", state.smb, tc.wantOn)
			}
			if !f.set {
				t.Error("the flag did not record that it was set, so the kind check cannot notice it")
			}
		})
	}

	// String is what `-h` shows as the default, so it has to say the
	// state rather than an empty string.
	on := lureState{smb: true}
	if got := (&lureFlag{state: &on}).String(); got != "smb=on" {
		t.Errorf("String() with smb on = %q", got)
	}
	off := lureState{}
	if got := (&lureFlag{state: &off}).String(); got != "smb=off" {
		t.Errorf("String() with smb off = %q", got)
	}
	if got := (*lureFlag)(nil).String(); got != "smb=on" {
		t.Errorf("String() on a nil flag = %q, want the default", got)
	}
}

// TestEnrolRunCommandWithoutTheLure: `--lure smb=off` has to leave the
// canary with no audit mount and no MOCKINGBIRD_SMB_AUDIT_PATH, because
// the variable being set is the whole of what starts the agent's smb road.
func TestEnrolRunCommandWithoutTheLure(t *testing.T) {
	var out strings.Builder
	if err := printEnrolRunCommand(&out, "203.0.113.10", "8444", "deadbeef", "cafebabe", "mockingbird:latest", false, "", ""); err != nil {
		t.Fatalf("printEnrolRunCommand: %v", err)
	}
	got := out.String()

	for _, absent := range []string{"smb-audit", "MOCKINGBIRD_SMB_AUDIT_PATH", "/audit"} {
		if strings.Contains(got, absent) {
			t.Errorf("the command still mentions %q with the lure off\ngot:\n%s", absent, got)
		}
	}
	// And everything else is untouched.
	if !strings.Contains(got, "-v mockingbird-state:/var/lib/mockingbird") {
		t.Errorf("turning the lure off changed the rest of the command\ngot:\n%s", got)
	}
}

func TestSMBLureRunCommandEscapesOperatorSuppliedValues(t *testing.T) {
	// parseSMBSettings would refuse these, so this asserts the second
	// line of defence: the values are escaped where they reach the
	// terminal, the same rule every other command in this package follows.
	settings := smbSettings{workgroup: "OFFICE\x1b[31m", shares: []string{"a\x07", "b", "c"}}
	var out strings.Builder
	if err := printSMBLureRunCommand(&out, "image\x1b]0;x\x07", settings); err != nil {
		t.Fatalf("printSMBLureRunCommand: %v", err)
	}
	got := out.String()
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("an escape character reached the terminal unescaped:\n%q", got)
	}
	if strings.ContainsRune(got, 0x07) {
		t.Errorf("a bell character reached the terminal unescaped:\n%q", got)
	}
}

func TestSMBLureRunCommandRefusesUnvalidatedSettings(t *testing.T) {
	// The renderer indexes three share names. Reaching it without
	// parseSMBSettings having checked that is a programming error, and it
	// says so rather than panicking on the index.
	var out strings.Builder
	if err := printSMBLureRunCommand(&out, defaultSMBLureImage, smbSettings{workgroup: "OFFICE"}); err == nil {
		t.Error("printSMBLureRunCommand accepted settings with no share names")
	}
}

func TestSMBLureImageComesFromTheEnvironment(t *testing.T) {
	t.Setenv(envSMBLureImage, "")
	if got := smbLureImage(); got != defaultSMBLureImage {
		t.Errorf("smbLureImage() = %q with nothing set, want %q", got, defaultSMBLureImage)
	}
	t.Setenv(envSMBLureImage, "registry.example.invalid/smb-lure@sha256:abc")
	if got := smbLureImage(); got != "registry.example.invalid/smb-lure@sha256:abc" {
		t.Errorf("smbLureImage() = %q, want the environment's value", got)
	}
}
