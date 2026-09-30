package runcmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agentkind"
)

func boolPtr(b bool) *bool { return &b }

// testUpgradeToken is a well-formed stand-in for store.MintUpgradeToken's
// output: 64 lowercase hex characters, obviously not random.
var testUpgradeToken = strings.Repeat("0123456789abcdef", 4)

// groupOpen and groupClose are the lines Upgrade wraps every script in
// (see Upgrade's doc comment).
var groupOpen = []string{
	"( set -e",
	`trap 'rc=$?; if [ "$rc" -eq 0 ]; then echo "birdcage upgrade: done"; else echo "birdcage upgrade stopped at: $step (nothing after it ran)" >&2; fi' EXIT`,
}

const groupClose = ")"

// grouped is golden with groupOpen before lines and groupClose after.
func grouped(lines ...string) string {
	all := append(append([]string{}, groupOpen...), lines...)
	return golden(append(all, groupClose)...)
}

// concat joins groups of lines into one list.
func concat(groups ...[]string) []string {
	var all []string
	for _, g := range groups {
		all = append(all, g...)
	}
	return all
}

// honeypotTokenStep is the upgrade token step for a honeypot whose
// agent image is mockingbird:latest.
var honeypotTokenStep = []string{
	"step='present the upgrade token'",
	"echo " + testUpgradeToken + ` | docker run --rm -i \`,
	`  --network container:holder \`,
	`  --read-only --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges \`,
	`  -v mockingbird-state:/var/lib/mockingbird:ro \`,
	"  mockingbird:latest upgrade-token || true",
}

// golden joins lines the way every Upgrade caller's fmt.Fprintln does:
// one "\n" between each pair, and a trailing one after the last --
// never an extra blank line beyond what an explicit "" entry (a
// deliberate blank() call in upgrade.go) already asks for.
func golden(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func TestUpgradeHoneypotWithLureOn(t *testing.T) {
	in := UpgradeInput{
		Kind:            agentkind.Honeypot,
		UpgradeToken:    testUpgradeToken,
		AdvertiseHost:   "canary.example.com",
		EnrolPort:       "8444",
		Pin:             "sha256/abc123",
		AgentImage:      "mockingbird:latest",
		HolderImage:     "holder:latest",
		OpenCanaryImage: "opencanary:latest",
		SMBLureImage:    "smb-lure:latest",
		BaitNames:       "fs-01,fs-02",
		SegmentProfile:  "windows",
		SMBLure:         boolPtr(true),
		SMBWorkgroup:    "WORKGROUP",
		SMBShares:       []string{"public", "backup", "scans"},
	}
	var out strings.Builder
	if err := Upgrade(&out, in); err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	want := grouped(concat([]string{
		"step='pull the current images'",
		"docker pull mockingbird:latest",
		"docker pull holder:latest",
		"docker pull opencanary:latest",
		"docker pull smb-lure:latest",
		"",
		"step='remove the old containers'",
		"docker rm -f smb-lure || true",
		"docker rm -f opencanary || true",
		"docker rm -f mockingbird || true",
		"docker rm -f holder || true",
		"",
		"step='start the address holder'",
		`docker volume create --driver local \`,
		`  --opt type=tmpfs --opt device=tmpfs --opt o=size=16m,mode=0755 \`,
		"  smb-audit",
		"",
		`docker run -d --name holder --restart unless-stopped \`,
		`  --read-only \`,
		`  --cap-drop ALL \`,
		`  --security-opt no-new-privileges \`,
		`  --pids-limit 16 \`,
		`  --memory 32m \`,
		`  -v smb-audit:/audit:ro \`,
		"  holder:latest",
		"",
	}, honeypotTokenStep, []string{
		"",
		"step='start mockingbird'",
		`docker run -d --name mockingbird --restart unless-stopped \`,
		`  --cap-add NET_RAW \`,
		`  --security-opt no-new-privileges \`,
		`  -v mockingbird-state:/var/lib/mockingbird -v mockingbird-log:/var/log/opencanary:ro \`,
		`  --network container:holder \`,
		`  -v smb-audit:/audit:ro \`,
		`  -e MOCKINGBIRD_SMB_AUDIT_PATH=/audit/smb.log \`,
		`  -e MOCKINGBIRD_BIRDCAGE_URL=https://canary.example.com:8444 \`,
		`  -e MOCKINGBIRD_CA_PIN=sha256/abc123 \`,
		`  -e MOCKINGBIRD_POISONER_NAMES=fs-01,fs-02 \`,
		`  -e MOCKINGBIRD_POISONER_PROFILE=windows \`,
		"  mockingbird:latest",
		"",
		"step='start opencanary'",
		`docker run -d --name opencanary --restart unless-stopped --init \`,
		`  --network container:holder \`,
		`  --sysctl net.ipv4.ip_unprivileged_port_start=0 \`,
		`  --read-only \`,
		`  --cap-drop ALL \`,
		`  --security-opt no-new-privileges \`,
		`  --pids-limit 32 \`,
		`  --memory 128m \`,
		`  --tmpfs /var/tmp:size=8m \`,
		`  -v mockingbird-log:/var/log/opencanary \`,
		"  opencanary:latest",
		"",
		"step='start the smb lure'",
		`docker run -d --name smb-lure --restart unless-stopped \`,
		`  --network container:holder \`,
		`  --read-only \`,
		`  --cap-drop ALL \`,
		`  --cap-add SETUID --cap-add SETGID --cap-add NET_BIND_SERVICE \`,
		`  --security-opt no-new-privileges \`,
		`  --pids-limit 128 \`,
		`  --memory 192m \`,
		`  --ulimit core=0 \`,
		`  --tmpfs /run:size=8m \`,
		`  --tmpfs /var/lib/samba:size=8m \`,
		`  --tmpfs /var/cache/samba:size=8m \`,
		`  --tmpfs /var/log:size=8m \`,
		`  -v smb-audit:/audit \`,
		`  -e SMB_WORKGROUP=WORKGROUP \`,
		`  -e SMB_SHARE_PUBLIC=public \`,
		`  -e SMB_SHARE_BACKUP=backup \`,
		`  -e SMB_SHARE_SCANS=scans \`,
		"  smb-lure:latest",
	})...)
	if out.String() != want {
		t.Errorf("Upgrade output mismatch:\ngot:\n%s\nwant:\n%s", out.String(), want)
	}
	assertNoDeployToken(t, out.String())
	assertNoVolumeRemoval(t, out.String())
	assertOrder(t, out.String(), "docker run -d --name holder", "docker run -d --name mockingbird",
		"docker run -d --name opencanary", "docker run -d --name smb-lure")
}

func TestUpgradeHoneypotWithLureOff(t *testing.T) {
	in := UpgradeInput{
		Kind:            agentkind.Honeypot,
		UpgradeToken:    testUpgradeToken,
		AdvertiseHost:   "canary.example.com",
		EnrolPort:       "8444",
		Pin:             "sha256/abc123",
		AgentImage:      "mockingbird:latest",
		HolderImage:     "holder:latest",
		OpenCanaryImage: "opencanary:latest",
		SMBLureImage:    "smb-lure:latest",
		SMBLure:         boolPtr(false),
	}
	var out strings.Builder
	if err := Upgrade(&out, in); err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	want := grouped(concat([]string{
		"step='pull the current images'",
		"docker pull mockingbird:latest",
		"docker pull holder:latest",
		"docker pull opencanary:latest",
		"",
		"step='remove the old containers'",
		"docker rm -f opencanary || true",
		"docker rm -f mockingbird || true",
		"docker rm -f holder || true",
		"",
		"step='start the address holder'",
		`docker run -d --name holder --restart unless-stopped \`,
		`  --read-only \`,
		`  --cap-drop ALL \`,
		`  --security-opt no-new-privileges \`,
		`  --pids-limit 16 \`,
		`  --memory 32m \`,
		"  holder:latest",
		"",
	}, honeypotTokenStep, []string{
		"",
		"step='start mockingbird'",
		`docker run -d --name mockingbird --restart unless-stopped \`,
		`  --cap-add NET_RAW \`,
		`  --security-opt no-new-privileges \`,
		`  -v mockingbird-state:/var/lib/mockingbird -v mockingbird-log:/var/log/opencanary:ro \`,
		`  --network container:holder \`,
		`  -e MOCKINGBIRD_BIRDCAGE_URL=https://canary.example.com:8444 \`,
		`  -e MOCKINGBIRD_CA_PIN=sha256/abc123 \`,
		"  mockingbird:latest",
		"",
		"step='start opencanary'",
		`docker run -d --name opencanary --restart unless-stopped --init \`,
		`  --network container:holder \`,
		`  --sysctl net.ipv4.ip_unprivileged_port_start=0 \`,
		`  --read-only \`,
		`  --cap-drop ALL \`,
		`  --security-opt no-new-privileges \`,
		`  --pids-limit 32 \`,
		`  --memory 128m \`,
		`  --tmpfs /var/tmp:size=8m \`,
		`  -v mockingbird-log:/var/log/opencanary \`,
		"  opencanary:latest",
		"",
		"# smb lure off for this canary: no smb-lure container to pull, remove or re-run",
	})...)
	if out.String() != want {
		t.Errorf("Upgrade output mismatch:\ngot:\n%s\nwant:\n%s", out.String(), want)
	}
	assertNoDeployToken(t, out.String())
	assertNoVolumeRemoval(t, out.String())
	if strings.Contains(out.String(), "smb-lure:latest") {
		t.Error("lure off: output still names the smb-lure image")
	}
	if strings.Contains(out.String(), "docker run -d --name smb-lure") {
		t.Error("lure off: output still runs an smb-lure container")
	}
}

func TestUpgradeHoneypotWithUnknownLure(t *testing.T) {
	in := UpgradeInput{
		Kind:            agentkind.Honeypot,
		UpgradeToken:    testUpgradeToken,
		AdvertiseHost:   "canary.example.com",
		EnrolPort:       "8444",
		Pin:             "sha256/abc123",
		AgentImage:      "mockingbird:latest",
		HolderImage:     "holder:latest",
		OpenCanaryImage: "opencanary:latest",
		SMBLureImage:    "smb-lure:latest",
		// SMBLure left nil: a canary enrolled before issue #54.
	}
	var out strings.Builder
	if err := Upgrade(&out, in); err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	want := grouped(concat([]string{
		"step='pull the current images'",
		"docker pull mockingbird:latest",
		"docker pull holder:latest",
		"docker pull opencanary:latest",
		"",
		"step='remove the old containers'",
		"docker rm -f opencanary || true",
		"docker rm -f mockingbird || true",
		"docker rm -f holder || true",
		"",
		"step='start the address holder'",
		`docker run -d --name holder --restart unless-stopped \`,
		`  --read-only \`,
		`  --cap-drop ALL \`,
		`  --security-opt no-new-privileges \`,
		`  --pids-limit 16 \`,
		`  --memory 32m \`,
		"  holder:latest",
		"",
	}, honeypotTokenStep, []string{
		"",
		"step='start mockingbird'",
		`docker run -d --name mockingbird --restart unless-stopped \`,
		`  --cap-add NET_RAW \`,
		`  --security-opt no-new-privileges \`,
		`  -v mockingbird-state:/var/lib/mockingbird -v mockingbird-log:/var/log/opencanary:ro \`,
		`  --network container:holder \`,
		`  -e MOCKINGBIRD_BIRDCAGE_URL=https://canary.example.com:8444 \`,
		`  -e MOCKINGBIRD_CA_PIN=sha256/abc123 \`,
		"  mockingbird:latest",
		"",
		"step='start opencanary'",
		`docker run -d --name opencanary --restart unless-stopped --init \`,
		`  --network container:holder \`,
		`  --sysctl net.ipv4.ip_unprivileged_port_start=0 \`,
		`  --read-only \`,
		`  --cap-drop ALL \`,
		`  --security-opt no-new-privileges \`,
		`  --pids-limit 32 \`,
		`  --memory 128m \`,
		`  --tmpfs /var/tmp:size=8m \`,
		`  -v mockingbird-log:/var/log/opencanary \`,
		"  opencanary:latest",
		"",
		"# SMB lure: unknown for this canary -- it was enrolled before birdcage started",
		"# recording this (issue #54). Check the canary host for a running smb-lure",
		"# container (docker ps -a --filter name=smb-lure) before relying on anything",
		"# below. Its workgroup and share names were never recorded either, so the",
		"# commented command below uses placeholders -- replace them with what the",
		"# host is actually running, or leave the lure off if `docker ps -a` finds none.",
		"# docker pull smb-lure:latest",
		"# docker rm -f smb-lure",
		`# docker run -d --name smb-lure --restart unless-stopped \`,
		`#   --network container:holder \`,
		`#   --read-only \`,
		`#   --cap-drop ALL \`,
		`#   --cap-add SETUID --cap-add SETGID --cap-add NET_BIND_SERVICE \`,
		`#   --security-opt no-new-privileges \`,
		`#   --pids-limit 128 \`,
		`#   --memory 192m \`,
		`#   --ulimit core=0 \`,
		`#   --tmpfs /run:size=8m \`,
		`#   --tmpfs /var/lib/samba:size=8m \`,
		`#   --tmpfs /var/cache/samba:size=8m \`,
		`#   --tmpfs /var/log:size=8m \`,
		`#   -v smb-audit:/audit \`,
		`#   -e SMB_WORKGROUP=WORKGROUP-UNKNOWN-CHECK-HOST \`,
		`#   -e SMB_SHARE_PUBLIC=SHARE1-UNKNOWN-CHECK-HOST \`,
		`#   -e SMB_SHARE_BACKUP=SHARE2-UNKNOWN-CHECK-HOST \`,
		`#   -e SMB_SHARE_SCANS=SHARE3-UNKNOWN-CHECK-HOST \`,
		"#   smb-lure:latest",
	})...)
	if out.String() != want {
		t.Errorf("Upgrade output mismatch:\ngot:\n%s\nwant:\n%s", out.String(), want)
	}
	assertNoDeployToken(t, out.String())
	assertNoVolumeRemoval(t, out.String())
	// Every lure-specific line the operator would have to act on is
	// commented -- never a bare `docker run -d --name smb-lure` or
	// `docker rm -f smb-lure` that could be pasted by mistake.
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "smb-lure") && !strings.HasPrefix(strings.TrimSpace(line), "#") && !strings.Contains(line, "-v smb-lure") {
			// smb-lure only appears in commented lines or container/image
			// names inside them; every one of those lines starts with "#".
			t.Errorf("uncommented line mentions smb-lure: %q", line)
		}
	}
}

func TestUpgradeScanner(t *testing.T) {
	in := UpgradeInput{
		Kind:          agentkind.Scanner,
		UpgradeToken:  testUpgradeToken,
		AdvertiseHost: "canary.example.com",
		EnrolPort:     "8444",
		Pin:           "sha256/abc123",
		AgentImage:    "nightjar:latest",
	}
	var out strings.Builder
	if err := Upgrade(&out, in); err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	want := grouped(
		"step='pull the current image'",
		"docker pull nightjar:latest",
		"",
		"step='remove the old container'",
		"docker rm -f nightjar || true",
		"",
		"step='present the upgrade token'",
		"echo "+testUpgradeToken+` | docker run --rm -i \`,
		`  --read-only --cap-drop ALL --security-opt no-new-privileges \`,
		`  -v nightjar-state:/var/lib/nightjar:ro \`,
		"  nightjar:latest upgrade-token || true",
		"",
		"step='start nightjar'",
		`docker run -d --name nightjar --restart unless-stopped \`,
		`  --read-only --cap-drop ALL --security-opt no-new-privileges \`,
		`  -v /:/host:ro \`,
		`  -v /dev/null:/host/etc/shadow:ro \`,
		`  -v /dev/null:/host/etc/gshadow:ro \`,
		`  --tmpfs /host/etc/ssh:ro \`,
		`  --tmpfs /host/root:ro \`,
		`  --tmpfs /host/proc:ro \`,
		`  --tmpfs /host/run:ro \`,
		`  --tmpfs /host/sys:ro \`,
		`  --tmpfs /host/dev:ro \`,
		`  --tmpfs /host/tmp:ro \`,
		`  --tmpfs /host/var/tmp:ro \`,
		`  --tmpfs /host/home:ro \`,
		`  -v nightjar-state:/var/lib/nightjar -v nightjar-grype-db:/var/lib/nightjar-grype-db \`,
		`  -e NIGHTJAR_BIRDCAGE_URL=https://canary.example.com:8444 \`,
		`  -e NIGHTJAR_CA_PIN=sha256/abc123 \`,
		"  nightjar:latest",
	)
	if out.String() != want {
		t.Errorf("Upgrade output mismatch:\ngot:\n%s\nwant:\n%s", out.String(), want)
	}
	assertNoDeployToken(t, out.String())
	assertNoVolumeRemoval(t, out.String())
}

// TestUpgradeEscapesOperatorSuppliedValues confirms every value that
// came from an operator or from birdcage's own configuration (never a
// fixed constant of this package's own) is escaped at the point it
// reaches the returned lines, matching cmd/birdcage's own rule --
// mirroring TestSMBLureRunCommandEscapesOperatorSuppliedValues.
func TestUpgradeEscapesOperatorSuppliedValues(t *testing.T) {
	control := "OFFICE\x1b[31m"
	in := UpgradeInput{
		Kind:            agentkind.Honeypot,
		UpgradeToken:    testUpgradeToken,
		AdvertiseHost:   "host\x07",
		EnrolPort:       "8444",
		Pin:             "sha256/abc123",
		AgentImage:      "mockingbird\x1b]0;x\x07",
		HolderImage:     "holder\x1b]0;x\x07",
		OpenCanaryImage: "opencanary\x1b]0;x\x07",
		SMBLureImage:    "smb-lure\x1b]0;x\x07",
		BaitNames:       "fs\x07",
		SegmentProfile:  "windows\x07",
		SMBLure:         boolPtr(true),
		SMBWorkgroup:    control,
		SMBShares:       []string{"a\x07", "b", "c"},
	}
	var out strings.Builder
	if err := Upgrade(&out, in); err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	got := out.String()
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("an escape character reached the output unescaped:\n%q", got)
	}
	if strings.ContainsRune(got, 0x07) {
		t.Errorf("a bell character reached the output unescaped:\n%q", got)
	}
}

func assertNoDeployToken(t *testing.T, out string) {
	t.Helper()
	for _, name := range []string{"MOCKINGBIRD_DEPLOY_TOKEN", "NIGHTJAR_DEPLOY_TOKEN"} {
		if strings.Contains(out, name) {
			t.Errorf("upgrade output carries %s, which the upgrade command must never mint or print", name)
		}
	}
}

func assertNoVolumeRemoval(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "volume rm") || strings.Contains(out, "volume prune") {
		t.Errorf("upgrade output removes a volume -- that destroys the credential state it depends on:\n%s", out)
	}
}

func assertOrder(t *testing.T, out string, inOrder ...string) {
	t.Helper()
	last := -1
	for _, marker := range inOrder {
		i := strings.Index(out, marker)
		if i < 0 {
			t.Fatalf("upgrade output is missing %q", marker)
		}
		if i < last {
			t.Errorf("upgrade output has %q before an earlier-required line", marker)
		}
		last = i
	}
}

// TestUpgradeRefusesMalformedToken: Upgrade never prints a script
// without a well-formed token, and never one carrying something that is
// not hex -- the token is printed unescaped, so its shape is what keeps
// it inert in a shell.
func TestUpgradeRefusesMalformedToken(t *testing.T) {
	for _, tok := range []string{
		"",
		testUpgradeToken[:63],
		testUpgradeToken + "0",
		strings.ToUpper(testUpgradeToken),
		testUpgradeToken[:62] + "; rm -rf /"[:2],
		testUpgradeToken[:63] + "g",
	} {
		for _, kind := range []agentkind.Kind{agentkind.Honeypot, agentkind.Scanner} {
			var out strings.Builder
			err := Upgrade(&out, UpgradeInput{Kind: kind, UpgradeToken: tok, AgentImage: "a", HolderImage: "h", OpenCanaryImage: "o"})
			if err == nil {
				t.Errorf("Upgrade(%s) accepted token %q", kind, tok)
			}
			if out.Len() != 0 {
				t.Errorf("Upgrade(%s) wrote output for token %q:\n%s", kind, tok, out.String())
			}
		}
	}
}

// TestUpgradeTokenOnlyOnStdin: the token appears exactly once, as the
// argument of the shell's own echo builtin piped into the upgrade-token
// step -- never in a docker argument or an -e variable, where it would
// sit in a process listing or the container's stored configuration.
func TestUpgradeTokenOnlyOnStdin(t *testing.T) {
	for _, in := range []UpgradeInput{
		{Kind: agentkind.Honeypot, UpgradeToken: testUpgradeToken, AdvertiseHost: "h", EnrolPort: "1", Pin: "p", AgentImage: "mockingbird:latest", HolderImage: "holder:latest", OpenCanaryImage: "opencanary:latest", SMBLure: boolPtr(false)},
		{Kind: agentkind.Scanner, UpgradeToken: testUpgradeToken, AdvertiseHost: "h", EnrolPort: "1", Pin: "p", AgentImage: "nightjar:latest"},
	} {
		var out strings.Builder
		if err := Upgrade(&out, in); err != nil {
			t.Fatalf("Upgrade(%s): %v", in.Kind, err)
		}
		got := out.String()
		if n := strings.Count(got, testUpgradeToken); n != 1 {
			t.Fatalf("%s: token appears %d times, want 1:\n%s", in.Kind, n, got)
		}
		for _, line := range strings.Split(got, "\n") {
			if strings.Contains(line, testUpgradeToken) && !strings.HasPrefix(line, "echo "+testUpgradeToken+" | docker run --rm -i ") {
				t.Errorf("%s: token on a line other than the stdin pipe: %q", in.Kind, line)
			}
		}
		if strings.Contains(got, "UPGRADE_TOKEN") {
			t.Errorf("%s: an UPGRADE_TOKEN variable is printed:\n%s", in.Kind, got)
		}
	}
}

// TestUpgradeTokenStepOrder: the token is presented after the old agent
// is gone and before the new one starts -- B4 compares builds on the new
// agent's first heartbeat, so the window must already be open by then.
func TestUpgradeTokenStepOrder(t *testing.T) {
	var hp, sc strings.Builder
	if err := Upgrade(&hp, UpgradeInput{Kind: agentkind.Honeypot, UpgradeToken: testUpgradeToken, AgentImage: "m", HolderImage: "h", OpenCanaryImage: "o", SMBLure: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	assertOrder(t, hp.String(), "docker rm -f mockingbird", "docker run -d --name holder", "upgrade-token || true", "docker run -d --name mockingbird")
	if err := Upgrade(&sc, UpgradeInput{Kind: agentkind.Scanner, UpgradeToken: testUpgradeToken, AgentImage: "n"}); err != nil {
		t.Fatal(err)
	}
	assertOrder(t, sc.String(), "docker rm -f nightjar", "upgrade-token || true", "docker run -d --name nightjar")
}

// fakeDocker is a POSIX sh stand-in for docker: it logs each call's
// arguments, and what arrived on stdin for `run --rm -i`, to $LOG, and
// exits with $FAIL_ON's status 1 when its arguments contain $FAIL_ON.
const fakeDocker = `#!/bin/sh
printf 'args:%s\n' "$*" >> "$LOG"
case "$*" in
  *"--rm -i"*) printf 'stdin:%s\n' "$(cat)" >> "$LOG" ;;
esac
if [ -n "$FAIL_ON" ]; then
  case "$*" in *"$FAIL_ON"*) exit 1 ;; esac
fi
exit 0
`

// runPasted feeds script to sh on stdin -- the way a paste reaches an
// interactive shell -- with fakeDocker first on PATH, and returns the
// combined output and the docker call log.
func runPasted(t *testing.T, shell, script, failOn string) (output, log string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fakeDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "log")
	cmd := exec.Command(shell)
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "LOG=" + logPath, "FAIL_ON=" + failOn}
	out, _ := cmd.CombinedOutput()
	b, _ := os.ReadFile(logPath)
	return string(out), string(b)
}

// TestUpgradeScriptRunsAsOnePaste is the owner's "one copy, one paste"
// (2026-09-27) as a test: the whole script fed to sh as one unit runs
// every step, hands the token to the upgrade-token step on stdin and
// nowhere else, and says it is done; a failing step stops everything
// after it and names itself.
func TestUpgradeScriptRunsAsOnePaste(t *testing.T) {
	var shells []string
	for _, sh := range []string{"sh", "dash", "bash"} {
		if p, err := exec.LookPath(sh); err == nil {
			shells = append(shells, p)
		}
	}
	if len(shells) == 0 {
		t.Skip("no POSIX shell on PATH")
	}
	var out strings.Builder
	if err := Upgrade(&out, UpgradeInput{
		Kind: agentkind.Honeypot, UpgradeToken: testUpgradeToken, AdvertiseHost: "h", EnrolPort: "1", Pin: "p",
		AgentImage: "mockingbird:latest", HolderImage: "holder:latest", OpenCanaryImage: "opencanary:latest",
		SMBLureImage: "smb-lure:latest", SMBLure: boolPtr(true), SMBWorkgroup: "W", SMBShares: []string{"a", "b", "c"},
	}); err != nil {
		t.Fatal(err)
	}
	script := out.String()

	for _, shell := range shells {
		t.Run(filepath.Base(shell), func(t *testing.T) {
			output, log := runPasted(t, shell, script, "")
			if !strings.Contains(output, "birdcage upgrade: done") {
				t.Fatalf("the script did not run to completion:\n%s\nlog:\n%s", output, log)
			}
			if !strings.Contains(log, "stdin:"+testUpgradeToken+"\n") {
				t.Errorf("the upgrade-token step did not get the token on stdin:\n%s", log)
			}
			for _, line := range strings.Split(log, "\n") {
				if strings.HasPrefix(line, "args:") && strings.Contains(line, testUpgradeToken) {
					t.Errorf("the token reached docker's arguments: %q", line)
				}
			}
			assertOrder(t, log, "args:pull mockingbird:latest", "args:rm -f holder", "args:run -d --name holder",
				"stdin:"+testUpgradeToken, "args:run -d --name mockingbird", "args:run -d --name opencanary", "args:run -d --name smb-lure")

			// A refused token does not stop the upgrade.
			output, log = runPasted(t, shell, script, "upgrade-token")
			if !strings.Contains(output, "birdcage upgrade: done") || !strings.Contains(log, "args:run -d --name mockingbird") {
				t.Errorf("a failed upgrade-token step stopped the upgrade:\n%s\nlog:\n%s", output, log)
			}

			// Any other failure stops it there -- removal (below) is the
			// one step that has to tolerate its own failure.
			output, log = runPasted(t, shell, script, "run -d --name opencanary")
			if !strings.Contains(output, "birdcage upgrade stopped at: start opencanary") {
				t.Errorf("a failed step was not named:\n%s", output)
			}
			if strings.Contains(log, "args:run -d --name smb-lure") || strings.Contains(output, "birdcage upgrade: done") {
				t.Errorf("steps after the failure ran:\n%s\nlog:\n%s", output, log)
			}
		})
	}
}

// TestUpgradeRemovalStepIsRetrySafe: the "remove the old containers"
// step has to tolerate `docker rm -f` failing on a container that is
// simply not there, not just a real docker error -- the shape a
// re-paste sees once some of the four were already removed by an
// earlier, partly-failed run. A script that still stopped here on that
// kind of failure would abort at the same named step on every retry,
// with no sign that some containers were already gone.
func TestUpgradeRemovalStepIsRetrySafe(t *testing.T) {
	var shells []string
	for _, sh := range []string{"sh", "dash", "bash"} {
		if p, err := exec.LookPath(sh); err == nil {
			shells = append(shells, p)
		}
	}
	if len(shells) == 0 {
		t.Skip("no POSIX shell on PATH")
	}
	var out strings.Builder
	if err := Upgrade(&out, UpgradeInput{
		Kind: agentkind.Honeypot, UpgradeToken: testUpgradeToken, AdvertiseHost: "h", EnrolPort: "1", Pin: "p",
		AgentImage: "mockingbird:latest", HolderImage: "holder:latest", OpenCanaryImage: "opencanary:latest",
		SMBLureImage: "smb-lure:latest", SMBLure: boolPtr(true), SMBWorkgroup: "W", SMBShares: []string{"a", "b", "c"},
	}); err != nil {
		t.Fatal(err)
	}
	script := out.String()

	for _, shell := range shells {
		t.Run(filepath.Base(shell), func(t *testing.T) {
			// smb-lure is the first removal attempted -- failing it
			// simulates the worst case, where nothing has been removed
			// yet on this attempt.
			output, log := runPasted(t, shell, script, "rm -f smb-lure")
			if !strings.Contains(output, "birdcage upgrade: done") {
				t.Fatalf("a failed removal of an already-gone container stopped the script:\n%s\nlog:\n%s", output, log)
			}
			assertOrder(t, log, "args:rm -f smb-lure", "args:rm -f opencanary", "args:rm -f mockingbird",
				"args:rm -f holder", "args:run -d --name holder", "args:run -d --name mockingbird",
				"args:run -d --name opencanary", "args:run -d --name smb-lure")
		})
	}
}
