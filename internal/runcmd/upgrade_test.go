package runcmd

import (
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agentkind"
)

func boolPtr(b bool) *bool { return &b }

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
	want := golden(
		"docker pull mockingbird:latest",
		"docker pull holder:latest",
		"docker pull opencanary:latest",
		"docker pull smb-lure:latest",
		"",
		"docker rm -f smb-lure",
		"docker rm -f opencanary",
		"docker rm -f mockingbird",
		"docker rm -f holder",
		"",
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
	)
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
	want := golden(
		"docker pull mockingbird:latest",
		"docker pull holder:latest",
		"docker pull opencanary:latest",
		"",
		"docker rm -f opencanary",
		"docker rm -f mockingbird",
		"docker rm -f holder",
		"",
		`docker run -d --name holder --restart unless-stopped \`,
		`  --read-only \`,
		`  --cap-drop ALL \`,
		`  --security-opt no-new-privileges \`,
		`  --pids-limit 16 \`,
		`  --memory 32m \`,
		"  holder:latest",
		"",
		`docker run -d --name mockingbird --restart unless-stopped \`,
		`  --cap-add NET_RAW \`,
		`  --security-opt no-new-privileges \`,
		`  -v mockingbird-state:/var/lib/mockingbird -v mockingbird-log:/var/log/opencanary:ro \`,
		`  --network container:holder \`,
		`  -e MOCKINGBIRD_BIRDCAGE_URL=https://canary.example.com:8444 \`,
		`  -e MOCKINGBIRD_CA_PIN=sha256/abc123 \`,
		"  mockingbird:latest",
		"",
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
	)
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
	want := golden(
		"docker pull mockingbird:latest",
		"docker pull holder:latest",
		"docker pull opencanary:latest",
		"",
		"docker rm -f opencanary",
		"docker rm -f mockingbird",
		"docker rm -f holder",
		"",
		`docker run -d --name holder --restart unless-stopped \`,
		`  --read-only \`,
		`  --cap-drop ALL \`,
		`  --security-opt no-new-privileges \`,
		`  --pids-limit 16 \`,
		`  --memory 32m \`,
		"  holder:latest",
		"",
		`docker run -d --name mockingbird --restart unless-stopped \`,
		`  --cap-add NET_RAW \`,
		`  --security-opt no-new-privileges \`,
		`  -v mockingbird-state:/var/lib/mockingbird -v mockingbird-log:/var/log/opencanary:ro \`,
		`  --network container:holder \`,
		`  -e MOCKINGBIRD_BIRDCAGE_URL=https://canary.example.com:8444 \`,
		`  -e MOCKINGBIRD_CA_PIN=sha256/abc123 \`,
		"  mockingbird:latest",
		"",
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
	)
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
		AdvertiseHost: "canary.example.com",
		EnrolPort:     "8444",
		Pin:           "sha256/abc123",
		AgentImage:    "nightjar:latest",
	}
	var out strings.Builder
	if err := Upgrade(&out, in); err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	want := golden(
		"docker pull nightjar:latest",
		"",
		"docker rm -f nightjar",
		"",
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
