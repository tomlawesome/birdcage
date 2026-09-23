package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/tomlawesome/birdcage/internal/term"
)

// The SMB lure's own enrolment inputs (issue #87 decisions 7 and 10).
//
// The lure is a second container beside the canary, not a part of
// Mockingbird (ADR-0008), so what `birdcage canary enrol` does with these
// is decide what it prints: the volume to create, the two lines that let
// the canary read the lure's audit file, and the lure's own run command.
// Nothing here is sent to the server or stored -- see this file's comment
// on lureState for what that does and does not deliver.
const (
	// smbAuditVolume is the volume the lure writes its audit file to and
	// the canary mounts read-only. Named, not anonymous, because the
	// operator has to create it themselves with tmpfs options before
	// either container starts: a container that reaches an uncreated
	// named volume first gets a plain on-disk one, silently losing the
	// size cap that makes filling it a crash of the lure rather than of
	// the host (#87 decision 6).
	smbAuditVolume = "smb-audit"

	// smbAuditPath is where the audit file appears inside both
	// containers. Fixed: the lure's own default, and the value the
	// canary's MOCKINGBIRD_SMB_AUDIT_PATH is set to.
	smbAuditPath = "/audit/smb.log"

	// smbAuditSize caps the audit volume. Small on purpose -- it holds
	// one text log that the canary reads continuously.
	smbAuditSize = "16m"

	// envSMBLureImage overrides the lure image name this command prints,
	// the same way MOCKINGBIRD_IMAGE overrides the agent's.
	envSMBLureImage = "SMB_LURE_IMAGE"

	// defaultSMBLureImage is what it prints otherwise. Like the agent's
	// image, birdcage does not publish this anywhere yet, so an operator
	// builds and tags it by hand.
	defaultSMBLureImage = "smb-lure:latest"
)

// Defaults for the lure's identity, matching build/smb-lure/entrypoint.sh
// exactly. The NetBIOS name and server string are deliberately not
// settable here: the lure joins the canary's network namespace, which
// shares its hostname, so it already names itself after the canary
// (#87 decision 7) and a flag would only be a way to get that wrong.
const (
	defaultSMBWorkgroup = "WORKGROUP"
	defaultSMBShares    = "public,backup,scans"
)

// The character sets build/smb-lure/entrypoint.sh checks its own
// environment against. Checked here too, at the point the operator can
// still fix a typo, rather than leaving them to find out from a container
// that refused to start.
var (
	smbWorkgroupPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)
	smbSharePattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
)

// smbShareCount is how many share names the lure serves: three fixed
// directories baked into the image, whose names an operator may change
// but whose number they may not.
const smbShareCount = 3

// lureState is which lures this enrolment is deploying.
//
// It decides what this command prints and nothing else. Recording that an
// operator *declined* a lure -- so the canary page's ledger could say
// "off" rather than "untested" (#87 decision 10) -- would need a
// per-canary field, and there is no per-canary configuration anywhere in
// the schema today: `canaries` carries id, name, lane, ports and
// heartbeat interval, and `enrolment_sessions` carries name, lane and
// kind. Declining still reads correctly on the ledger, because a service
// with no listening port and no self-test target is already shown as
// untested (frontend/src/lib/canary/model.ts, selfTestCards); what is
// missing is only the distinction between "nobody has tested this" and
// "the operator said no".
type lureState struct {
	// smb is whether to deploy the SMB lure. Default true: the lure is
	// part of what a canary is unless an operator says otherwise.
	smb bool
}

// smbSettings is the lure's identity as the operator asked for it.
type smbSettings struct {
	workgroup string
	shares    []string
}

// lureFlag parses repeated `--lure name=state` flags. A flag.Value so
// `--lure smb=off` reads the way every other flag in this command does,
// and so an unknown lure name or state is refused by name rather than
// ignored -- an operator who mistypes the one flag that turns a lure off
// must not get a canary with the lure still on and no warning.
type lureFlag struct {
	state *lureState
	set   bool
}

func (f *lureFlag) String() string {
	if f == nil || f.state == nil || f.state.smb {
		return "smb=on"
	}
	return "smb=off"
}

func (f *lureFlag) Set(value string) error {
	for _, pair := range strings.Split(value, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, state, ok := strings.Cut(pair, "=")
		if !ok {
			return fmt.Errorf("--lure wants name=state, got %q (the only lure is smb, and its states are on and off)", pair)
		}
		if name != "smb" {
			return fmt.Errorf("--lure: unknown lure %q (the only lure is smb)", name)
		}
		switch state {
		case "on":
			f.state.smb = true
		case "off":
			f.state.smb = false
		default:
			return fmt.Errorf("--lure smb: unknown state %q (on or off)", state)
		}
		f.set = true
	}
	return nil
}

// parseSMBSettings validates the two lure-identity flags. It refuses
// rather than silently correcting: a canary that came up under a
// different workgroup from the one the operator asked for is worse than
// one that did not come up.
func parseSMBSettings(workgroup, shares string) (smbSettings, error) {
	if !smbWorkgroupPattern.MatchString(workgroup) {
		return smbSettings{}, fmt.Errorf("--smb-workgroup %q is not usable: %s", workgroup, smbWorkgroupPattern)
	}
	names := strings.Split(shares, ",")
	if len(names) != smbShareCount {
		return smbSettings{}, fmt.Errorf("--smb-shares wants exactly %d names, comma-separated, got %d in %q",
			smbShareCount, len(names), shares)
	}
	seen := map[string]bool{}
	for i, name := range names {
		names[i] = strings.TrimSpace(name)
		if !smbSharePattern.MatchString(names[i]) {
			return smbSettings{}, fmt.Errorf("--smb-shares: %q is not a usable share name: %s", names[i], smbSharePattern)
		}
		if seen[strings.ToLower(names[i])] {
			return smbSettings{}, fmt.Errorf("--smb-shares: %q appears twice; SMB share names are case-insensitive", names[i])
		}
		seen[strings.ToLower(names[i])] = true
	}
	return smbSettings{workgroup: workgroup, shares: names}, nil
}

// smbLureImage is the image name to print.
func smbLureImage() string {
	if image := os.Getenv(envSMBLureImage); image != "" {
		return image
	}
	return defaultSMBLureImage
}

// printSMBLureRunCommand writes the two commands an operator runs to put
// the lure beside the canary: the audit volume, then the container.
//
// Every line of this output also appears verbatim in docs/enrolment.md
// and build/smb-lure/README.md, and TestSMBLureRunCommandMatchesTheDocs
// is what keeps the three from drifting -- this command is the product's
// one install instruction, and a hardening flag silently dropped from a
// copy of it is a lure running without it.
//
// The settings are operator-supplied, so they are escaped at the point
// they reach the terminal, matching this file's rule for every other
// caller-supplied value -- even though parseSMBSettings has already
// refused anything outside a narrow character set.
func printSMBLureRunCommand(w io.Writer, image string, settings smbSettings) error {
	if len(settings.shares) != smbShareCount {
		return errors.New("printSMBLureRunCommand: settings were not validated by parseSMBSettings")
	}
	lines := []string{
		"docker volume create --driver local \\",
		fmt.Sprintf("  --opt type=tmpfs --opt device=tmpfs --opt o=size=%s,mode=0755 \\", smbAuditSize),
		fmt.Sprintf("  %s", smbAuditVolume),
		"",
		"docker run -d --name smb-lure --restart unless-stopped \\",
		"  --network container:mockingbird \\",
		"  --read-only \\",
		"  --cap-drop ALL \\",
		"  --cap-add SETUID --cap-add SETGID --cap-add NET_BIND_SERVICE \\",
		"  --security-opt no-new-privileges \\",
		"  --pids-limit 128 \\",
		"  --memory 192m \\",
		"  --ulimit core=0 \\",
		"  --tmpfs /run:size=8m \\",
		"  --tmpfs /var/lib/samba:size=8m \\",
		"  --tmpfs /var/cache/samba:size=8m \\",
		"  --tmpfs /var/log:size=8m \\",
		fmt.Sprintf("  -v %s:/audit \\", smbAuditVolume),
		fmt.Sprintf("  -e SMB_WORKGROUP=%s \\", term.Escape(settings.workgroup)),
		fmt.Sprintf("  -e SMB_SHARE_PUBLIC=%s \\", term.Escape(settings.shares[0])),
		fmt.Sprintf("  -e SMB_SHARE_BACKUP=%s \\", term.Escape(settings.shares[1])),
		fmt.Sprintf("  -e SMB_SHARE_SCANS=%s \\", term.Escape(settings.shares[2])),
		fmt.Sprintf("  %s", term.Escape(image)),
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
