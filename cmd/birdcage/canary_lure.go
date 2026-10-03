package main

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/tomlawesome/birdcage/internal/runcmd"
)

// The SMB lure's own enrolment inputs (issue #87 decisions 7 and 10).
//
// The lure is a second container beside the canary, not a part of
// Mockingbird (ADR-0008), so what `birdcage canary enrol` does with these
// is decide what it prints: the volume to create, the two lines that let
// the canary read the lure's audit file, and the lure's own run command.
// Nothing here is sent to the server or stored -- see this file's comment
// on lureState for what that does and does not deliver.
// The volume name, in-container path, image env/default and container
// name below all now live in internal/runcmd (issue #54, so the upgrade
// command can build the identical lines) -- these are the same values
// under their original names, kept here so nothing else in this file or
// its tests has to change.
const (
	smbAuditVolume       = runcmd.SMBAuditVolume
	smbAuditPath         = runcmd.SMBAuditPath
	smbAuditSize         = runcmd.SMBAuditSize
	envSMBLureImage      = runcmd.EnvSMBLureImage
	defaultSMBLureImage  = runcmd.DefaultSMBLureImage
	smbLureContainerName = runcmd.SMBLureContainerName
)

// The address holder's own enrolment inputs (issue #126).
//
// The canary's own network namespace used to be what the SMB lure
// joined (`--network container:mockingbird`), which meant restarting the
// canary destroyed the namespace the lure was listening in -- the lure
// stayed `running` with nothing answering on 445, and only restarting it
// too brought the share back. The owner's fix: a third, do-nothing
// container (cmd/holder) owns the network address instead, and both the
// canary and the lure join *it* with `--network container:holder`.
// Restarting either one now leaves the shared namespace alone, because
// neither of them owns it -- and anything added later joins the same
// way.
//
// Issue #132 made it unconditional: OpenCanary now always joins it too
// (printOpenCanaryRunCommand below), so there is always something else
// for it to protect, whether or not the SMB lure is also deployed.
// Before #132 it was printed only when the lure was being deployed,
// since a lure-less canary otherwise had nothing else ever joining its
// own namespace.
const (
	holderContainerName = runcmd.HolderContainerName
	envHolderImage      = runcmd.EnvHolderImage
	defaultHolderImage  = runcmd.DefaultHolderImage
)

// OpenCanary's own enrolment inputs (issue #132).
//
// OpenCanary used to run inside the same container as the agent, as its
// child process (#69); the owner's decision on #132 (recorded in the
// ADR-0008 amendment, docs/adr/0013-opencanary-own-container.md) split
// it into its own image and container, with no access whatsoever to the
// agent's own state volume. It joins the address holder exactly the way
// the agent and the SMB lure do, and always -- there is no flag to turn
// it off, because a honeypot canary with no honeypot is not a honeypot.
const (
	openCanaryContainerName = runcmd.OpenCanaryContainerName
	envOpenCanaryImage      = runcmd.EnvOpenCanaryImage
	defaultOpenCanaryImage  = runcmd.DefaultOpenCanaryImage
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
const smbShareCount = runcmd.SMBShareCount

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
func smbLureImage() string { return runcmd.SMBLureImage() }

// holderImage is the image name to print for the address holder.
func holderImage() string { return runcmd.HolderImage() }

// printHolderRunCommand writes the commands an operator runs before the
// canary, OpenCanary or the lure: the audit volume (only when the lure is
// being deployed), then the holder container that owns the network
// address every one of them joins.
//
// The volume is created here, not by printSMBLureRunCommand, because the
// holder mounts it too (issue #126: a tmpfs volume's backing memory is
// freed the moment nothing has it mounted, so the holder has to reach it
// before either of the containers that might restart do) and because it
// has to exist before the first container that touches it starts, same
// reasoning smbAuditVolume's own doc comment gives.
//
// smbLure gates only the audit volume and its mount, not the holder
// itself (issue #132 made the holder unconditional: OpenCanary always
// joins it, whether or not the lure does). Printing an unused tmpfs
// volume and mount on every lure-less canary would be exactly the kind
// of drift docs/enrolment.md's own "smb lure off by request" line exists
// to avoid.
//
// Every line of this output also appears verbatim in docs/enrolment.md
// and build/smb-lure/README.md, and TestSMBLureRunCommandMatchesTheDocs
// is what keeps the copies from drifting.
//
// The actual line-building now lives in internal/runcmd.WriteHolderRun
// (issue #54), so `birdcage agent enrol` and the canary page's upgrade
// command build it identically; this stays as the thin wrapper the
// existing tests in this package call directly.
func printHolderRunCommand(w io.Writer, image string, smbLure bool) error {
	return runcmd.WriteHolderRun(w, runcmd.HolderConfig{Image: image, SMBLure: smbLure})
}

// openCanaryImage is the image name to print for OpenCanary.
func openCanaryImage() string { return runcmd.OpenCanaryImage() }

// printOpenCanaryRunCommand writes the `docker run` command for
// OpenCanary's own container (issue #132): joined to the holder's
// network namespace exactly like the agent, hardened like the SMB lure
// (build/opencanary/README.md has the per-flag evidence), and mounting
// only the log volume the agent also mounts -- read-write here, since
// this is the writer -- and never the agent's own state volume.
//
// --sysctl, not --cap-add: OpenCanary binds several ports under 1024
// (21, 22, 23, 80 among them) as the same non-root user distroless
// ships, and a namespace-wide floor is what lets it, not a capability --
// see build/opencanary/Dockerfile's own comment. It can only be set once
// per network namespace, and this is the container that needs it; the
// agent's own command (printEnrolRunCommand) carries none.
//
// --tmpfs /var/tmp: OpenCanary's SSH module generates its host key pair
// there on every start (ssh.py's hard-coded SSH_PATH) and --read-only
// alone made that a hard failure, reproduced directly against this image
// (2026-09-26): "OSError: [Errno 30] Read-only file system:
// '/var/tmp/id_rsa.pub'", the whole application failing to load with it
// -- not a dropped event, every module refusing to start. The key never
// needs to survive a restart (a fresh one each start is exactly as
// convincing a target), so a small tmpfs is the fix, the same "every
// path that needs writing gets its own tmpfs" shape the SMB lure's own
// four --tmpfs flags already use.
//
// Every line of this output also appears verbatim in docs/enrolment.md
// and build/opencanary/README.md, and TestOpenCanaryRunCommandMatchesTheDocs
// is what keeps the copies from drifting -- the same discipline
// printHolderRunCommand and printSMBLureRunCommand already have, for the
// same reason: a hardening flag silently dropped from one copy is
// OpenCanary running without it.
//
// Moved to internal/runcmd.WriteOpenCanaryRun (issue #54); this stays as
// the thin wrapper this package's tests call directly.
func printOpenCanaryRunCommand(w io.Writer, image string) error {
	return runcmd.WriteOpenCanaryRun(w, runcmd.OpenCanaryConfig{Image: image})
}

// printSMBLureRunCommand writes the `docker run` command an operator
// runs to put the lure beside the canary, after both the holder
// (printHolderRunCommand) and the canary itself already exist: the lure
// joins the holder's network namespace, not the canary's own (issue
// #126, amending #87 decision 3's wording -- the lure joins the holder,
// not the canary), so a restart of either the canary or the lure leaves
// that namespace alone.
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
//
// Moved to internal/runcmd.WriteSMBLureRun (issue #54); this stays as
// the thin wrapper this package's tests call directly.
func printSMBLureRunCommand(w io.Writer, image string, settings smbSettings) error {
	return runcmd.WriteSMBLureRun(w, runcmd.SMBLureConfig{Image: image, Workgroup: settings.workgroup, Shares: settings.shares})
}
