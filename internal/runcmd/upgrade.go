package runcmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/term"
)

// UpgradeInput is everything Upgrade needs to build one canary's
// upgrade command (issue #54): the copy-and-paste script the canary
// page shows when that canary's agent is running an older build than
// birdcage itself. A plain `docker restart` would keep the old image
// running, so this pulls every current image first, removes every
// container (dependants before the holder that owns their shared
// network namespace), then re-runs each one in the same order enrolment
// printed them in -- never with a deploy token, see
// MockingbirdConfig.Token's own doc comment for why one is pointless
// here.
type UpgradeInput struct {
	Kind agentkind.Kind

	// AdvertiseHost, EnrolPort and Pin are birdcage's own current
	// runtime facts -- the same three values every current enrolment
	// uses, not something read back per canary.
	AdvertiseHost string
	EnrolPort     string
	Pin           string

	// AgentImage is Mockingbird's image reference for a honeypot,
	// Nightjar's for a scanner -- the caller resolves it from
	// agentkind.Lookup(Kind).Profile's own ImageEnv/DefaultImage, the
	// same resolution `birdcage agent enrol` already uses.
	AgentImage string

	// HolderImage, OpenCanaryImage and SMBLureImage are the caller's own
	// HolderImage()/OpenCanaryImage()/SMBLureImage() reads (below).
	// Honeypot only; a caller building a scanner's input may leave them
	// unset.
	HolderImage     string
	OpenCanaryImage string
	SMBLureImage    string

	// BaitNames and SegmentProfile are this canary's current
	// canary_settings values (store.ListCanarySettings) -- honeypot
	// only, empty when neither was ever set, matching
	// MockingbirdConfig's own fields.
	BaitNames      string
	SegmentProfile string

	// SMBLure, SMBWorkgroup and SMBShares are
	// store.CanaryUpgradeFacts' own fields. SMBLure nil means unknown --
	// this canary predates issue #54, which is the first thing that ever
	// recorded it -- and Upgrade must never guess which way (owner,
	// 2026-09-27: "treat lure as unknown ... never guess silently"): it
	// prints the lure's own commands commented, with a note to check
	// the host, rather than either running them or silently leaving
	// them out. SMBWorkgroup and SMBShares (exactly SMBShareCount
	// entries) are set only when SMBLure is non-nil and true.
	SMBLure      *bool
	SMBWorkgroup string
	SMBShares    []string
}

// Placeholders for a legacy canary's never-recorded SMB workgroup and
// share names -- SMBLure == nil means the operator's original
// --smb-workgroup/--smb-shares values (if any) were never stored at
// all (issue #54 is what started storing them), so there is nothing
// truer to print here than a marker the operator has to replace by
// hand after checking the host. Letters, digits and hyphens only,
// matching the character set parseSMBSettings itself accepts, even
// though nothing here validates them -- these never reach a live
// container uncommented.
const unknownSMBWorkgroupPlaceholder = "WORKGROUP-UNKNOWN-CHECK-HOST"

var unknownSMBSharePlaceholders = []string{
	"SHARE1-UNKNOWN-CHECK-HOST",
	"SHARE2-UNKNOWN-CHECK-HOST",
	"SHARE3-UNKNOWN-CHECK-HOST",
}

// Upgrade writes the full upgrade script for one canary. Returns an
// error naming the kind for anything Upgrade has no script for, the
// same "fail loudly, never invent" stance
// cmd/birdcage/canary.go's own runCanaryEnrol switch takes on an
// unregistered kind.
func Upgrade(w io.Writer, in UpgradeInput) error {
	switch in.Kind {
	case agentkind.Honeypot:
		return upgradeHoneypot(w, in)
	case agentkind.Scanner:
		return upgradeScanner(w, in)
	default:
		return fmt.Errorf("runcmd: Upgrade: no upgrade script registered for kind %q", in.Kind)
	}
}

func blank(w io.Writer) error {
	_, err := fmt.Fprintln(w)
	return err
}

// upgradeScanner builds a scanner's upgrade script: Nightjar is a
// single standalone container (no shared network namespace, no
// dependants), so this is the simplest of the two -- pull, remove,
// re-run, no token.
func upgradeScanner(w io.Writer, in UpgradeInput) error {
	if err := writeLines(w, []string{fmt.Sprintf("docker pull %s", term.Escape(in.AgentImage))}); err != nil {
		return err
	}
	if err := blank(w); err != nil {
		return err
	}
	if err := writeLines(w, []string{fmt.Sprintf("docker rm -f %s", NightjarContainerName)}); err != nil {
		return err
	}
	if err := blank(w); err != nil {
		return err
	}
	return WriteNightjarRun(w, NightjarConfig{
		AdvertiseHost: in.AdvertiseHost,
		EnrolPort:     in.EnrolPort,
		Pin:           in.Pin,
		Token:         "",
		Image:         in.AgentImage,
	})
}

// upgradeHoneypot builds a honeypot's upgrade script: up to four
// containers sharing the holder's network namespace, so every image is
// pulled before any container is removed, and every removal has to land
// before the holder's own -- a dependant removed after its own
// namespace is gone fails outright, which is why "dependants before
// holder" is not just tidiness.
func upgradeHoneypot(w io.Writer, in UpgradeInput) error {
	lureOn := in.SMBLure != nil && *in.SMBLure
	lureOff := in.SMBLure != nil && !*in.SMBLure

	pulls := []string{
		fmt.Sprintf("docker pull %s", term.Escape(in.AgentImage)),
		fmt.Sprintf("docker pull %s", term.Escape(in.HolderImage)),
		fmt.Sprintf("docker pull %s", term.Escape(in.OpenCanaryImage)),
	}
	if lureOn {
		pulls = append(pulls, fmt.Sprintf("docker pull %s", term.Escape(in.SMBLureImage)))
	}
	if err := writeLines(w, pulls); err != nil {
		return err
	}
	if err := blank(w); err != nil {
		return err
	}

	// Dependants before the holder -- the reverse of the enrolment
	// order below, since each one joined the holder's namespace only
	// once the holder already existed.
	var rms []string
	if lureOn {
		rms = append(rms, fmt.Sprintf("docker rm -f %s", SMBLureContainerName))
	}
	rms = append(rms,
		fmt.Sprintf("docker rm -f %s", OpenCanaryContainerName),
		fmt.Sprintf("docker rm -f %s", MockingbirdContainerName),
		fmt.Sprintf("docker rm -f %s", HolderContainerName),
	)
	if err := writeLines(w, rms); err != nil {
		return err
	}
	if err := blank(w); err != nil {
		return err
	}

	// Re-run in enrolment order: holder, Mockingbird, OpenCanary, the
	// lure -- runCanaryEnrol's own comment on that order still applies
	// (Mockingbird's receiver must be listening before OpenCanary's
	// first webhook attempt, and the lure joins the holder only once it
	// exists).
	if err := WriteHolderRun(w, HolderConfig{Image: in.HolderImage, SMBLure: lureOn}); err != nil {
		return err
	}
	if err := blank(w); err != nil {
		return err
	}

	if err := WriteMockingbirdRun(w, MockingbirdConfig{
		AdvertiseHost:  in.AdvertiseHost,
		EnrolPort:      in.EnrolPort,
		Pin:            in.Pin,
		Token:          "",
		Image:          in.AgentImage,
		SMBLure:        lureOn,
		BaitNames:      in.BaitNames,
		SegmentProfile: in.SegmentProfile,
	}); err != nil {
		return err
	}
	if err := blank(w); err != nil {
		return err
	}

	if err := WriteOpenCanaryRun(w, OpenCanaryConfig{Image: in.OpenCanaryImage}); err != nil {
		return err
	}

	if err := blank(w); err != nil {
		return err
	}
	switch {
	case lureOn:
		return WriteSMBLureRun(w, SMBLureConfig{Image: in.SMBLureImage, Workgroup: in.SMBWorkgroup, Shares: in.SMBShares})
	case lureOff:
		// Matching cmd/birdcage/canary.go's own enrolment-time line for
		// the same decision ("smb lure off by request"): one line, no
		// commands, so there is nothing here for an operator to
		// mistakenly run.
		_, err := fmt.Fprintln(w, "# smb lure off for this canary: no smb-lure container to pull, remove or re-run")
		return err
	default:
		return writeUnknownSMBLureBlock(w, in)
	}
}

// writeUnknownSMBLureBlock is upgradeHoneypot's SMBLure == nil case: a
// canary enrolled before issue #54 ever recorded whether it had the SMB
// lure at all. Printing nothing would silently drop a lure that is
// still running; printing a live command would silently create one
// that never existed. Neither is a guess this function gets to make, so
// it prints the commands commented out, with a note to check the host
// first, and placeholders (unknownSMBWorkgroupPlaceholder/
// unknownSMBSharePlaceholders) standing in for a workgroup and share
// names that were never recorded either -- an operator who confirms the
// lure exists still has to fill those in by hand or read them off the
// running container.
func writeUnknownSMBLureBlock(w io.Writer, in UpgradeInput) error {
	note := []string{
		"# SMB lure: unknown for this canary -- it was enrolled before birdcage started",
		"# recording this (issue #54). Check the canary host for a running smb-lure",
		"# container (docker ps -a --filter name=smb-lure) before relying on anything",
		"# below. Its workgroup and share names were never recorded either, so the",
		"# commented command below uses placeholders -- replace them with what the",
		"# host is actually running, or leave the lure off if `docker ps -a` finds none.",
	}
	if err := writeLines(w, note); err != nil {
		return err
	}

	var body strings.Builder
	if err := WriteSMBLureRun(&body, SMBLureConfig{
		Image:     in.SMBLureImage,
		Workgroup: unknownSMBWorkgroupPlaceholder,
		Shares:    unknownSMBSharePlaceholders,
	}); err != nil {
		return err
	}

	commented := []string{
		"# " + fmt.Sprintf("docker pull %s", term.Escape(in.SMBLureImage)),
		"# " + fmt.Sprintf("docker rm -f %s", SMBLureContainerName),
	}
	for _, line := range strings.Split(strings.TrimRight(body.String(), "\n"), "\n") {
		commented = append(commented, "# "+line)
	}
	return writeLines(w, commented)
}
