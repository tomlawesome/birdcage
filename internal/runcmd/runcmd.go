// Package runcmd builds the `docker run`/`docker volume create` lines
// this product ever prints for an operator to paste onto a canary host:
// once at enrolment (`birdcage agent enrol`, cmd/birdcage/canary.go and
// canary_lure.go), and again as the copy-and-paste upgrade command the
// canary page shows when its agent trails birdcage (issue #54,
// upgrade.go in this package). Both callers build from the exact same
// functions, so the enrolment command and the upgrade command can never
// silently drift apart on a flag.
//
// Every function here writes a fixed set of hardening flags plus the
// caller's own values; every operator- or environment-supplied value is
// escaped with term.Escape at the point it reaches the returned lines,
// matching cmd/birdcage's own rule for every value it prints to a
// terminal -- even a value already narrowed by a validator upstream,
// because a rule with an exception is a rule somebody forgets.
package runcmd

import (
	"fmt"
	"io"
	"os"

	"github.com/tomlawesome/birdcage/internal/hostmask"
	"github.com/tomlawesome/birdcage/internal/term"
)

// Container names, fixed across both enrolment and upgrade output.
const (
	HolderContainerName      = "holder"
	MockingbirdContainerName = "mockingbird"
	OpenCanaryContainerName  = "opencanary"
	SMBLureContainerName     = "smb-lure"
	NightjarContainerName    = "nightjar"
)

// The SMB lure's own fixed identity (issue #87), moved from
// cmd/birdcage/canary_lure.go unchanged.
const (
	// SMBAuditVolume is the volume the lure writes its audit file to and
	// the canary mounts read-only. Named, not anonymous, because the
	// operator (or the upgrade script) has to create it with tmpfs
	// options before either container reaches it: a container that
	// reaches an uncreated named volume first gets a plain on-disk one,
	// silently losing the size cap that makes filling it a crash of the
	// lure rather than of the host (#87 decision 6).
	SMBAuditVolume = "smb-audit"

	// SMBAuditPath is where the audit file appears inside both
	// containers. Fixed: the lure's own default, and the value the
	// canary's MOCKINGBIRD_SMB_AUDIT_PATH is set to.
	SMBAuditPath = "/audit/smb.log"

	// SMBAuditSize caps the audit volume. Small on purpose -- it holds
	// one text log that the canary reads continuously.
	SMBAuditSize = "16m"

	// SMBShareCount is how many share names the lure serves: three fixed
	// directories baked into the image, whose names an operator may
	// change but whose number they may not.
	SMBShareCount = 3
)

// Image environment variables and defaults for the three containers
// that have no agentkind.Profile of their own (the holder, OpenCanary and
// the SMB lure are never enrolled as an agent kind in their own right --
// they ride along with the honeypot). Mockingbird's and Nightjar's own
// image env/default live in agentkind.Profile (MOCKINGBIRD_IMAGE,
// NIGHTJAR_IMAGE) and are read the same way by both this package's
// callers and internal/agentkind's own consumers.
const (
	EnvHolderImage     = "HOLDER_IMAGE"
	DefaultHolderImage = "holder:latest"

	EnvOpenCanaryImage     = "OPENCANARY_IMAGE"
	DefaultOpenCanaryImage = "opencanary:latest"

	EnvSMBLureImage     = "SMB_LURE_IMAGE"
	DefaultSMBLureImage = "smb-lure:latest"
)

// HolderImage, OpenCanaryImage and SMBLureImage read this process' own
// environment for an override, falling back to the fixed default --
// the same os.Getenv-or-default shape cmd/birdcage's own holderImage/
// openCanaryImage/smbLureImage used before this package existed, and
// the one agentkind.Profile.ImageEnv/DefaultImage already gives
// Mockingbird and Nightjar.
func HolderImage() string { return envOrDefault(EnvHolderImage, DefaultHolderImage) }

func OpenCanaryImage() string { return envOrDefault(EnvOpenCanaryImage, DefaultOpenCanaryImage) }

func SMBLureImage() string { return envOrDefault(EnvSMBLureImage, DefaultSMBLureImage) }

func envOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// HolderConfig is WriteHolderRun's input.
type HolderConfig struct {
	// Image is the holder's own image reference (HolderImage(), or an
	// operator override read the same way).
	Image string
	// SMBLure is whether the SMB lure is part of this canary -- gates
	// only the audit volume and its mount on the holder, not the holder
	// itself, which issue #132 made unconditional (see WriteHolderRun's
	// own doc comment).
	SMBLure bool
}

// WriteHolderRun writes the commands that create the address holder
// (issue #126) -- moved out of cmd/birdcage/canary_lure.go's own
// printHolderRunCommand, byte-for-byte, so `birdcage agent enrol` and
// the upgrade command (Upgrade, below) build it identically.
//
// It also creates the SMB audit volume when cfg.SMBLure is set, before
// the holder container that mounts it, for the reason
// cmd/birdcage/canary_lure.go's own comment on this ordering gives: a
// tmpfs volume's backing memory is freed the moment nothing has it
// mounted, so whichever container reaches it first has to find it
// already there. Re-running `docker volume create` for a volume that
// already exists with the same options is a deliberate no-op, not an
// error -- Docker's own documented stance -- which is what makes this
// safe to run again on an upgrade rather than only once at enrolment.
//
// Every line of this output also appears verbatim in docs/enrolment.md
// and build/smb-lure/README.md, and TestSMBLureRunCommandMatchesTheDocs
// (cmd/birdcage/canary_lure_test.go) is what keeps the copies from
// drifting.
func WriteHolderRun(w io.Writer, cfg HolderConfig) error {
	var lines []string
	if cfg.SMBLure {
		lines = append(lines,
			"docker volume create --driver local \\",
			fmt.Sprintf("  --opt type=tmpfs --opt device=tmpfs --opt o=size=%s,mode=0755 \\", SMBAuditSize),
			fmt.Sprintf("  %s", SMBAuditVolume),
			"",
		)
	}
	lines = append(lines,
		fmt.Sprintf("docker run -d --name %s --restart unless-stopped \\", HolderContainerName),
		"  --read-only \\",
		"  --cap-drop ALL \\",
		"  --security-opt no-new-privileges \\",
		"  --pids-limit 16 \\",
		"  --memory 32m \\",
	)
	if cfg.SMBLure {
		lines = append(lines, fmt.Sprintf("  -v %s:/audit:ro \\", SMBAuditVolume))
	}
	lines = append(lines, fmt.Sprintf("  %s", term.Escape(cfg.Image)))
	return writeLines(w, lines)
}

// OpenCanaryConfig is WriteOpenCanaryRun's input.
type OpenCanaryConfig struct {
	// Image is OpenCanary's own image reference.
	Image string
}

// WriteOpenCanaryRun writes the `docker run` command for OpenCanary's
// own container (issue #132) -- moved out of
// cmd/birdcage/canary_lure.go's own printOpenCanaryRunCommand,
// byte-for-byte. See that function's original doc comment (still there,
// on cmd/birdcage's now-thin wrapper) for why each flag is there.
//
// Every line of this output also appears verbatim in docs/enrolment.md
// and build/opencanary/README.md, and
// TestOpenCanaryRunCommandMatchesTheDocs is what keeps the copies from
// drifting.
func WriteOpenCanaryRun(w io.Writer, cfg OpenCanaryConfig) error {
	lines := []string{
		fmt.Sprintf("docker run -d --name %s --restart unless-stopped --init \\", OpenCanaryContainerName),
		fmt.Sprintf("  --network container:%s \\", HolderContainerName),
		"  --sysctl net.ipv4.ip_unprivileged_port_start=0 \\",
		"  --read-only \\",
		"  --cap-drop ALL \\",
		"  --security-opt no-new-privileges \\",
		"  --pids-limit 32 \\",
		"  --memory 128m \\",
		"  --tmpfs /var/tmp:size=8m \\",
		"  -v mockingbird-log:/var/log/opencanary \\",
		fmt.Sprintf("  %s", term.Escape(cfg.Image)),
	}
	return writeLines(w, lines)
}

// SMBLureConfig is WriteSMBLureRun's input. Shares must have exactly
// SMBShareCount entries, in the fixed order public, backup, scans --
// callers get this from parseSMBSettings (cmd/birdcage/canary_lure.go)
// at enrolment or from store.CanaryUpgradeFacts.SMBShares (split on
// comma) at upgrade time.
type SMBLureConfig struct {
	Image     string
	Workgroup string
	Shares    []string
}

// WriteSMBLureRun writes the `docker run` command for the SMB lure's own
// container (issue #87) -- moved out of cmd/birdcage/canary_lure.go's
// own printSMBLureRunCommand, byte-for-byte. cfg.Workgroup and
// cfg.Shares are operator-supplied, so they are escaped here, at the
// point they reach the returned lines, matching this package's own rule
// for every caller-supplied value -- even though both enrolment's own
// parseSMBSettings and, for an upgrade, the values this canary was
// enrolled with have already been validated against a narrow character
// set.
//
// Every line of this output also appears verbatim in docs/enrolment.md
// and build/smb-lure/README.md, and TestSMBLureRunCommandMatchesTheDocs
// is what keeps the three from drifting.
func WriteSMBLureRun(w io.Writer, cfg SMBLureConfig) error {
	if len(cfg.Shares) != SMBShareCount {
		return fmt.Errorf("runcmd: WriteSMBLureRun: got %d shares, want %d", len(cfg.Shares), SMBShareCount)
	}
	lines := []string{
		fmt.Sprintf("docker run -d --name %s --restart unless-stopped \\", SMBLureContainerName),
		fmt.Sprintf("  --network container:%s \\", HolderContainerName),
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
		fmt.Sprintf("  -v %s:/audit \\", SMBAuditVolume),
		fmt.Sprintf("  -e SMB_WORKGROUP=%s \\", term.Escape(cfg.Workgroup)),
		fmt.Sprintf("  -e SMB_SHARE_PUBLIC=%s \\", term.Escape(cfg.Shares[0])),
		fmt.Sprintf("  -e SMB_SHARE_BACKUP=%s \\", term.Escape(cfg.Shares[1])),
		fmt.Sprintf("  -e SMB_SHARE_SCANS=%s \\", term.Escape(cfg.Shares[2])),
		fmt.Sprintf("  %s", term.Escape(cfg.Image)),
	}
	return writeLines(w, lines)
}

// MockingbirdConfig is WriteMockingbirdRun's input.
type MockingbirdConfig struct {
	AdvertiseHost string
	EnrolPort     string
	Pin           string
	// Token is the one-time deploy token. Empty omits
	// MOCKINGBIRD_DEPLOY_TOKEN entirely, rather than printing it empty --
	// Upgrade (below) always passes "": the agent's own ensureEnrolled
	// (cmd/mockingbird/config.go) ignores that variable once
	// mockingbird-state already holds a credential, so a token minted
	// for an upgrade would be either ignored or, worse, mistaken for
	// this canary's new one, which it never was.
	Token          string
	Image          string
	SMBLure        bool
	BaitNames      string
	SegmentProfile string
}

// WriteMockingbirdRun writes the `docker run` line for Mockingbird's own
// container -- moved out of cmd/birdcage/canary.go's own
// printEnrolRunCommand, byte-for-byte except for cfg.Token's own
// omit-when-empty rule above (printEnrolRunCommand always had a token to
// print, so this is a widening, not a behaviour change, for every
// existing caller).
func WriteMockingbirdRun(w io.Writer, cfg MockingbirdConfig) error {
	lines := []string{
		fmt.Sprintf("docker run -d --name %s --restart unless-stopped \\", MockingbirdContainerName),
		"  --cap-add NET_RAW \\",
		"  --security-opt no-new-privileges \\",
		"  -v mockingbird-state:/var/lib/mockingbird -v mockingbird-log:/var/log/opencanary:ro \\",
		fmt.Sprintf("  --network container:%s \\", HolderContainerName),
	}
	if cfg.SMBLure {
		lines = append(lines,
			fmt.Sprintf("  -v %s:/audit:ro \\", SMBAuditVolume),
			fmt.Sprintf("  -e MOCKINGBIRD_SMB_AUDIT_PATH=%s \\", SMBAuditPath),
		)
	}
	lines = append(lines,
		fmt.Sprintf("  -e MOCKINGBIRD_BIRDCAGE_URL=https://%s:%s \\", term.Escape(cfg.AdvertiseHost), cfg.EnrolPort),
		fmt.Sprintf("  -e MOCKINGBIRD_CA_PIN=%s \\", cfg.Pin),
	)
	if cfg.Token != "" {
		lines = append(lines, fmt.Sprintf("  -e MOCKINGBIRD_DEPLOY_TOKEN=%s \\", cfg.Token))
	}
	if cfg.BaitNames != "" {
		lines = append(lines, fmt.Sprintf("  -e MOCKINGBIRD_POISONER_NAMES=%s \\", term.Escape(cfg.BaitNames)))
	}
	if cfg.SegmentProfile != "" {
		lines = append(lines, fmt.Sprintf("  -e MOCKINGBIRD_POISONER_PROFILE=%s \\", term.Escape(cfg.SegmentProfile)))
	}
	lines = append(lines, fmt.Sprintf("  %s", term.Escape(cfg.Image)))
	return writeLines(w, lines)
}

// NightjarConfig is WriteNightjarRun's input.
type NightjarConfig struct {
	AdvertiseHost string
	EnrolPort     string
	Pin           string
	// Token is the one-time deploy token; empty omits
	// NIGHTJAR_DEPLOY_TOKEN entirely -- see MockingbirdConfig.Token's own
	// doc comment; cmd/nightjar's ensureEnrolled draws the identical
	// distinction.
	Token string
	Image string
}

// WriteNightjarRun writes the `docker run` line for the scanner kind --
// moved out of cmd/birdcage/canary.go's own printScannerEnrolRunCommand,
// byte-for-byte except for cfg.Token's own omit-when-empty rule (see
// WriteMockingbirdRun's doc comment for the same widening).
func WriteNightjarRun(w io.Writer, cfg NightjarConfig) error {
	lines := []string{
		fmt.Sprintf("docker run -d --name %s --restart unless-stopped \\", NightjarContainerName),
		"  --read-only --cap-drop ALL --security-opt no-new-privileges \\",
		"  -v /:/host:ro \\",
	}
	for _, flag := range hostmask.RunFlags("/host") {
		lines = append(lines, fmt.Sprintf("  %s \\", flag))
	}
	lines = append(lines, "  -v nightjar-state:/var/lib/nightjar -v nightjar-grype-db:/var/lib/nightjar-grype-db \\")
	lines = append(lines,
		fmt.Sprintf("  -e NIGHTJAR_BIRDCAGE_URL=https://%s:%s \\", term.Escape(cfg.AdvertiseHost), cfg.EnrolPort),
		fmt.Sprintf("  -e NIGHTJAR_CA_PIN=%s \\", cfg.Pin),
	)
	if cfg.Token != "" {
		lines = append(lines, fmt.Sprintf("  -e NIGHTJAR_DEPLOY_TOKEN=%s \\", cfg.Token))
	}
	lines = append(lines, fmt.Sprintf("  %s", term.Escape(cfg.Image)))
	return writeLines(w, lines)
}

func writeLines(w io.Writer, lines []string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
