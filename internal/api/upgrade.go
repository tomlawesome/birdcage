package api

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/runcmd"
	"github.com/tomlawesome/birdcage/internal/store"
)

// UpgradeConfig is the answer to the questions `birdcage agent enrol`
// answers from its environment (issue #54): where a canary reaches this
// birdcage (AdvertiseHost, EnrolPort), which CA it pins (Pin), and which
// image each container runs. An agent's upgrade command is built from
// these plus the canary's own stored facts (UpgradeInputFor), so an
// upgrade re-runs exactly what a fresh enrolment from this server would
// print, minus the deploy token and plus a single-use upgrade token.
//
// cmd/birdcage fills it twice from the same variables: once at server
// startup, for the canary page's upgrade_available, and once in `agent
// upgrade-command`, which prints the command. The zero value means "this
// server cannot print one" -- ingest is off, or BIRDCAGE_ADVERTISE_HOST
// is unset, so there is no address a canary could be told to reach --
// and the page then says upgrade_available false, which the frontend
// answers with a pointer to docs/enrolment.md.
type UpgradeConfig struct {
	AdvertiseHost string
	EnrolPort     string
	Pin           string

	// AgentImages is each kind's own agent image (agentkind.Profile's
	// ImageEnv, else DefaultImage) -- Mockingbird for a honeypot,
	// Nightjar for a scanner.
	AgentImages map[agentkind.Kind]string

	// HolderImage, OpenCanaryImage and SMBLureImage are runcmd's own
	// HolderImage()/OpenCanaryImage()/SMBLureImage() reads.
	HolderImage     string
	OpenCanaryImage string
	SMBLureImage    string
}

// Usable reports whether c holds enough to print a working command: the
// three facts every agent's run line carries. Images always have a
// default, so they are never what is missing.
func (c UpgradeConfig) Usable() bool {
	return c.AdvertiseHost != "" && c.EnrolPort != "" && c.Pin != ""
}

// upgradeAvailable is the canary page's upgrade_available: c is
// agent_out_of_date and this server could print its upgrade command.
// Read from c.ActiveStates rather than c.Status: a worse state (silent,
// say) can hold Status while the agent is still behind underneath it,
// and the operator still needs the command then.
//
// The page carries no command itself (issue #54, ADR-0012's B4
// amendment): every command carries a freshly minted single-use token,
// and minting is a state change the dashboard API cannot make while it
// is read-only (owner, 2026-09-26, until #8's login). `birdcage agent
// upgrade-command <id>` on the birdcage host mints it and prints the
// command.
func (h *handler) upgradeAvailable(c store.Canary) bool {
	return slices.Contains(c.ActiveStates, string(store.StateAgentOutOfDate)) && h.upgrade.Usable()
}

// UpgradeInputFor reads everything runcmd.Upgrade needs about canaryID
// -- its kind and enrolment-time SMB lure identity
// (store.GetCanaryUpgradeFacts), a honeypot's bait names and segment
// profile (store.ListCanarySettings) -- and combines it with cfg, the
// server's own facts. The caller adds the upgrade token. Read-only, so
// it runs before the token is minted and a failure here burns nothing.
//
// Never carries a deploy token: runcmd.Upgrade always passes none (see
// runcmd.MockingbirdConfig.Token for why one would be pointless or
// worse).
func UpgradeInputFor(ctx context.Context, database *db.DB, cfg UpgradeConfig, canaryID string) (runcmd.UpgradeInput, error) {
	facts, err := store.GetCanaryUpgradeFacts(ctx, database, canaryID)
	if err != nil {
		return runcmd.UpgradeInput{}, fmt.Errorf("upgrade facts: %w", err)
	}
	in := runcmd.UpgradeInput{
		Kind:            facts.Kind,
		AdvertiseHost:   cfg.AdvertiseHost,
		EnrolPort:       cfg.EnrolPort,
		Pin:             cfg.Pin,
		AgentImage:      cfg.AgentImages[facts.Kind],
		HolderImage:     cfg.HolderImage,
		OpenCanaryImage: cfg.OpenCanaryImage,
		SMBLureImage:    cfg.SMBLureImage,
		SMBLure:         facts.SMBLure,
		SMBWorkgroup:    facts.SMBWorkgroup,
	}
	if facts.SMBShares != "" {
		in.SMBShares = strings.Split(facts.SMBShares, ",")
	}

	// Only a honeypot's run line carries these two; a scanner has no
	// canary_settings keys that reach its environment.
	if facts.Kind == agentkind.Honeypot {
		settings, err := store.ListCanarySettings(ctx, database, canaryID)
		if err != nil {
			return runcmd.UpgradeInput{}, fmt.Errorf("list canary settings: %w", err)
		}
		for _, s := range settings {
			switch s.Key {
			case store.CanarySettingBaitNames:
				in.BaitNames = s.Value
			case store.CanarySettingSegmentProfile:
				in.SegmentProfile = s.Value
			}
		}
	}
	return in, nil
}
