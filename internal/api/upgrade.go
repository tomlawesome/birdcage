package api

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/runcmd"
	"github.com/tomlawesome/birdcage/internal/store"
)

// UpgradeConfig is the running server's own answer to the questions
// `birdcage agent enrol` answers from its environment at CLI time (issue
// #54): where a canary reaches this birdcage (AdvertiseHost, EnrolPort),
// which CA it pins (Pin), and which image each container runs. The
// canary page's upgrade command is built from these plus the canary's
// own stored facts, so an upgrade re-runs exactly what a fresh enrolment
// from this server would print, minus the deploy token.
//
// cmd/birdcage/main.go fills it once at startup from the same
// environment the enrolment listener is configured by. The zero value
// means "this server cannot print one" -- ingest is off, or
// BIRDCAGE_ADVERTISE_HOST is unset, so there is no address a canary could
// be told to reach -- and the page then carries an empty
// upgrade_command, which the frontend answers with a pointer to
// docs/enrolment.md instead of a command that would not work.
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

// usable reports whether c holds enough to print a working command: the
// three facts every agent's run line carries. Images always have a
// default, so they are never what is missing.
func (c UpgradeConfig) usable() bool {
	return c.AdvertiseHost != "" && c.EnrolPort != "" && c.Pin != ""
}

// upgradeCommand is canary c's upgrade script, or "" when c is not
// agent_out_of_date or this server cannot print one. Read from
// c.ActiveStates rather than c.Status: a worse state (silent, say) can
// hold Status while the agent is still behind underneath it, and the
// operator still needs the command then.
//
// Never carries a deploy token: runcmd.Upgrade always passes none (see
// runcmd.MockingbirdConfig.Token for why one would be pointless or
// worse), and nothing here has one to pass.
func (h *handler) upgradeCommand(ctx context.Context, c store.Canary) (string, error) {
	if !slices.Contains(c.ActiveStates, string(store.StateAgentOutOfDate)) || !h.upgrade.usable() {
		return "", nil
	}

	facts, err := store.GetCanaryUpgradeFacts(ctx, h.db, c.ID)
	if err != nil {
		return "", fmt.Errorf("upgrade facts: %w", err)
	}
	in := runcmd.UpgradeInput{
		Kind:            facts.Kind,
		AdvertiseHost:   h.upgrade.AdvertiseHost,
		EnrolPort:       h.upgrade.EnrolPort,
		Pin:             h.upgrade.Pin,
		AgentImage:      h.upgrade.AgentImages[facts.Kind],
		HolderImage:     h.upgrade.HolderImage,
		OpenCanaryImage: h.upgrade.OpenCanaryImage,
		SMBLureImage:    h.upgrade.SMBLureImage,
		SMBLure:         facts.SMBLure,
		SMBWorkgroup:    facts.SMBWorkgroup,
	}
	if facts.SMBShares != "" {
		in.SMBShares = strings.Split(facts.SMBShares, ",")
	}

	// Only a honeypot's run line carries these two; a scanner has no
	// canary_settings keys that reach its environment.
	if facts.Kind == agentkind.Honeypot {
		settings, err := store.ListCanarySettings(ctx, h.db, c.ID)
		if err != nil {
			return "", fmt.Errorf("list canary settings: %w", err)
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

	var b strings.Builder
	if err := runcmd.Upgrade(&b, in); err != nil {
		return "", err
	}
	return b.String(), nil
}
