package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/runcmd"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/term"
)

// startupUpgradeConfig is issue #54's server-side counterpart to what
// runCanaryEnrol (canary.go) reads at CLI time: the same advertise host,
// enrolment port, CA pin and image references, resolved once from the
// running server's own configuration so the canary page's upgrade command
// names exactly what a fresh `birdcage agent enrol` from this server
// would print. `agent upgrade-command` resolves the same through
// cliUpgradeConfig below.
//
// The images are read through getenv with the same variables and
// defaults enrolment uses (agentkind.Profile.ImageEnv/DefaultImage,
// runcmd's EnvHolderImage and friends) -- `agent enrol` run with `docker
// exec` inherits this container's environment, so the two agree unless
// an operator overrides one on the exec line alone.
//
// Returns the zero value -- no command printed -- when there is nothing a
// canary could be told to reach: ingest (and so enrolment) off, no
// BIRDCAGE_ADVERTISE_HOST, no CA, or an enrolment address with no port.
// The same conditions runCanaryEnrol refuses on.
func startupUpgradeConfig(cfg startupConfig, birdcageCA *ca.CA, getenv func(string) string) api.UpgradeConfig {
	if cfg.ingestAddr == "" || cfg.advertiseHost == "" || birdcageCA == nil {
		return api.UpgradeConfig{}
	}
	_, enrolPort, err := net.SplitHostPort(cfg.enrolAddr)
	if err != nil || enrolPort == "" {
		return api.UpgradeConfig{}
	}

	orDefault := func(name, def string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return def
	}
	images := make(map[agentkind.Kind]string)
	for _, kind := range agentkind.Kinds() {
		if profile, ok := agentkind.Lookup(kind); ok {
			images[kind] = orDefault(profile.ImageEnv, profile.DefaultImage)
		}
	}
	return api.UpgradeConfig{
		AdvertiseHost:   cfg.advertiseHost,
		EnrolPort:       enrolPort,
		Pin:             birdcageCA.Pin(),
		AgentImages:     images,
		HolderImage:     orDefault(runcmd.EnvHolderImage, runcmd.DefaultHolderImage),
		OpenCanaryImage: orDefault(runcmd.EnvOpenCanaryImage, runcmd.DefaultOpenCanaryImage),
		SMBLureImage:    orDefault(runcmd.EnvSMBLureImage, runcmd.DefaultSMBLureImage),
	}
}

// cliUpgradeConfig is startupUpgradeConfig for `birdcage agent
// upgrade-command`, run with `docker exec` beside the server and so
// reading the same environment the server started from: the same
// ingest, enrolment and advertise settings, the same CA directory, the
// same image overrides. Unlike the server, which answers "no command"
// quietly, it says what is missing.
func cliUpgradeConfig(getenv func(string) string) (api.UpgradeConfig, error) {
	caDir := getenv(envCADir)
	if caDir == "" {
		caDir = defaultCADir
	}
	birdcageCA, _, err := ca.Load(caDir, nil)
	if err != nil {
		return api.UpgradeConfig{}, fmt.Errorf("load CA (%s=%q): %w", envCADir, caDir, err)
	}
	enrolAddr := getenv(envEnrolAddr)
	if enrolAddr == "" {
		enrolAddr = defaultEnrolAddr
	}
	cfg := startupUpgradeConfig(startupConfig{
		ingestAddr:    getenv(envIngestAddr),
		enrolAddr:     enrolAddr,
		advertiseHost: getenv(envAdvertiseHost),
	}, birdcageCA, getenv)
	if !cfg.Usable() {
		return api.UpgradeConfig{}, fmt.Errorf("cannot print an upgrade command: %s and %s must be set and %s=%q must name a port, as for `birdcage agent enrol`",
			envIngestAddr, envAdvertiseHost, envEnrolAddr, enrolAddr)
	}
	return cfg, nil
}

// runAgentUpgradeCommand implements `birdcage agent upgrade-command
// <agent_id>` (issue #54, ADR-0012's B4 amendment): mints a single-use
// upgrade token for the agent, valid for store.UpgradeTokenTTL, and
// prints the agent's whole upgrade command with the token in it -- one
// block to copy from here and paste on the agent's host.
//
// A CLI on the birdcage host rather than a button on the canary page:
// minting is a state change, and the dashboard API stays read-only
// until login exists (owner, 2026-09-26, #8) -- the same reason `agent
// settings set` is a CLI. It also keeps minting away from anything an
// agent credential can reach, so a copied credential can never open a
// window for itself.
//
// Only an agent birdcage already shows as agent_out_of_date gets one
// (store.ErrAgentNotBehind). Everything read-only happens first, so a
// failure before the mint burns nothing; the mint and its audit row
// commit together; the command is printed only after that commit. The
// command goes to stdout alone, so it can be copied or redirected whole;
// the note saying how long it is good for goes to stderr, before it.
func runAgentUpgradeCommand(args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: birdcage agent upgrade-command <agent_id>")
	}
	agentID := args[0]

	cfg, err := cliUpgradeConfig(getenv)
	if err != nil {
		return err
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	in, err := api.UpgradeInputFor(ctx, database, cfg, agentID)
	if err != nil {
		if errors.Is(err, store.ErrCanaryNotFound) {
			return fmt.Errorf("unknown agent %s", term.Escape(agentID))
		}
		return err
	}

	tx, err := database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer rollbackCanaryTx(tx, &committed)

	now := time.Now().UTC()
	raw, tok, err := store.MintUpgradeToken(ctx, tx, agentID, version, now)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrCanaryNotFound):
			return fmt.Errorf("unknown agent %s", term.Escape(agentID))
		case errors.Is(err, store.ErrAgentNotBehind):
			return fmt.Errorf("agent %s is not behind birdcage %s: there is nothing to upgrade, so no upgrade token was minted",
				term.Escape(agentID), term.Escape(version))
		}
		return fmt.Errorf("mint upgrade token: %w", err)
	}
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Action: "canary.upgrade_token_minted",
		Target: agentID,
		Reason: fmt.Sprintf("minted via CLI; single use, valid until %s; its window would cover agent builds %q and %q",
			tok.ExpiresAt.Format(time.RFC3339), tok.FromVersion, tok.ToVersion),
		TriggeredBy: "cli",
		CreatedAt:   now,
	}); err != nil {
		return fmt.Errorf("record mint audit entry: %w", err)
	}

	in.UpgradeToken = raw
	var script strings.Builder
	if err := runcmd.Upgrade(&script, in); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true

	_, _ = fmt.Fprintf(stderr, "Upgrade command for agent %s, from %s to %s. It carries a single-use upgrade token, valid until %s (%d minutes). Paste the whole block on the agent's host, as one paste:\n",
		term.Escape(agentID), term.Escape(tok.FromVersion), term.Escape(tok.ToVersion),
		tok.ExpiresAt.Format(time.RFC3339), int(store.UpgradeTokenTTL/time.Minute))
	_, err = io.WriteString(stdout, script.String())
	return err
}
