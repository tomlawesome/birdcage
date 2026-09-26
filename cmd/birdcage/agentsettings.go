package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/term"
)

// runAgentSettings dispatches `birdcage agent settings <show|set> ...`
// (issue #124): the operator's one way to change a running agent's
// per-canary settings (segment profile, bait names, pace floor/ceiling,
// working hours) without a container restart. There is no dashboard
// write path -- owner, 2026-09-26: the dashboard API stays read-only
// until login exists (#8), so this CLI, run on the birdcage host, is the
// only door onto store.SetCanarySettings today. The canary page (#134)
// waits on that login before it can offer the same write.
func runAgentSettings(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: birdcage agent settings <show|set> <agent_id> [<key>=<value> ...]")
	}
	switch args[0] {
	case "show":
		return runAgentSettingsShow(args[1:])
	case "set":
		return runAgentSettingsSet(args[1:])
	default:
		return fmt.Errorf("unknown agent settings subcommand %q (want show or set)", args[0])
	}
}

// runAgentSettingsShow implements `birdcage agent settings show <agent_id>`:
// every canary_settings row for agent_id, its value, version and updated_at,
// and whether the agent's own last-reported heartbeat hash confirms it is
// actually running with that value (store.SettingsHash compared against
// agents.settings_hash -- the same computation internal/api/canary.go's
// facts column uses, so this command and the canary page can never
// disagree about what "confirmed" means).
func runAgentSettingsShow(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: birdcage agent settings show <agent_id>")
	}
	agentID := args[0]

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	if _, err := store.GetCanaryKind(ctx, database, agentID); err != nil {
		if errors.Is(err, store.ErrCanaryNotFound) {
			return fmt.Errorf("unknown agent %s", term.Escape(agentID))
		}
		return fmt.Errorf("get agent kind: %w", err)
	}

	settings, err := store.ListCanarySettings(ctx, database, agentID)
	if err != nil {
		return fmt.Errorf("list agent settings: %w", err)
	}
	if len(settings) == 0 {
		fmt.Printf("no settings pushed for %s; its environment variables are in force\n", term.Escape(agentID))
		return nil
	}

	reportedHash, _, err := store.GetCanarySettingsHash(ctx, database, agentID)
	if err != nil {
		return fmt.Errorf("get agent settings hash: %w", err)
	}
	currentHash := store.SettingsHash(settings)
	confirmed := reportedHash != "" && reportedHash == currentHash

	// settings/values are read back from the database exactly as stored;
	// escaped here, at the point they reach this terminal, matching
	// runCanaryList's own rule -- including bait_names, which must never
	// be printed unescaped even though it never reaches a log line (see
	// internal/agent/poisoner's package comment: this screen is an
	// operator's own terminal, not a log).
	for _, s := range settings {
		fmt.Printf("%s=%s\tversion=%d\tupdated=%s\tconfirmed=%t\n",
			term.Escape(string(s.Key)), term.Escape(s.Value), s.Version, s.UpdatedAt.Format(time.RFC3339), confirmed)
	}
	return nil
}

// runAgentSettingsSet implements `birdcage agent settings set <agent_id>
// <key>=<value> [<key>=<value> ...]`: one or more keys, written in one
// transaction (store.SetCanarySettings) -- a batch with one bad key
// writes nothing, not a partial update. Validated against the same
// closed key set and rules the environment variables and enrolment
// flags already use (internal/store/canary_settings.go); an unknown
// key, an invalid value, or a key that does not apply to this agent's
// kind (e.g. segment_profile on a scanner) is refused with a message
// naming what was wrong, before anything is stored.
func runAgentSettingsSet(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: birdcage agent settings set <agent_id> <key>=<value> [<key>=<value> ...]")
	}
	agentID := args[0]

	updates := make(map[store.CanarySettingKey]string, len(args)-1)
	for _, pair := range args[1:] {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" {
			return fmt.Errorf("usage: birdcage agent settings set <agent_id> <key>=<value> [<key>=<value> ...] -- %q is not key=value", pair)
		}
		updates[store.CanarySettingKey(key)] = value
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	kind, err := store.GetCanaryKind(ctx, database, agentID)
	if err != nil {
		if errors.Is(err, store.ErrCanaryNotFound) {
			return fmt.Errorf("unknown agent %s", term.Escape(agentID))
		}
		return fmt.Errorf("get agent kind: %w", err)
	}

	if err := store.SetCanarySettings(ctx, database, agentID, kind, updates, time.Now().UTC(), "cli"); err != nil {
		return fmt.Errorf("set agent settings: %w", err)
	}

	// args are exactly what the caller typed; escaped here, at the point
	// they reach this terminal, same as runCanaryAdd/Mint/Revoke and
	// runSettingsSet.
	for _, pair := range args[1:] {
		fmt.Println(term.Escape(pair))
	}
	return nil
}
