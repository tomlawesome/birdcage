package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/term"
)

// runFindings dispatches `birdcage findings <list|accept> ...` (issue
// #109). Like `birdcage agent settings` (cmd/birdcage/agentsettings.go,
// issue #124), this exists because the dashboard API stays read-only
// until login exists (#134, owner 2026-09-26): store.AcceptFinding is
// otherwise unreachable from outside the store package. `list` is a
// convenience for an operator to see what they are accepting, not a
// requirement of the issue.
func runFindings(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: birdcage findings <list|accept> ...")
	}
	switch args[0] {
	case "list":
		return runFindingsList(args[1:])
	case "accept":
		return runFindingsAccept(args[1:])
	default:
		return fmt.Errorf("unknown findings subcommand %q (want list or accept)", args[0])
	}
}

// runFindingsList implements `birdcage findings list <agent_id>`: every
// findings row for that agent, whatever its state, read back exactly as
// stored (term.Escape at the point it reaches this terminal, the same
// rule runAgentSettingsShow follows).
func runFindingsList(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: birdcage findings list <agent_id>")
	}
	agentID := args[0]

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	findings, err := store.ListFindings(ctx, database, store.FindingFilter{AgentID: agentID})
	if err != nil {
		return fmt.Errorf("list findings: %w", err)
	}
	if len(findings) == 0 {
		fmt.Printf("no findings recorded for %s\n", term.Escape(agentID))
		return nil
	}
	for _, f := range findings {
		accepted := ""
		if f.State == store.FindingAccepted {
			accepted = fmt.Sprintf("\taccepted_by=%s\taccepted_at=%s", term.Escape(f.AcceptedBy), f.AcceptedAt.Format(time.RFC3339))
		}
		fmt.Printf("%s\t%s\tstate=%s\tseverity=%s\tinstalled=%s\tfixing=%s\tfirst_seen=%s\tlast_seen=%s%s\n",
			term.Escape(f.Target), term.Escape(f.VulnerabilityID), f.State, term.Escape(f.Severity),
			term.Escape(f.InstalledVersion), term.Escape(f.FixingVersion),
			f.FirstSeen.Format(time.RFC3339), f.LastSeen.Format(time.RFC3339), accepted)
	}
	return nil
}

// runFindingsAccept implements `birdcage findings accept <agent_id>
// <target> <vulnerability_id> <accepted_by>`: the operator's acceptance
// decision (ADR-0010 decision 4), the one write path onto findings.state
// -- there is no dashboard route, per dashboardRouteSpecs' own read-only
// rule. accepted_by is the operator's own name/identifier, recorded
// plainly (not derived from any credential -- this CLI runs on the
// birdcage host with no login system to attribute to yet).
func runFindingsAccept(args []string) error {
	if len(args) != 4 {
		return errors.New("usage: birdcage findings accept <agent_id> <target> <vulnerability_id> <accepted_by>")
	}
	agentID, target, vulnerabilityID, acceptedBy := args[0], args[1], args[2], args[3]

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	if err := store.AcceptFinding(ctx, database, agentID, target, vulnerabilityID, acceptedBy, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrFindingNotFound) {
			return fmt.Errorf("no open or accepted finding %s/%s for agent %s", term.Escape(target), term.Escape(vulnerabilityID), term.Escape(agentID))
		}
		return fmt.Errorf("accept finding: %w", err)
	}
	fmt.Printf("accepted\t%s\t%s\t%s\tby=%s\n", term.Escape(agentID), term.Escape(target), term.Escape(vulnerabilityID), term.Escape(acceptedBy))
	return nil
}
