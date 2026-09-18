// Package store: this file mints and matches issue #46's self-test
// commands. It deliberately adds no new table -- a selftest command's
// issued markers are already durable in canary_commands.params (written
// by MintSelfTestCommand, read back by MatchSelfTest), so a matcher
// needs nothing beyond that column and a substring search.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/selftest"
)

// SelfTestTarget is what MintSelfTestCommand needs from a caller to plant
// one probe: which service, on which port. The marker itself is never a
// caller input -- see MintSelfTestCommand -- because a marker a caller
// could choose or observe in advance is a marker an attacker could guess.
type SelfTestTarget struct {
	Service  string
	DestPort int
}

// MintSelfTestCommand builds one selftest.Params for canaryID -- a fresh
// crypto/rand marker per target, never reused, never derived from
// anything predictable (#46 settled decision 4: a guessable marker would
// let an attacker's own traffic be classified as a test and so kept off
// the dashboard, which inverts the product) -- and queues it through
// MintCanaryCommand, the one door into canary_commands.
func MintSelfTestCommand(ctx context.Context, database db.Conn, canaryID, address string, targets []SelfTestTarget, createdAt, expiresAt time.Time) (CanaryCommand, error) {
	if len(targets) == 0 {
		return CanaryCommand{}, selftest.ErrNoTargets
	}
	runID, err := randomHex(commandIDBytes)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("generate selftest run id: %w", err)
	}
	params := selftest.Params{
		RunID:   runID,
		Address: address,
		Targets: make([]selftest.Target, len(targets)),
	}
	for i, tgt := range targets {
		// selftest.MarkerBytes of crypto/rand entropy, hex-encoded --
		// randomHex is the same primitive canary_tokens and
		// canary_commands ids already trust for unguessable values.
		marker, err := randomHex(selftest.MarkerBytes)
		if err != nil {
			return CanaryCommand{}, fmt.Errorf("generate selftest marker: %w", err)
		}
		params.Targets[i] = selftest.Target{
			Service:  tgt.Service,
			DestPort: tgt.DestPort,
			Marker:   marker,
		}
	}
	if err := params.Validate(); err != nil {
		// selftest.Validate is the wire contract's own gate; failing it
		// here is this function's bug (e.g. a caller-supplied empty
		// Service), not a condition worth minting a command the agent
		// will just refuse.
		return CanaryCommand{}, fmt.Errorf("selftest: built invalid params: %w", err)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("marshal selftest params: %w", err)
	}
	return MintCanaryCommand(ctx, database, canaryID, CommandSelfTest, string(raw), createdAt, expiresAt)
}

// MatchSelfTest decides whether alert is a hit birdcage's own self-test
// planted, never whether it merely looks like one. This is #46's whole
// security property: "anything test-shaped that does not match an issued
// command is a real alert, not a test", so every unmatched, unparseable
// or doubtful path below returns false -- fail closed, same as
// selftest.DecodeParams does on the wire.
//
// The candidate set is every selftest command ever minted for
// alert.InstanceID, which structurally enforces "same canary the command
// was minted for": a command minted for a different canary is never in
// this query's result, so it is never checked. Callers must pass the
// canary id it actually came in on -- see AlertInsert.InstanceID's own
// doc comment ("identity from the token, never the payload").
func MatchSelfTest(ctx context.Context, database *db.DB, alert AlertInsert, now time.Time) (bool, error) {
	cmds, err := listCanaryCommandsForCanary(ctx, database, alert.InstanceID, CommandSelfTest)
	if err != nil {
		return false, fmt.Errorf("list selftest commands: %w", err)
	}
	now = now.UTC()
	for _, cmd := range cmds {
		// Expiry is judged here in Go on parsed RFC3339Nano, never in
		// SQL -- ClaimNextCanaryCommand's doc comment has the trimmed-
		// fractional-second trap this avoids.
		if !cmd.ExpiresAt.After(now) {
			continue
		}
		params, err := selftest.DecodeParams(json.RawMessage(cmd.Params))
		if err != nil {
			// A row this package itself wrote should always decode; if
			// it doesn't, that is corruption, not evidence of a test --
			// skip it rather than trust it.
			continue
		}
		for _, tgt := range params.Targets {
			if tgt.Marker != "" && strings.Contains(alert.Raw, tgt.Marker) {
				return true, nil
			}
		}
	}
	return false, nil
}

// listCanaryCommandsForCanary returns every canary_commands row for
// canaryID and kind, delivered or not, expired or not: MatchSelfTest is
// the only caller and it judges both of those itself, in Go.
func listCanaryCommandsForCanary(ctx context.Context, database *db.DB, canaryID string, kind CommandKind) ([]CanaryCommand, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT id, canary_id, kind, params, created_at, expires_at
		FROM canary_commands
		WHERE canary_id = ? AND kind = ?`, canaryID, string(kind))
	if err != nil {
		return nil, fmt.Errorf("list canary commands: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var cmds []CanaryCommand
	for rows.Next() {
		cmd, err := scanPendingCommand(rows)
		if err != nil {
			return nil, err
		}
		cmds = append(cmds, cmd)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate canary commands: %w", err)
	}
	return cmds, nil
}
