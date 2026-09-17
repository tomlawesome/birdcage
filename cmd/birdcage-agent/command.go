package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// commandPollInterval and commandPollJitter are #48 decision 3, ratified
// by the owner 2026-09-15: "polls every 60 s with jitter, so a fleet
// does not knock in the same second" -- 60 s +/- 10 s (#46's own
// stagger decision narrows the jitter to this bound rather than
// spreading across the whole minute).
const (
	commandPollInterval = 60 * time.Second
	commandPollJitter   = 10 * time.Second
)

// commandRunnerBuffer is #48's process-composition note, decision 4
// [contested]: "the poll loop hands commands to a sequential runner
// (buffer 4 [contested]); overflow drops the newest with a loud local
// log -- safe because birdcage re-mints from observed state."
const commandRunnerBuffer = 4

// kindSelfTest mirrors internal/store.CommandSelfTest's wire value
// ("selftest") rather than importing internal/store, which pulls
// internal/db behind it -- exactly the class of import this binary must
// never link (see main.go's package doc, and internal/agent/client's
// own wire types, which mirror internal/ingest's shapes the same way).
const kindSelfTest = "selftest"

// runCommandPollLoop polls for one command every commandPollInterval
// +/- commandPollJitter (#48 decision 2, owner: "plain poll. No long
// poll") and hands whatever it gets to run, dropping the newest command
// with a loud log if run's buffer is full -- safe, since birdcage
// re-mints a command from observed state rather than expecting one
// specific delivery (decision 3 of this same note).
func runCommandPollLoop(ctx context.Context, c *client.Client, ts *TokenStore, run chan<- *client.Command) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitteredInterval(commandPollInterval, commandPollJitter)):
		}

		cmd, err := authedRetryValue(ts, func(token string) (*client.Command, error) {
			return c.PollCommand(ctx, token)
		})
		if err != nil {
			if client.IsUnauthorized(err) {
				log.Printf("command poll: token unauthorized -- this canary has no channel to birdcage; recovery is re-enrolment (#47)")
			} else {
				log.Printf("command poll: failed, will retry next cycle: %v", err)
			}
			continue
		}
		if cmd == nil {
			continue
		}

		select {
		case run <- cmd:
		case <-ctx.Done():
			return
		default:
			log.Printf("command runner: buffer full, dropping newest command %s (%s) -- birdcage re-mints from observed state", cmd.ID, cmd.Kind)
		}
	}
}

// jitteredInterval returns base plus a uniformly random offset in
// [-jitter, +jitter]. math/rand, not crypto/rand: this only staggers a
// fleet's poll timing against itself, nothing security-relevant depends
// on its unpredictability.
func jitteredInterval(base, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return base
	}
	offset := time.Duration(rand.Int63n(int64(2*jitter+1))) - jitter
	return base + offset
}

// runCommandRunner executes commands from run one at a time, in arrival
// order (#48's process-composition note: "executes dispatched commands
// sequentially"), until ctx is done.
func runCommandRunner(ctx context.Context, run <-chan *client.Command) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-run:
			if err := runCommand(cmd); err != nil {
				log.Printf("command %s (%s): refused, executing nothing: %v", cmd.ID, cmd.Kind, err)
			}
		}
	}
}

// runCommand validates cmd against the one kind this agent knows today
// (store.CommandSelfTest is the only mintable kind; "upgrade" is
// unmintable until #54's verify path exists) and dispatches it. A
// non-nil return is a refusal -- unknown kind or unparseable params --
// and the command is never partially executed either way (#48
// fail-closed: "a command the agent cannot fully parse is an attack or
// version skew; both end in refusal").
func runCommand(cmd *client.Command) error {
	switch cmd.Kind {
	case kindSelfTest:
		return runSelfTest(cmd)
	default:
		return fmt.Errorf("unknown command kind %q", cmd.Kind)
	}
}

// runSelfTest is the command runner's seat for a selftest command, not
// the probe engine itself -- #48's process-composition note: "the
// selftest probe engine is its own later slice (gated on #46's open
// question about unprobeable modules); this composition only fixes its
// seat: a runner invoked with opaque params, emitting nothing into the
// event path, since its probes produce real OpenCanary events that
// arrive by the ordinary two roads."
//
// Params is opaque here in the same sense the process-composition note
// uses it: this function does not interpret any specific field (the
// real schema -- probe order, per-run marker -- is #46's to settle
// alongside the probe engine). What it does check, generically, is that
// non-empty params decode as a JSON object at all, matching the shape
// every command_test.go fixture already uses (`{"marker":"m1"}`) --
// params that are not an object (a bare string, number, or malformed
// JSON) are refused as unparseable rather than silently ignored, per
// #48's fail-closed rule for a command the agent cannot fully parse.
func runSelfTest(cmd *client.Command) error {
	if len(cmd.Params) > 0 {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(cmd.Params, &obj); err != nil {
			return fmt.Errorf("selftest params is not a JSON object: %w", err)
		}
	}
	log.Printf("command %s: selftest accepted (probe engine not yet built, #46)", cmd.ID)
	return nil
}
