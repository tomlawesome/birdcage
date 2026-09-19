package main

import (
	"context"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// validSelfTestParams is one well-formed selftest.Params, matching the
// real wire schema #46 ratified (internal/selftest/params.go) rather
// than the opaque-object placeholder this seat used to accept. Port 1
// has nothing listening in this sandbox, so the target itself fails
// fast (StatusFailed) -- irrelevant here, since runSelfTest's own
// contract is that a target failing is not a command-level refusal.
var validSelfTestParams = []byte(`{"run_id":"r1","address":"127.0.0.1","targets":[{"service":"ftp","dest_port":1,"marker":"m1"}]}`)

// TestRunCommandUnknownKindRefused proves #48's fail-closed rule: a
// command of a kind this agent does not know is refused and nothing is
// executed -- runCommand's non-nil return is the caller's cue to log the
// refusal rather than act on it.
func TestRunCommandUnknownKindRefused(t *testing.T) {
	err := runCommand(context.Background(), &client.Command{ID: "cmd-1", Kind: "upgrade"})
	if err == nil {
		t.Fatal("runCommand(unknown kind) = nil, want a refusal")
	}
}

// TestRunCommandSelfTestAccepted proves a well-formed selftest command
// is accepted regardless of how its targets fare -- the probe engine's
// per-target failures are logged, not returned as a command-level
// refusal (#46: a self-test measuring a dead service is a correct
// result, not an error).
func TestRunCommandSelfTestAccepted(t *testing.T) {
	err := runCommand(context.Background(), &client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: validSelfTestParams})
	if err != nil {
		t.Errorf("runCommand(selftest, params=%s) = %v, want nil", validSelfTestParams, err)
	}
}

// TestRunCommandSelfTestUnparseableParamsRefused proves #48's
// fail-closed rule for commands: params that do not decode as a valid
// selftest.Params -- absent entirely, an empty object missing every
// required field, not even a JSON object, or malformed JSON outright --
// are refused rather than silently ignored or partially run, even for
// the one kind this agent knows.
func TestRunCommandSelfTestUnparseableParamsRefused(t *testing.T) {
	for _, params := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`{"marker":"m1"}`), // the old placeholder's shape: not a valid Params
		[]byte(`"just-a-string"`),
		[]byte(`42`),
		[]byte(`[1,2,3]`),
		[]byte(`{not valid json`),
	} {
		err := runCommand(context.Background(), &client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: params})
		if err == nil {
			t.Errorf("runCommand(selftest, params=%s) = nil, want a refusal", params)
		}
	}
}

// TestJitteredIntervalStaysInBound proves the poll cadence's jitter
// (#48 decision 3, owner-ratified: "every 60 s with jitter") never
// strays outside base +/- jitter, and that jitter <= 0 is a no-op.
func TestJitteredIntervalStaysInBound(t *testing.T) {
	base, jitter := commandPollInterval, commandPollJitter
	for i := 0; i < 200; i++ {
		got := jitteredInterval(base, jitter)
		if got < base-jitter || got > base+jitter {
			t.Fatalf("jitteredInterval() = %v, want within [%v, %v]", got, base-jitter, base+jitter)
		}
	}
	if got := jitteredInterval(base, 0); got != base {
		t.Fatalf("jitteredInterval(base, 0) = %v, want %v unchanged", got, base)
	}
}

// TestRunSelfTestLogsOutcomesAndReturnsNil proves runSelfTest itself --
// not just the runCommand dispatch above it -- accepts a well-formed
// run and returns nil, leaving per-target reporting to its own logging
// (probe.Sweep's outcomes are exercised directly in
// internal/agent/probe's own tests).
func TestRunSelfTestLogsOutcomesAndReturnsNil(t *testing.T) {
	err := runSelfTest(context.Background(), &client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: validSelfTestParams})
	if err != nil {
		t.Fatalf("runSelfTest(%s) = %v, want nil", validSelfTestParams, err)
	}
}
