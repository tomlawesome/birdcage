package main

import (
	"encoding/json"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// TestRunCommandUnknownKindRefused proves #48's fail-closed rule: a
// command of a kind this agent does not know is refused and nothing is
// executed -- runCommand's non-nil return is the caller's cue to log the
// refusal rather than act on it.
func TestRunCommandUnknownKindRefused(t *testing.T) {
	err := runCommand(&client.Command{ID: "cmd-1", Kind: "upgrade"})
	if err == nil {
		t.Fatal("runCommand(unknown kind) = nil, want a refusal")
	}
}

// TestRunCommandSelfTestAccepted proves the known kind, with no params
// and with a well-formed object of params, is accepted -- the runner's
// seat, not the probe engine (#48's process-composition note).
func TestRunCommandSelfTestAccepted(t *testing.T) {
	for _, params := range [][]byte{nil, []byte(`{"marker":"m1"}`), []byte(`{}`)} {
		if err := runCommand(&client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: params}); err != nil {
			t.Errorf("runCommand(selftest, params=%s) = %v, want nil", params, err)
		}
	}
}

// TestRunCommandSelfTestUnparseableParamsRefused proves the other half
// of #48's fail-closed rule for commands: params that are not a JSON
// object -- a bare string or number, or malformed JSON outright -- are
// refused rather than silently ignored, even for the one kind this
// agent knows.
func TestRunCommandSelfTestUnparseableParamsRefused(t *testing.T) {
	for _, params := range [][]byte{
		[]byte(`"just-a-string"`),
		[]byte(`42`),
		[]byte(`[1,2,3]`),
		[]byte(`{not valid json`),
	} {
		err := runCommand(&client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: params})
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

// selftestParamsRoundTrip is a sanity check that runSelfTest's generic
// object check accepts exactly the params shape command_test.go's own
// client package fixtures already mint (`{"marker":"m1"}"`), so this
// slice's validation cannot be stricter than what #46 already relies on.
func TestRunSelfTestAcceptsMarkerShapedParams(t *testing.T) {
	var probe map[string]json.RawMessage
	params := []byte(`{"marker":"m1"}`)
	if err := json.Unmarshal(params, &probe); err != nil {
		t.Fatalf("fixture itself is not a JSON object: %v", err)
	}
	if err := runSelfTest(&client.Command{ID: "cmd-1", Kind: kindSelfTest, Params: params}); err != nil {
		t.Fatalf("runSelfTest(%s) = %v, want nil", params, err)
	}
}
