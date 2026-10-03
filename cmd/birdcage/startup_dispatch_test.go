package main

import (
	"io"
	"testing"
)

// TestRunSubcommandCanaryDispatch drives every case of runSubcommand's
// `agent` switch, under both its `agent` name and its `canary` alias
// (issue #107: ADR-0009 gave nodes a kind, so `canary` is one kind, not
// the fleet noun) -- TestRunSubcommand (startup_test.go) only proves the
// "no subcommand" branch, leaving add/mint/list/revoke/enrol/unknown
// themselves undispatched. Each case here uses args that return quickly
// (a usage error, where the underlying function needs none) so this
// stays about proving the dispatch wiring reaches the right function,
// not re-testing each function's own behavior (canary_test.go and
// canary_add_test.go already do that).
func TestRunSubcommandCanaryDispatch(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	cases := []struct {
		name string
		args []string
	}{
		{"add", []string{"birdcage", "agent", "add"}},
		{"mint", []string{"birdcage", "agent", "mint"}},
		{"list", []string{"birdcage", "agent", "list", "unexpected-arg"}},
		{"revoke", []string{"birdcage", "agent", "revoke"}},
		{"enrol", []string{"birdcage", "agent", "enrol"}},
		{"settings", []string{"birdcage", "agent", "settings"}},
		{"upgrade-command", []string{"birdcage", "agent", "upgrade-command"}},
		{"unknown", []string{"birdcage", "agent", "bogus"}},
		{"alias add", []string{"birdcage", "canary", "add"}},
		{"alias mint", []string{"birdcage", "canary", "mint"}},
		{"alias list", []string{"birdcage", "canary", "list", "unexpected-arg"}},
		{"alias revoke", []string{"birdcage", "canary", "revoke"}},
		{"alias enrol", []string{"birdcage", "canary", "enrol"}},
		{"alias settings", []string{"birdcage", "canary", "settings"}},
		{"alias upgrade-command", []string{"birdcage", "canary", "upgrade-command"}},
		{"alias unknown", []string{"birdcage", "canary", "bogus"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handled, exitCode := runSubcommand(c.args, io.Discard)
			if !handled {
				t.Fatalf("runSubcommand(%v) handled = false, want true", c.args)
			}
			if exitCode != 1 {
				t.Errorf("runSubcommand(%v) exitCode = %d, want 1 (every case here is an error path)", c.args, exitCode)
			}
		})
	}
}

// TestRunSubcommandAgentSettingsDispatch drives `agent settings`'s own
// show/set/unknown cases -- TestRunSubcommandCanaryDispatch above only
// reaches the "settings" usage-error branch (no show/set argument at
// all), leaving runAgentSettings' own dispatch undispatched.
func TestRunSubcommandAgentSettingsDispatch(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	insertTestCanary(t, database, "agent-settings-dispatch-test")
	closeCanaryDB(database)

	t.Run("show unknown agent is an error", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "agent", "settings", "show", "does-not-exist"}, io.Discard)
		if !handled || exitCode != 1 {
			t.Errorf("runSubcommand(agent settings show does-not-exist) = handled=%v exitCode=%d, want true, 1", handled, exitCode)
		}
	})
	t.Run("show succeeds", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "agent", "settings", "show", "agent-settings-dispatch-test"}, io.Discard)
		if !handled || exitCode != 0 {
			t.Errorf("runSubcommand(agent settings show) = handled=%v exitCode=%d, want true, 0", handled, exitCode)
		}
	})
	t.Run("set succeeds", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "agent", "settings", "set", "agent-settings-dispatch-test", "segment_profile=off"}, io.Discard)
		if !handled || exitCode != 0 {
			t.Errorf("runSubcommand(agent settings set) = handled=%v exitCode=%d, want true, 0", handled, exitCode)
		}
	})
	t.Run("unknown subcommand is an error", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "agent", "settings", "bogus"}, io.Discard)
		if !handled || exitCode != 1 {
			t.Errorf("runSubcommand(agent settings bogus) = handled=%v exitCode=%d, want true, 1", handled, exitCode)
		}
	})
}

// TestRunSubcommandSettingsDispatch drives the `settings` switch's three
// cases plus a successful (exit 0) run, which TestRunSubcommand never
// reaches -- its one settings subtest is the unknown-subcommand branch.
func TestRunSubcommandSettingsDispatch(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	t.Run("list succeeds", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "settings", "list"}, io.Discard)
		if !handled || exitCode != 0 {
			t.Errorf("runSubcommand(settings list) = handled=%v exitCode=%d, want true, 0", handled, exitCode)
		}
	})
	t.Run("get usage error", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "settings", "get"}, io.Discard)
		if !handled || exitCode != 1 {
			t.Errorf("runSubcommand(settings get) = handled=%v exitCode=%d, want true, 1", handled, exitCode)
		}
	})
	t.Run("set succeeds", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "settings", "set", "admin_approval_address", "admin@example.net"}, io.Discard)
		if !handled || exitCode != 0 {
			t.Errorf("runSubcommand(settings set) = handled=%v exitCode=%d, want true, 0", handled, exitCode)
		}
	})
}

// TestRunSubcommandApprovalDispatch drives the `approval` branch
// entirely -- untouched by TestRunSubcommand, which never sends
// "approval" at all.
func TestRunSubcommandApprovalDispatch(t *testing.T) {
	t.Run("no subcommand", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "approval"}, io.Discard)
		if !handled || exitCode != 1 {
			t.Errorf("runSubcommand(approval) = handled=%v exitCode=%d, want true, 1", handled, exitCode)
		}
	})
	t.Run("unknown subcommand", func(t *testing.T) {
		handled, exitCode := runSubcommand([]string{"birdcage", "approval", "bogus"}, io.Discard)
		if !handled || exitCode != 1 {
			t.Errorf("runSubcommand(approval bogus) = handled=%v exitCode=%d, want true, 1", handled, exitCode)
		}
	})
	t.Run("check dispatches to runApprovalCheck", func(t *testing.T) {
		// No arguments after "check" is itself a usage error inside
		// runApprovalCheck -- enough to prove the dispatch reached it,
		// without needing a real .eml fixture or database here (both
		// are covered by approval_test.go's own, more targeted tests).
		handled, exitCode := runSubcommand([]string{"birdcage", "approval", "check"}, io.Discard)
		if !handled || exitCode != 1 {
			t.Errorf("runSubcommand(approval check) = handled=%v exitCode=%d, want true, 1", handled, exitCode)
		}
	})
}
