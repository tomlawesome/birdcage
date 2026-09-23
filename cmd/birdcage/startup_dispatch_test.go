package main

import (
	"io"
	"testing"
)

// TestRunSubcommandCanaryDispatch drives every case of runSubcommand's
// `canary` switch -- TestRunSubcommand (startup_test.go) only proves the
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
		{"add", []string{"birdcage", "canary", "add"}},
		{"mint", []string{"birdcage", "canary", "mint"}},
		{"list", []string{"birdcage", "canary", "list", "unexpected-arg"}},
		{"revoke", []string{"birdcage", "canary", "revoke"}},
		{"enrol", []string{"birdcage", "canary", "enrol"}},
		{"unknown", []string{"birdcage", "canary", "bogus"}},
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
