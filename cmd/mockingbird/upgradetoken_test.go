package main

import (
	"strings"
	"testing"
)

// TestRunUpgradeTokenRefusesArguments: the token is read from stdin
// only; an argument -- where a token would show in a process listing --
// is a usage error before anything else happens.
func TestRunUpgradeTokenRefusesArguments(t *testing.T) {
	var out strings.Builder
	token := strings.Repeat("ab", 32)
	if code := runUpgradeToken([]string{token}, strings.NewReader(token), &out); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if strings.Contains(out.String(), token) {
		t.Errorf("the usage message repeats the argument: %q", out.String())
	}
}

// TestRunUpgradeTokenNeedsStdin: no token on stdin is a usage error.
func TestRunUpgradeTokenNeedsStdin(t *testing.T) {
	var out strings.Builder
	if code := runUpgradeToken(nil, strings.NewReader(""), &out); code != 2 {
		t.Errorf("exit = %d, want 2 (output %q)", code, out.String())
	}
}
