package auth_test

import (
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/auth"
)

// gateRuleLine is what gauntlet's gate logs once, when it is built, naming
// the admin passkey rule it was given.
const gateRuleLine = "gate: admin passkey rule: "

// gateRules returns the rule names the gate logged while the service opened.
func gateRules(c *logCapture) []string {
	var rules []string
	for _, line := range c.all() {
		if rest, ok := strings.CutPrefix(line, gateRuleLine); ok {
			rules = append(rules, strings.TrimSpace(rest))
		}
	}
	return rules
}

// TestOpenBuildsGateWithAdminPasskeyRule checks that Open hands the gate the
// rule AdminPasskeyRule decides (#180, ADR-0016 decision 5), observed through
// the line gauntlet's gate logs when it starts.
func TestOpenBuildsGateWithAdminPasskeyRule(t *testing.T) {
	tests := []struct {
		name     string
		cfg      auth.Config
		wantRule string
	}{
		{"https domain with passkeys wired requires it", auth.Config{PublicURL: "https://birdcage.example.com"}, "required"},
		{"https IP address leaves it optional", auth.Config{PublicURL: "https://192.0.2.10"}, "optional"},
		{"plain http leaves it optional", auth.Config{PublicURL: "http://birdcage.example.com"}, "optional"},
		{"no public URL leaves it optional", auth.Config{}, "optional"},
		{"override optional on an https domain", auth.Config{PublicURL: "https://birdcage.example.com", AdminPasskeyOverride: "optional"}, "optional"},
		{"override required on an https domain", auth.Config{PublicURL: "https://birdcage.example.com", AdminPasskeyOverride: "required"}, "required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Key = testKey('r')
			sys := startSystemWith(t, openDatabase(t), tc.cfg)
			got := gateRules(sys.log)
			if len(got) != 1 || got[0] != tc.wantRule {
				t.Errorf("gate admin passkey rule logged %q, want exactly [%s]", got, tc.wantRule)
			}
		})
	}
}

// TestOpenRefusesInvalidAdminPasskeyOverride checks that auth.Open refuses
// to start on an override it cannot honour, instead of building the gate.
func TestOpenRefusesInvalidAdminPasskeyOverride(t *testing.T) {
	tests := []struct {
		name string
		cfg  auth.Config
		want string
	}{
		{"unknown value", auth.Config{PublicURL: "https://birdcage.example.com", AdminPasskeyOverride: "sometimes"}, "is not recognised"},
		{"required on an IP address", auth.Config{PublicURL: "https://192.0.2.10", AdminPasskeyOverride: "required"}, "BIRDCAGE_AUTH_ADMIN_PASSKEY=required"},
		{"required with no public URL", auth.Config{AdminPasskeyOverride: "required"}, "BIRDCAGE_AUTH_ADMIN_PASSKEY=required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Key = testKey('r')
			logger, capture := newLogCapture()
			svc, err := auth.Open(t.Context(), openDatabase(t), tc.cfg, logger)
			if err == nil {
				svc.Close()
				t.Fatal("auth.Open succeeded, want a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
			if got := gateRules(capture); len(got) != 0 {
				t.Errorf("gate was built (logged %q) despite the refusal", got)
			}
		})
	}
}
