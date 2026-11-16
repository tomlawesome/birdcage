package auth_test

import (
	"testing"

	"github.com/tomlawesome/gauntlet/gate"

	"github.com/tomlawesome/birdcage/internal/auth"
)

// TestAdminPasskeyRule covers every row of the rule in ADR-0016 decision 5:
// required only for an https URL on a domain name with passkeys wired;
// optional otherwise; BIRDCAGE_AUTH_ADMIN_PASSKEY overrides, but cannot ask
// for a passkey that is not wired; any other override value is an error.
func TestAdminPasskeyRule(t *testing.T) {
	cases := []struct {
		name      string
		publicURL string
		wired     bool
		override  string
		want      gate.AdminPasskeyRule
		wantErr   bool
	}{
		{name: "https on a domain name with passkeys wired is required", publicURL: "https://birdcage.example.net", wired: true, want: gate.AdminPasskeyRequired},
		{name: "https on a domain name with a port is required", publicURL: "https://birdcage.example.net:8443", wired: true, want: gate.AdminPasskeyRequired},
		{name: "https on an IPv4 address is optional", publicURL: "https://203.0.113.5", wired: true, want: gate.AdminPasskeyOptional},
		{name: "https on an IPv6 address is optional", publicURL: "https://[2001:db8::5]:8443", wired: true, want: gate.AdminPasskeyOptional},
		{name: "http on a domain name is optional", publicURL: "http://birdcage.example.net", wired: true, want: gate.AdminPasskeyOptional},
		{name: "http on a domain name without passkeys is optional", publicURL: "http://birdcage.example.net", wired: false, want: gate.AdminPasskeyOptional},
		{name: "https on a domain name without passkeys wired is optional", publicURL: "https://birdcage.example.net", wired: false, want: gate.AdminPasskeyOptional},
		{name: "no public URL and no passkeys is optional", publicURL: "", wired: false, want: gate.AdminPasskeyOptional},
		{name: "override optional beats https on a domain name", publicURL: "https://birdcage.example.net", wired: true, override: "optional", want: gate.AdminPasskeyOptional},
		{name: "override required with passkeys wired is required", publicURL: "https://birdcage.example.net", wired: true, override: "required", want: gate.AdminPasskeyRequired},
		{name: "override required with passkeys not wired is an error", publicURL: "", wired: false, override: "required", wantErr: true},
		{name: "override required on an https domain without passkeys wired is an error", publicURL: "https://birdcage.example.net", wired: false, override: "required", wantErr: true},
		{name: "any other override value is an error", publicURL: "https://birdcage.example.net", wired: true, override: "maybe", wantErr: true},
		{name: "any other override value is an error even where optional would apply", publicURL: "", wired: false, override: "always", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := auth.AdminPasskeyRule(tc.publicURL, tc.wired, tc.override)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("AdminPasskeyRule(%q, %v, %q) = %q, nil; want an error", tc.publicURL, tc.wired, tc.override, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AdminPasskeyRule(%q, %v, %q): %v", tc.publicURL, tc.wired, tc.override, err)
			}
			if got != tc.want {
				t.Errorf("AdminPasskeyRule(%q, %v, %q) = %q, want %q", tc.publicURL, tc.wired, tc.override, got, tc.want)
			}
		})
	}
}
