package main

import (
	"testing"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/runcmd"
)

// TestStartupUpgradeConfig: issue #54's server-side facts come from the
// same configuration enrolment uses, and are withheld entirely whenever
// enrolment itself would refuse -- a command naming no reachable address
// is worse than none.
func TestStartupUpgradeConfig(t *testing.T) {
	birdcageCA := testCA(t)
	full := startupConfig{ingestAddr: ":8443", enrolAddr: ":8444", advertiseHost: "birdcage.example.test"}
	noEnv := func(string) string { return "" }

	t.Run("defaults", func(t *testing.T) {
		got := startupUpgradeConfig(full, birdcageCA, noEnv)
		mockingbird, _ := agentkind.Lookup(agentkind.Honeypot)
		nightjar, _ := agentkind.Lookup(agentkind.Scanner)
		if got.AdvertiseHost != "birdcage.example.test" || got.EnrolPort != "8444" || got.Pin != birdcageCA.Pin() {
			t.Errorf("host/port/pin = %q/%q/%q, want birdcage.example.test/8444/%s", got.AdvertiseHost, got.EnrolPort, got.Pin, birdcageCA.Pin())
		}
		if got.AgentImages[agentkind.Honeypot] != mockingbird.DefaultImage || got.AgentImages[agentkind.Scanner] != nightjar.DefaultImage {
			t.Errorf("agent images = %v, want the profiles' defaults", got.AgentImages)
		}
		if got.HolderImage != runcmd.DefaultHolderImage || got.OpenCanaryImage != runcmd.DefaultOpenCanaryImage || got.SMBLureImage != runcmd.DefaultSMBLureImage {
			t.Errorf("holder/opencanary/lure = %q/%q/%q, want runcmd's defaults", got.HolderImage, got.OpenCanaryImage, got.SMBLureImage)
		}
	})

	t.Run("environment overrides, as enrolment reads them", func(t *testing.T) {
		env := map[string]string{
			"MOCKINGBIRD_IMAGE":       "r/mockingbird:1",
			"NIGHTJAR_IMAGE":          "r/nightjar:1",
			runcmd.EnvHolderImage:     "r/holder:1",
			runcmd.EnvOpenCanaryImage: "r/opencanary:1",
			runcmd.EnvSMBLureImage:    "r/smb-lure:1",
		}
		got := startupUpgradeConfig(full, birdcageCA, func(k string) string { return env[k] })
		if got.AgentImages[agentkind.Honeypot] != "r/mockingbird:1" || got.AgentImages[agentkind.Scanner] != "r/nightjar:1" ||
			got.HolderImage != "r/holder:1" || got.OpenCanaryImage != "r/opencanary:1" || got.SMBLureImage != "r/smb-lure:1" {
			t.Errorf("images ignored the environment: %+v", got)
		}
	})

	for _, tc := range []struct {
		name string
		cfg  startupConfig
		ca   *ca.CA
	}{
		{"ingest off", startupConfig{enrolAddr: ":8444", advertiseHost: "birdcage.example.test"}, birdcageCA},
		{"no advertise host", startupConfig{ingestAddr: ":8443", enrolAddr: ":8444"}, birdcageCA},
		{"no CA", full, nil},
		{"enrol address without a port", startupConfig{ingestAddr: ":8443", enrolAddr: "nope", advertiseHost: "birdcage.example.test"}, birdcageCA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := startupUpgradeConfig(tc.cfg, tc.ca, noEnv)
			if got.AdvertiseHost != "" || got.Pin != "" || got.EnrolPort != "" || got.AgentImages != nil {
				t.Errorf("got %+v, want the zero value (no command printed)", got)
			}
			var zero api.UpgradeConfig
			if got.HolderImage != zero.HolderImage {
				t.Errorf("got %+v, want the zero value", got)
			}
		})
	}
}
