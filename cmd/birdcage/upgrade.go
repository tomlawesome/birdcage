package main

import (
	"net"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/runcmd"
)

// startupUpgradeConfig is issue #54's server-side counterpart to what
// runCanaryEnrol (canary.go) reads at CLI time: the same advertise host,
// enrolment port, CA pin and image references, resolved once from the
// running server's own configuration so the canary page's upgrade command
// names exactly what a fresh `birdcage agent enrol` from this server
// would print.
//
// The images are read through getenv with the same variables and
// defaults enrolment uses (agentkind.Profile.ImageEnv/DefaultImage,
// runcmd's EnvHolderImage and friends) -- `agent enrol` run with `docker
// exec` inherits this container's environment, so the two agree unless
// an operator overrides one on the exec line alone.
//
// Returns the zero value -- no command printed -- when there is nothing a
// canary could be told to reach: ingest (and so enrolment) off, no
// BIRDCAGE_ADVERTISE_HOST, no CA, or an enrolment address with no port.
// The same conditions runCanaryEnrol refuses on.
func startupUpgradeConfig(cfg startupConfig, birdcageCA *ca.CA, getenv func(string) string) api.UpgradeConfig {
	if cfg.ingestAddr == "" || cfg.advertiseHost == "" || birdcageCA == nil {
		return api.UpgradeConfig{}
	}
	_, enrolPort, err := net.SplitHostPort(cfg.enrolAddr)
	if err != nil || enrolPort == "" {
		return api.UpgradeConfig{}
	}

	orDefault := func(name, def string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return def
	}
	images := make(map[agentkind.Kind]string)
	for _, kind := range agentkind.Kinds() {
		if profile, ok := agentkind.Lookup(kind); ok {
			images[kind] = orDefault(profile.ImageEnv, profile.DefaultImage)
		}
	}
	return api.UpgradeConfig{
		AdvertiseHost:   cfg.advertiseHost,
		EnrolPort:       enrolPort,
		Pin:             birdcageCA.Pin(),
		AgentImages:     images,
		HolderImage:     orDefault(runcmd.EnvHolderImage, runcmd.DefaultHolderImage),
		OpenCanaryImage: orDefault(runcmd.EnvOpenCanaryImage, runcmd.DefaultOpenCanaryImage),
		SMBLureImage:    orDefault(runcmd.EnvSMBLureImage, runcmd.DefaultSMBLureImage),
	}
}
