package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/readiness"
)

// readinessConfig bundles runReadinessCheck's tunables the same way
// portscan.Config and snmp.Config bundle theirs -- a caller building the
// production road only has to think about the config path, everything
// else has a shipped default.
type readinessConfig struct {
	ConfPath    string
	Host        string
	Window      time.Duration
	PollEvery   time.Duration
	DialTimeout time.Duration
}

// defaultReadinessConfig is what a canary runs with. envOpenCanaryConf is
// the same variable newPortscanRoad and newSNMPRoad already read, so one
// override moves every road that reads opencanary.conf at once.
//
// The 10s window is generous next to what a real boot needs: the
// container this check was proven against (2026-09-22, the https module
// forced to fail by disabling it -- see internal/agent/readiness's doc
// comment) bound every other module within tens of milliseconds of each
// other. A slow module costs this road nothing until it is actually still
// down at the deadline.
func defaultReadinessConfig() readinessConfig {
	return readinessConfig{
		ConfPath:    os.Getenv(envOpenCanaryConf),
		Host:        "127.0.0.1",
		Window:      10 * time.Second,
		PollEvery:   250 * time.Millisecond,
		DialTimeout: 500 * time.Millisecond,
	}
}

// runReadinessCheck is #65's detection half: independently verifying,
// once per boot, that every module opencanary.conf enables actually
// answers, rather than trusting OpenCanary's own startup log to say so.
// internal/agent/readiness's own doc comment has the reason that log
// cannot be trusted to tell a failed module from a started one: both log
// through the same helper, at the same logtype, and OpenCanary keeps
// running either way.
//
// It polls (readiness.Check) until every enabled module has answered at
// least once, or cfg.Window elapses, then logs one WARN per module that
// never did -- named and ported, so an operator or CI reading this
// container's log has something to grep for instead of the generic "base"
// noise OpenCanary's own log carries the same failure in, indistinguishable
// from "Added service from class ... to fake".
//
// Runs once, meant to be started from its own goroutine, and returns once
// it is done. It does not repeat: #65's own scope is a module that never
// started, not one that stops later -- an ongoing health signal belongs to
// #45/#46, not this road.
func runReadinessCheck(ctx context.Context, cfg readinessConfig, log *slog.Logger) {
	confPath := cfg.ConfPath
	if confPath == "" {
		confPath = readiness.DefaultConfPath
	}

	ports, err := readiness.ModulePorts(confPath)
	if err != nil {
		log.Warn(fmt.Sprintf("readiness: could not read OpenCanary's configuration, skipping the startup check: %s", safeErr(err)))
		return
	}
	if len(ports) == 0 {
		return
	}

	up := make(map[string]bool, len(ports))
	deadline := time.Now().Add(cfg.Window)
	for {
		pending := make(map[string]int, len(ports)-len(up))
		for module, port := range ports {
			if !up[module] {
				pending[module] = port
			}
		}

		for _, r := range readiness.Check(ctx, readiness.Dial, cfg.Host, pending, cfg.DialTimeout) {
			if r.Up {
				up[r.Module] = true
			}
		}

		if len(up) == len(ports) || ctx.Err() != nil || !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(cfg.PollEvery):
		}
	}

	for module, port := range ports {
		if up[module] {
			continue
		}
		log.Warn(fmt.Sprintf(
			"readiness: module %q is enabled in opencanary.conf but nothing answered on port %d "+
				"after %s -- it may have failed to start; OpenCanary logs its own reason for this "+
				"above, at the same level as every module that started cleanly, which is why this "+
				"check exists (#65)",
			module, port, cfg.Window))
	}
}
