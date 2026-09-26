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

	if len(up) == len(ports) {
		// Issue #47 step 7: the agent's own "I believe I am ready"
		// signal -- every module opencanary.conf enables answered before
		// the deadline. Logged only, never sent to birdcage: the wire
		// shape this signal would ride (client.SelfReport, the heartbeat
		// body) already carries a narrower field (LogReadOK) for a
		// different check, and adding a new one is a larger change than
		// this slice's "keep it small" -- birdcage does not trust this
		// line in any case (#47's own "does not take its word for it"),
		// so the operator reading container logs is this signal's only
		// audience. See this build's report.
		log.Info(fmt.Sprintf("readiness: every enabled module answered within %s -- agent believes it is ready (#47)", cfg.Window))
		return
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

// openCanaryProbe is issue #132's own addition: OpenCanary now runs in
// its own container, so the agent can no longer tell it died by
// noticing a child process exit (#69, superseded by this container
// split) -- it dials OpenCanary's own configured ports on their shared
// network namespace once per heartbeat instead, the same
// internal/agent/readiness dial runReadinessCheck's boot-time pass
// above already uses, just one pass rather than polled to a deadline:
// a heartbeat tick is itself the retry, 60s later.
//
// Its module list is read once, at construction, matching how
// newPortscanRoad and newSNMPRoad read opencanary.conf once at startup
// rather than on every road tick -- the configuration this image ships
// with does not change while the container runs.
type openCanaryProbe struct {
	cfg   readinessConfig
	ports map[string]int // nil if opencanary.conf could not be read
	log   *slog.Logger
	down  bool // last-reported state, so a log line prints only on change
}

// udpOnlyModules are OpenCanary modules whose protocol is UDP, reused
// from readiness.ModulePorts' own port map even though nothing here can
// verify them: internal/agent/readiness.Dial always dials "tcp" (see its
// own doc comment and Check's call site), which the boot-time readiness
// check already tolerates as a soft false-positive -- runReadinessCheck
// logs "may have failed to start" for sip and tftp on every boot,
// verified against opencanary.conf's own shipped defaults, and that WARN
// gates nothing. It cannot be tolerated here: this probe's result drives
// a dashboard alert (StateOpenCanaryDown), and a module this probe can
// never actually confirm would make that alert permanently, falsely,
// active. So these modules are excluded from what this probe requires to
// call OpenCanary "up" -- reproduced directly (2026-09-26): with sip and
// tftp counted, every heartbeat reported OpenCanary down regardless of
// whether it was actually running, because a plain TCP dial against a
// UDP-only port is always refused.
//
// Named explicitly, not derived from opencanary.conf (which carries no
// protocol field for readiness.ModulePorts to read), against upstream
// OpenCanary's own module implementations: sip.py and tftp.py both bind
// SOCK_DGRAM. ntp, snmp and llmnr are also UDP upstream but ship disabled
// in build/opencanary/opencanary.conf; listed anyway so enabling one
// later does not reintroduce this same false alarm silently.
var udpOnlyModules = map[string]bool{
	"sip":   true,
	"tftp":  true,
	"ntp":   true,
	"snmp":  true,
	"llmnr": true,
}

// newOpenCanaryProbe builds the probe, logging once if opencanary.conf
// could not be read -- from then on Probe always returns nil, the same
// "no opinion" this package's other roads give when their own
// configuration read fails.
func newOpenCanaryProbe(cfg readinessConfig, log *slog.Logger) *openCanaryProbe {
	confPath := cfg.ConfPath
	if confPath == "" {
		confPath = readiness.DefaultConfPath
	}
	allPorts, err := readiness.ModulePorts(confPath)
	if err != nil {
		log.Warn(fmt.Sprintf("opencanary probe: could not read OpenCanary's configuration, reporting no opinion: %s", safeErr(err)))
		return &openCanaryProbe{cfg: cfg, log: log}
	}
	ports := make(map[string]int, len(allPorts))
	for module, port := range allPorts {
		if udpOnlyModules[module] {
			continue
		}
		ports[module] = port
	}
	return &openCanaryProbe{cfg: cfg, ports: ports, log: log}
}

// Probe dials every configured module port once and reports whether all
// of them answered. nil means no opinion -- opencanary.conf could not be
// read, or names no port at all -- which client.SelfReport.OpenCanaryUp
// and, downstream, canaries.agent_opencanary_up must keep distinct from
// an explicit false (internal/store/health.go's openCanaryDown).
//
// Not safe for concurrent use: called once per heartbeat tick, from the
// same goroutine that builds the rest of the self-report (main.go's
// report() closure), so p.down needs no lock.
func (p *openCanaryProbe) Probe(ctx context.Context) *bool {
	if len(p.ports) == 0 {
		return nil
	}
	results := readiness.Check(ctx, readiness.Dial, p.cfg.Host, p.ports, p.cfg.DialTimeout)
	up := true
	var down []string
	for _, r := range results {
		if !r.Up {
			up = false
			down = append(down, fmt.Sprintf("%s:%d(%v)", r.Module, r.Port, r.Err))
		}
	}
	if !up && !p.down {
		p.log.Warn(fmt.Sprintf("opencanary: not answering on %v -- reporting it down on the next heartbeat (#132)", down))
	}
	if up && p.down {
		p.log.Info("opencanary: answering again")
	}
	p.down = !up
	return &up
}
