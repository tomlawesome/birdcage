package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/tomlawesome/birdcage/internal/agent/portscan"
	"github.com/tomlawesome/birdcage/internal/logging"
)

// Environment variables the port-scan road reads. All three are
// optional, which is why they are here rather than in config.go's
// fail-closed required set: a canary with none of them set runs
// detection with the shipped defaults, and #48 decision 1's "a
// half-credentialed agent must never half-run" is about credentials, not
// about a detector that has a working default for every input.
const (
	// envPortscan turns detection off when set to "0". Anything else,
	// including unset, leaves it on. One switch, no levels: an operator
	// on a segment where this is too noisy wants it off, and
	// envPortscanIgnorePorts is the dial for everything short of that.
	envPortscan = "MOCKINGBIRD_PORTSCAN"

	// envPortscanIgnorePorts is a comma-separated list of additional
	// ports to treat as ours, on top of whatever OpenCanary's own
	// configuration says it is listening on. For the cases that
	// configuration cannot cover: something else in the container's
	// network namespace answering on a port, or a monitoring probe that
	// would otherwise read as a sweep.
	envPortscanIgnorePorts = "MOCKINGBIRD_PORTSCAN_IGNORE_PORTS"

	// envOpenCanaryConf is OpenCanary's configuration file, read once at
	// startup for the listening-port set and the node id. Defaults to
	// portscan.DefaultConfPath, which is where build/mockingbird/
	// Dockerfile puts it; an operator who bind-mounts their own
	// configuration somewhere else points this at it.
	envOpenCanaryConf = "MOCKINGBIRD_OPENCANARY_CONF"
)

// agentInventory is the small set of startup facts this binary states
// about itself in its log.
//
// Not the boot inventory cmd/birdcage prints: this process runs on the
// honeypot, and this package's doc comment is explicit that a
// configuration inventory there would hand an attacker the state
// directory, log path and listen address. Nothing in here is one of
// those. PortscanActive is a single boolean about whether a defence is
// running, which an attacker learns anyway the moment they scan the box
// and either are or are not caught -- while an operator who cannot see
// it has no way to tell a quiet segment from a missing capability.
type agentInventory struct {
	// PortscanActive is whether the capture socket opened. False means
	// port-scan detection is off for this run, for the reason logged
	// beside it.
	PortscanActive bool

	// ListeningPorts is how many ports the detector treats as ours and
	// so never counts towards a scan. The count only -- never the list,
	// which would be a map of where to look on a box whose stdout an
	// attacker can read.
	ListeningPorts int
}

// line renders the inventory as the single startup line main prints.
func (inv agentInventory) line() string {
	if !inv.PortscanActive {
		return "port-scan detection off"
	}
	return fmt.Sprintf("port-scan detection active, %d ports treated as listening", inv.ListeningPorts)
}

// portscanEnabled reports whether the port-scan road should run at all.
func portscanEnabled() bool { return os.Getenv(envPortscan) != "0" }

// parseIgnorePorts reads envPortscanIgnorePorts' comma list. Anything
// that is not a port number is skipped with a warning rather than
// failing startup: a typo in an optional tuning variable should not take
// the honeypot down, and skipping it silently would be worse than
// noisily. The offending text is operator-supplied and goes through
// logging.Printable, since everything this binary prints can end up in
// a terminal an attacker also reads.
func parseIgnorePorts(raw string, log *slog.Logger) []uint16 {
	var ports []uint16
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		n, err := strconv.Atoi(field)
		if err != nil || n < 1 || n > 65535 {
			log.Warn(fmt.Sprintf("ignoring unusable entry in %s: %q", envPortscanIgnorePorts, logging.Printable(field)))
			continue
		}
		ports = append(ports, uint16(n))
	}
	return ports
}

// listenPort is the agent's own loopback receiver port, pulled out of
// cfg.Listen so the detector treats it as ours. OpenCanary posts every
// webhook to it over loopback; without this, the agent's own receiver
// would be one of the ports it reports scans against. The address itself
// is never logged (see this package's doc comment) -- an unparseable one
// just yields no extra port, and the receiver's own bind has already
// failed loudly by then anyway.
func listenPort(listen string) (uint16, bool) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

// newPortscanRoad builds the port-scan detector and opens its capture
// socket, returning the detector to run (nil if detection is off) and
// what the startup inventory should say about it.
//
// It never returns an error. Detection being unavailable is a running
// condition to report, not a reason to refuse to be a honeypot -- the
// same call #48 already makes for an unreadable log file, and for the
// same reason: a canary that will not start reports nothing at all,
// which is strictly worse than one that reports hits on its emulated
// services but misses a sweep of closed ports.
func newPortscanRoad(cfg Config, in *Intake, log *slog.Logger) (*portscan.Detector, agentInventory) {
	if !portscanEnabled() {
		// No line of its own: the inventory line main prints already
		// says detection is off, and the operator who set the variable
		// does not need telling twice.
		return nil, agentInventory{PortscanActive: false}
	}

	ignore := parseIgnorePorts(os.Getenv(envPortscanIgnorePorts), log)
	if port, ok := listenPort(cfg.Listen); ok {
		ignore = append(ignore, port)
	}

	detector, warning := portscan.New(portscan.Config{
		ConfPath:         os.Getenv(envOpenCanaryConf),
		ExtraIgnorePorts: ignore,
	}, in.SubmitPortscanEvent, log)
	if warning != "" {
		log.Warn(warning)
	}

	if err := detector.Open(); err != nil {
		// The one WARN #65 requires: what is off, and why, in terms an
		// operator can act on. safeErr because this is the honeypot's
		// own stdout -- the socket error carries no path today, but a
		// future wrapping of it could.
		log.Warn(fmt.Sprintf(
			"port-scan detection is OFF: %s. Run the container with --cap-add NET_RAW "+
				"(and use an image whose binary carries cap_net_raw) to turn it on -- see "+
				"docs/enrolment.md. Hits on emulated services are still reported; a sweep of "+
				"closed ports is not.",
			safeErr(err)))
		return nil, agentInventory{PortscanActive: false}
	}

	return detector, agentInventory{PortscanActive: true, ListeningPorts: detector.ListeningPorts()}
}

// runPortscanRoad watches for scans until ctx is done. A nil detector --
// detection off, for either reason above -- makes this a no-op, so main
// starts the same goroutine either way rather than branching around it.
func runPortscanRoad(ctx context.Context, detector *portscan.Detector, log *slog.Logger) {
	if detector == nil {
		return
	}
	if err := detector.Run(ctx); err != nil {
		log.Warn(fmt.Sprintf("port-scan detection stopped: %s", safeErr(err)))
	}
}
