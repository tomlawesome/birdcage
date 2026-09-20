package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/tomlawesome/birdcage/internal/agent/snmp"
)

// Environment variables the SNMP road reads. Both optional, the same
// shape portscan.go's envPortscan/envPortscanIgnorePorts are: a canary
// with neither set runs detection with the shipped defaults.
const (
	// envSNMP turns the SNMP listener off when set to "0". Anything
	// else, including unset, leaves it on -- one switch, no levels, the
	// same reasoning envPortscan states.
	envSNMP = "MOCKINGBIRD_SNMP"

	// envSNMPListen overrides where the UDP socket binds. Defaults to
	// snmp.DefaultListenAddr (":161", the standard SNMP port and
	// upstream OpenCanary's own default for its own, disabled, snmp
	// module). An operator running this alongside a real SNMP agent on
	// the same host points it elsewhere.
	envSNMPListen = "MOCKINGBIRD_SNMP_LISTEN"
)

// snmpInventory is the one startup fact this road states about itself --
// the same shape as agentInventory in portscan.go, and for the same
// reason (that package's own doc comment: no configuration inventory on
// a box an attacker can read stdout from).
type snmpInventory struct {
	// SNMPActive is whether the UDP socket bound. False means SNMP
	// detection is off for this run, for the reason logged beside it.
	SNMPActive bool
}

// line renders the inventory as the single startup line main prints.
func (inv snmpInventory) line() string {
	if !inv.SNMPActive {
		return "snmp detection off"
	}
	return "snmp detection active"
}

// snmpEnabled reports whether the SNMP road should run at all.
func snmpEnabled() bool { return os.Getenv(envSNMP) != "0" }

// newSNMPRoad builds the SNMP detector and opens its UDP socket,
// returning the detector to run (nil if detection is off) and what the
// startup inventory should say about it. Mirrors newPortscanRoad's
// contract exactly, including never returning an error: a canary that
// will not start reports nothing at all, which is strictly worse than
// one that misses SNMP probes but still reports hits on its emulated
// services.
func newSNMPRoad(in *Intake, log *slog.Logger) (*snmp.Detector, snmpInventory) {
	if !snmpEnabled() {
		return nil, snmpInventory{SNMPActive: false}
	}

	detector, warning := snmp.New(snmp.Config{
		ListenAddr: os.Getenv(envSNMPListen),
		ConfPath:   os.Getenv(envOpenCanaryConf),
	}, in.SubmitSNMPEvent, log)
	if warning != "" {
		log.Warn(warning)
	}

	if err := detector.Open(); err != nil {
		// The one WARN this road owes an operator: what is off, and
		// why, in terms they can act on. safeErr because this is the
		// honeypot's own stdout.
		log.Warn(fmt.Sprintf(
			"snmp detection is OFF: %s. The default port (161) is privileged -- the enrolment "+
				"command already runs this container with --sysctl "+
				"net.ipv4.ip_unprivileged_port_start=0, which is what makes binding it work "+
				"without root; without that sysctl, point %s at an unprivileged port instead.",
			safeErr(err), envSNMPListen))
		return nil, snmpInventory{SNMPActive: false}
	}

	return detector, snmpInventory{SNMPActive: true}
}

// runSNMPRoad watches for SNMP requests until ctx is done. A nil
// detector -- disabled, or the bind failed -- makes this a no-op, so
// main starts the same goroutine either way rather than branching
// around it.
func runSNMPRoad(ctx context.Context, detector *snmp.Detector, log *slog.Logger) {
	if detector == nil {
		return
	}
	if err := detector.Run(ctx); err != nil {
		log.Warn(fmt.Sprintf("snmp detection stopped: %s", safeErr(err)))
	}
}
