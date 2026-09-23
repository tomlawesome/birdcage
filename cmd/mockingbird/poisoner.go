package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
)

// Environment variables the poisoner road reads (issue #86). All
// optional, the same shape portscan.go's and snmp.go's are: a canary with
// none of them set runs with the shipped defaults.
//
// They live here rather than in config.go for the reason that file states
// -- its fail-closed required set is about credentials, and #48 decision
// 1's "a half-credentialed agent must never half-run" does not extend to
// a detector with a working default for every input.
//
// Issue #86 design point 3 asks for these to be per-canary settings
// "changeable without a release", and point 7 for the profile to be
// changeable from the canary page. These variables deliver the first:
// an operator changes one and restarts the container. They do not deliver
// the second -- birdcage has no channel that pushes a setting to an agent
// at all today (heartbeat and command-poll responses carry none), so the
// canary page cannot change one. See docs/configuration.md.
const (
	// envPoisoner turns the whole road off when set to "0", sockets
	// included. Anything else, including unset, leaves it on -- one
	// switch, no levels, the same reasoning envPortscan states.
	//
	// Not the same as the "off" profile: "off" stops the bait queries and
	// keeps the receive-only sockets counting the segment's own query
	// rate (decision 41: the pace-matcher runs in all three profiles),
	// which is what a later change to a sending profile would be paced
	// by. This turns everything off, including the counting.
	envPoisoner = "MOCKINGBIRD_POISONER"

	// envPoisonerNames is the operator's own two or three bait names, as
	// a comma-separated list -- a retired file server, a printer that was
	// moved (decision 31). Unset means the agent derives neighbours of
	// its own hostname instead. No name ships in the code, so nothing is
	// greppable in the binary.
	envPoisonerNames = "MOCKINGBIRD_POISONER_NAMES"

	// envPoisonerProfile is the segment profile: "windows" (the default,
	// all three protocols), "linux" (LLMNR and mDNS only, shaped like
	// systemd-resolved and Avahi) or "off" (no bait queries).
	envPoisonerProfile = "MOCKINGBIRD_POISONER_PROFILE"

	// envPoisonerFloor is the longest gap between bursts during working
	// hours, as a Go duration ("2h"). The shipped default is provisional
	// -- #121 replaces it with a measured value.
	envPoisonerFloor = "MOCKINGBIRD_POISONER_FLOOR"

	// envPoisonerCeiling is the shortest gap between bursts ("30m").
	// Provisional in the same way.
	envPoisonerCeiling = "MOCKINGBIRD_POISONER_CEILING"

	// envPoisonerHours is when the canary asks anything at all, in its own
	// timezone: "08:00-18:00", optionally with a day list
	// ("06:00-22:00/Mon,Tue,Wed,Thu,Fri,Sat"). A workstation asks for
	// names when somebody is using it, so a host asking at three in the
	// morning is the odd one out on the segment.
	envPoisonerHours = "MOCKINGBIRD_POISONER_HOURS"
)

// poisonerInventory is what this road states about itself at startup --
// the same shape as agentInventory and snmpInventory, and under the same
// rule: no bait name, ever, and no count of them either fine-grained
// enough to narrow a guess. An attacker who reads this box's stdout learns
// that the detector is running, which they learn anyway the moment they
// run Responder and get caught.
type poisonerInventory struct {
	// Active is whether anything opened at all.
	Active bool

	// Profile is the segment profile in force.
	Profile poisoner.Profile

	// Sending is whether bait queries actually go out. False for the
	// "off" profile, and on a container with no segment to ask on.
	Sending bool

	// Counting is how many of the three ports the pace-matcher bound.
	Counting int
}

// line renders the inventory as the single startup line main prints.
func (inv poisonerInventory) line() string {
	if !inv.Active {
		return "poisoner detection off"
	}
	if !inv.Sending {
		return fmt.Sprintf("poisoner detection listening only (profile %s), counting %d of 3 ports", inv.Profile, inv.Counting)
	}
	return fmt.Sprintf("poisoner detection active (profile %s), counting %d of 3 ports", inv.Profile, inv.Counting)
}

// poisonerEnabled reports whether the poisoner road should run at all.
func poisonerEnabled() bool { return os.Getenv(envPoisoner) != "0" }

// poisonerSettings reads the six environment variables into the
// detector's configuration.
//
// A setting that does not parse is a warning and a fall back to the
// default, not a startup failure: the same call parseIgnorePorts makes in
// portscan.go, and for the same reason -- a typo in an optional tuning
// variable should not take the honeypot down. The one thing the warnings
// never contain is a bait name, so envPoisonerNames' own failure is
// reported as a count.
func poisonerSettings() (poisoner.Config, []string) {
	var warnings []string
	cfg := poisoner.Config{
		ConfPath: os.Getenv(envOpenCanaryConf),
		Pace:     poisoner.DefaultPaceSettings(),
	}

	profile, err := poisoner.ParseProfile(os.Getenv(envPoisonerProfile))
	if err != nil {
		warnings = append(warnings, fmt.Sprintf(
			"%s is not one of windows, linux or off, so the default profile is in use: %v", envPoisonerProfile, err))
		profile = poisoner.DefaultProfile
	}
	cfg.Profile = profile

	if raw := os.Getenv(envPoisonerNames); raw != "" {
		names, refused, err := poisoner.ParseNames(raw)
		switch {
		case err != nil:
			// Every name was unusable, so there is nothing to use. The
			// error states the rule and the count; it never quotes a
			// name back, and neither does this.
			warnings = append(warnings, fmt.Sprintf(
				"no usable bait name in %s, so names are derived from this canary's hostname instead: %v",
				envPoisonerNames, err))
		case refused > 0:
			warnings = append(warnings, fmt.Sprintf(
				"%d entr%s in %s could not be used and %s ignored; a bait name is 1 to 15 characters of letters, digits and hyphens, not starting or ending with a hyphen, and at most 3 are used",
				refused, plural(refused, "y", "ies"), envPoisonerNames, plural(refused, "was", "were")))
			cfg.OperatorNames = names
		default:
			cfg.OperatorNames = names
		}
	}

	if gap, ok := poisonerDuration(envPoisonerFloor, &warnings); ok {
		cfg.Pace.FloorGap = gap
	}
	if gap, ok := poisonerDuration(envPoisonerCeiling, &warnings); ok {
		cfg.Pace.CeilingGap = gap
	}

	if raw := os.Getenv(envPoisonerHours); raw != "" {
		hours, err := poisoner.ParseWorkingHours(raw)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"%s is not of the form HH:MM-HH:MM, so the default working hours are in use: %v", envPoisonerHours, err))
		} else {
			cfg.Pace.Hours = hours
		}
	}

	return cfg, warnings
}

// poisonerDuration reads one duration variable, reporting an unusable
// value rather than failing startup over it.
func poisonerDuration(name string, warnings *[]string) (time.Duration, bool) {
	raw := os.Getenv(name)
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		*warnings = append(*warnings, fmt.Sprintf(
			"%s is not a positive duration such as \"2h\", so the default is in use", name))
		return 0, false
	}
	return d, true
}

// plural picks between two words for a count, so the warnings above read
// as English rather than as "1 entries were".
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// newPoisonerRoad builds the poisoner detector and opens its sockets,
// returning the detector to run (nil if the road is off) and what the
// startup inventory should say about it.
//
// It never returns an error, the same contract newPortscanRoad and
// newSNMPRoad state: detection being unavailable is a running condition to
// report, not a reason to refuse to be a honeypot.
func newPoisonerRoad(in *Intake, log *slog.Logger) (*poisoner.Detector, poisonerInventory) {
	if !poisonerEnabled() {
		return nil, poisonerInventory{Active: false}
	}

	cfg, warnings := poisonerSettings()
	detector, more := poisoner.New(cfg, in.SubmitPoisonerEvent, log)
	for _, w := range append(warnings, more...) {
		log.Warn(w)
	}

	openWarnings, err := detector.Open()
	for _, w := range openWarnings {
		log.Warn(w)
	}
	if err != nil {
		// The one WARN this road owes an operator when nothing at all
		// opened: what is off, and why, in terms they can act on.
		// safeErr because this is the honeypot's own stdout.
		log.Warn(fmt.Sprintf(
			"poisoner detection is OFF: %s. Ports 137, 5353 and 5355 are privileged -- the enrolment "+
				"command already runs this container with --sysctl "+
				"net.ipv4.ip_unprivileged_port_start=0, which is what makes binding them work without "+
				"root. Without it, a poisoner on this segment is not caught.",
			safeErr(err)))
		return nil, poisonerInventory{Active: false}
	}

	return detector, poisonerInventory{
		Active:   true,
		Profile:  detector.Profile(),
		Sending:  detector.CanSend(),
		Counting: detector.Listening(),
	}
}

// runPoisonerRoad asks and listens until ctx is done. A nil detector --
// the road off, or nothing opened -- makes this a no-op, so main starts
// the same goroutine either way rather than branching around it.
func runPoisonerRoad(ctx context.Context, detector *poisoner.Detector, log *slog.Logger) {
	if detector == nil {
		return
	}
	if err := detector.Run(ctx); err != nil {
		log.Warn(fmt.Sprintf("poisoner detection stopped: %s", safeErr(err)))
	}
}
