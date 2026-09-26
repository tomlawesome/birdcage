package main

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
)

// The wire key names issue #124's settings block uses -- internal/store's
// own CanarySettingKey constants, duplicated rather than imported: an
// agent binary must never import internal/store (ADR-0008 decision 4).
// Keep the two lists in lockstep.
const (
	settingSegmentProfile = "segment_profile"
	settingBaitNames      = "bait_names"
	settingPaceFloor      = "pace_floor"
	settingPaceCeiling    = "pace_ceiling"
	settingWorkingHours   = "working_hours"
)

// settingMaxValueLen mirrors internal/store's own
// canarySettingMaxValueLen: a second, agent-side cap on an untrusted
// push, per issue #124's own security point ("cap sizes") -- birdcage
// already enforces this at the write, but this agent must never trust
// that birdcage did.
const settingMaxValueLen = 512

// liveSettable is the one poisoner.Detector method agentSettings needs,
// as an interface so a test can fake it without opening real sockets.
type liveSettable interface {
	SetLiveSettings(profile poisoner.Profile, operatorNames poisoner.Names, pace poisoner.PaceSettings)
}

// agentSettings is this process' own record of what birdcage has pushed
// and this agent has validated and applied (issue #124) -- separate from
// the MOCKINGBIRD_POISONER_* environment variables, which remain this
// agent's fallback for exactly as long as birdcage has never pushed a
// setting (poisoner.go's poisonerSettings, cfg below, is that fallback,
// read once at startup).
//
// effective is exactly what the last successful push contained, key for
// key -- never the environment's own values, so Hash() reports "" (never
// pushed to) until the first push lands, matching birdcage's own
// contract that it never even compares a hash for a canary it holds no
// settings for. profile/names/pace are the live-applied typed values, kept
// across calls so a push naming only one key (e.g. just segment_profile)
// leaves the others exactly as they were rather than reverting them to
// cfg's own startup values.
//
// A key that birdcage's push omits is left exactly as this agent last
// had it (never reverted to the environment default): canary_settings
// rows are never deleted in this design, so an omitted key is not a
// state this agent should ever actually see.
type agentSettings struct {
	mu        sync.Mutex
	effective map[string]string
	profile   poisoner.Profile
	names     poisoner.Names
	pace      poisoner.PaceSettings
}

// newAgentSettings seeds live state from cfg -- the exact Config
// poisonerSettings() built and poisoner.New() was constructed with, so
// this record starts in agreement with the detector rather than
// recomputing defaults a second way.
func newAgentSettings(cfg poisoner.Config) *agentSettings {
	return &agentSettings{
		effective: map[string]string{},
		profile:   cfg.Profile,
		names:     cfg.OperatorNames,
		pace:      cfg.Pace,
	}
}

// Hash is this heartbeat's settings_hash: client.SettingsHash over
// exactly what birdcage has successfully pushed and this agent applied.
// Empty when nothing has ever been pushed -- the ordinary state for a
// canary running on its environment variables alone.
func (a *agentSettings) Hash() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.effective) == 0 {
		return ""
	}
	return client.SettingsHash(a.effective)
}

// Apply validates pushed (birdcage's heartbeat response, issue #124)
// against exactly the parsers the environment-variable path already uses
// (poisoner.ParseProfile/ParseNames/ParseWorkingHours, a positive
// time.Duration for the pace bounds), applies every key that validates
// to detector with no restart, and records it in effective so the next
// heartbeat's hash reflects it. A key outside the closed set above, or a
// value that fails validation or the size cap, is logged and left
// exactly as this agent had it -- pushed is untrusted input on this
// side, per issue #124's own security point, regardless of what birdcage
// itself already validated before storing it.
func (a *agentSettings) Apply(pushed map[string]string, detector liveSettable, log *slog.Logger) {
	if detector == nil || len(pushed) == 0 {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	changed := false
	for key, value := range pushed {
		if len(value) > settingMaxValueLen {
			log.Warn(fmt.Sprintf("birdcage pushed a %q value of %d bytes, more than the %d-byte limit; ignoring it", key, len(value), settingMaxValueLen))
			continue
		}
		switch key {
		case settingSegmentProfile:
			profile, err := poisoner.ParseProfile(value)
			if err != nil {
				log.Warn(fmt.Sprintf("birdcage pushed an invalid %s: %v; leaving the current profile in force", key, err))
				continue
			}
			a.profile = profile
		case settingBaitNames:
			var names poisoner.Names
			if value != "" {
				parsed, refused, err := poisoner.ParseNames(value)
				if err != nil || refused > 0 {
					log.Warn(fmt.Sprintf("birdcage pushed %d unusable bait name(s); leaving the current names in force", refused))
					continue
				}
				names = parsed
			}
			a.names = names
		case settingPaceFloor:
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				log.Warn(fmt.Sprintf("birdcage pushed an invalid %s; leaving the current pace floor in force", key))
				continue
			}
			a.pace.FloorGap = d
		case settingPaceCeiling:
			d, err := time.ParseDuration(value)
			if err != nil || d <= 0 {
				log.Warn(fmt.Sprintf("birdcage pushed an invalid %s; leaving the current pace ceiling in force", key))
				continue
			}
			a.pace.CeilingGap = d
		case settingWorkingHours:
			hours, err := poisoner.ParseWorkingHours(value)
			if err != nil {
				log.Warn(fmt.Sprintf("birdcage pushed an invalid %s: %v; leaving the current working hours in force", key, err))
				continue
			}
			a.pace.Hours = hours
		default:
			log.Warn(fmt.Sprintf("birdcage pushed an unknown setting %q; ignoring it", key))
			continue
		}
		a.effective[key] = value
		changed = true
	}

	if !changed {
		return
	}
	detector.SetLiveSettings(a.profile, a.names, a.pace)
}
