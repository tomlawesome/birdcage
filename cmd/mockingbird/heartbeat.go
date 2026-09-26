package main

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
	"github.com/tomlawesome/birdcage/internal/agent/renewal"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var heartbeatLog = logging.New("heartbeat")

// heartbeatInterval matches the server's per-canary HeartbeatIntervalS
// default of 60s (#48's process-composition note: "that value is
// server-side data, but no channel delivers it to the agent today -- a
// future #46 concern, not local config").
const heartbeatInterval = 60 * time.Second

// selfReportFunc builds the SelfReport to send on the next heartbeat.
// A function rather than a fixed value or a struct held by this loop
// because the later slice that wires the queue, tailer and ledger needs
// to plug in the real queue depth, log-read status and counters without
// changing this loop at all -- see main.go's currentSelfReport, this
// slice's honest stand-in.
type selfReportFunc func() client.SelfReport

// runHeartbeatLoop sends the agent's self-report immediately, then every
// heartbeatInterval (#48 item 6, decision 4's cadence), on a
// time.Ticker -- monotonic, per #48's hard constraint that no agent
// cadence may evaluate wall-clock time. Each tick also drives one
// certificate-renewal check (runRenewalTick, ADR-0012 B2: "on every
// heartbeat tick") -- sharing this loop's cadence rather than running a
// separate ticker, since both are meant to fire together and neither
// needs finer timing than the other.
//
// 401 handling is this loop's instance of decision 4's uniform rule,
// via authedRetry: on ErrUnauthorized, re-check the token store in case
// rotation swapped the token underneath this request, and retry once. If
// the current token itself is refused, log loudly and move on to the
// next tick rather than stopping -- the agent never invents a path back
// to a token mint (recovery is re-enrolment, #47), and a persistent 401
// here is exactly the signal #45's token-conflict state reads.
func runHeartbeatLoop(ctx context.Context, c *client.Client, ts *TokenStore, rm *renewal.Manager, report selfReportFunc, settings *agentSettings, detector *poisoner.Detector) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	sendHeartbeat(ctx, c, ts, report, settings, detector)
	runRenewalTick(ctx, rm, c, ts)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendHeartbeat(ctx, c, ts, report, settings, detector)
			runRenewalTick(ctx, rm, c, ts)
		}
	}
}

// sendHeartbeat sends one self-report, applying authedRetry's uniform
// 401 handling. Any other failure (a *client.RetryableError, or a
// transport error) is logged and left for the next tick, matching #32's
// own transport semantics: a heartbeat birdcage never saw simply means
// its last-seen doesn't advance until the next one lands.
//
// Issue #124: report.SettingsHash is set from settings' own record
// before sending, and whatever birdcage pushes back is validated and
// applied to detector immediately, live -- within this same heartbeat,
// not the next one. detector may be nil (the poisoner road off, or its
// Open never succeeded); settings.Apply below only ever calls it when it
// is not, since a nil *poisoner.Detector boxed into the liveSettable
// interface would not compare equal to a nil interface.
func sendHeartbeat(ctx context.Context, c *client.Client, ts *TokenStore, report selfReportFunc, settings *agentSettings, detector *poisoner.Detector) {
	sr := report()
	if settings != nil {
		sr.SettingsHash = settings.Hash()
	}

	pushed, err := authedRetryValue(ts, func(token string) (map[string]string, error) {
		return c.SendHeartbeat(ctx, token, sr)
	})
	if err != nil {
		if client.IsUnauthorized(err) {
			heartbeatLog.Warn("token unauthorized -- this canary has no channel to birdcage; recovery is re-enrolment (#47)")
			return
		}
		heartbeatLog.Warn(fmt.Sprintf("send failed, will retry next cycle: %s", safeErr(err)))
		return
	}
	if len(pushed) == 0 || settings == nil {
		return
	}
	if detector == nil {
		heartbeatLog.Warn("birdcage pushed settings for a canary with no poisoner detector running; nothing to apply them to")
		return
	}
	settings.Apply(pushed, detector, heartbeatLog)
}
