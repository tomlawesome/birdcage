// heartbeat.go adds the common heartbeat loop issue #106 requires of
// every agent kind (ADR-0009: "the small common part -- agent version,
// last contact -- is shared; the rest belongs to the kind"). #108's own
// scope note deferred exactly this loop to #106's split: a scanner has
// nothing honest to say about queue depth or log-read status, and the
// common shape (internal/agent/client.CommonHeartbeat) asks it for
// neither.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/renewal"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var heartbeatLog = logging.New("heartbeat")

// heartbeatInterval matches cmd/mockingbird's own constant: the server's
// per-canary HeartbeatIntervalS default (60s) -- no channel delivers
// that value to the agent today, cmd/mockingbird/heartbeat.go's own
// comment records the same gap.
const heartbeatInterval = 60 * time.Second

// runHeartbeatLoop sends the common heartbeat immediately, then every
// interval (heartbeatInterval in production; a test passes something
// short, the same reason runScanLoop takes its interval as a parameter),
// on a time.Ticker -- monotonic, per #48's hard
// constraint that no agent cadence may evaluate wall-clock time, which
// this loop inherits rather than re-deciding.
//
// Unlike cmd/mockingbird's own heartbeat loop, there is no TokenStore and
// no authedRetry here: this binary mints no rotation loop at all
// (cmd/nightjar/token.go's own doc comment -- token is the one value
// this process ever presents, for its whole lifetime). A persistent 401
// is logged and left for the next tick; the agent never invents a path
// back to a token mint, and recovery is re-enrolment (#47), the same
// stance every agent takes on its own dead credential.
func runHeartbeatLoop(ctx context.Context, c *client.Client, token string, rm *renewal.Manager, version string, interval time.Duration, dbTracker *dbRefreshTracker, runTracker *currentRunTracker) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sendHeartbeat(ctx, c, token, version, dbTracker, runTracker)
	runRenewalTick(ctx, rm, c, token)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendHeartbeat(ctx, c, token, version, dbTracker, runTracker)
			runRenewalTick(ctx, rm, c, token)
		}
	}
}

// sendHeartbeat sends one common heartbeat. Any failure -- unauthorized,
// a *client.RetryableError, or a transport error -- is logged and left
// for the next tick, matching runScanOnce's own "log and continue"
// stance: a heartbeat birdcage never saw simply means its last-seen
// doesn't advance until the next one lands.
//
// dbTracker and runTracker may be nil (every production call passes
// both; tests exercising only the plain heartbeat shape, like this
// file's own TestSendHeartbeatPostsCommonShapeOnly, pass neither) --
// dbRefreshReportIfFailing already treats a nil tracker as healthy, and
// runTracker.get() on a nil *currentRunTracker would panic, so this
// checks it directly.
//
// ADR-0012 decision 9: "[Nightjar] repeats the current stage on every
// ordinary tick until the run is answered" -- runTracker is what makes
// that true here, independent of whichever loop (scan or command) last
// changed it.
func sendHeartbeat(ctx context.Context, c *client.Client, token, version string, dbTracker *dbRefreshTracker, runTracker *currentRunTracker) {
	hb := client.CommonHeartbeat{
		AgentVersion: version,
		DBRefresh:    dbRefreshReportIfFailing(dbTracker),
	}
	if runTracker != nil {
		if runID, stage := runTracker.get(); runID != "" {
			hb.Run = &client.RunReport{RunID: runID, Stage: stage}
		}
	}
	err := c.SendCommonHeartbeat(ctx, token, hb)
	if err == nil {
		return
	}
	if client.IsUnauthorized(err) {
		heartbeatLog.Warn("token unauthorized -- this agent has no channel to birdcage; recovery is re-enrolment (#47)")
		return
	}
	heartbeatLog.Warn(fmt.Sprintf("send failed, will retry next cycle: %s", safeErr(err)))
}
