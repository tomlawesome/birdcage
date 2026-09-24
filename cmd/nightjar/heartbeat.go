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
func runHeartbeatLoop(ctx context.Context, c *client.Client, token string, rm *renewal.Manager, version string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sendHeartbeat(ctx, c, token, version)
	runRenewalTick(ctx, rm, c, token)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendHeartbeat(ctx, c, token, version)
			runRenewalTick(ctx, rm, c, token)
		}
	}
}

// sendHeartbeat sends one common heartbeat. Any failure -- unauthorized,
// a *client.RetryableError, or a transport error -- is logged and left
// for the next tick, matching runScanOnce's own "log and continue"
// stance: a heartbeat birdcage never saw simply means its last-seen
// doesn't advance until the next one lands.
func sendHeartbeat(ctx context.Context, c *client.Client, token, version string) {
	err := c.SendCommonHeartbeat(ctx, token, client.CommonHeartbeat{AgentVersion: version})
	if err == nil {
		return
	}
	if client.IsUnauthorized(err) {
		heartbeatLog.Warn("token unauthorized -- this canary has no channel to birdcage; recovery is re-enrolment (#47)")
		return
	}
	heartbeatLog.Warn(fmt.Sprintf("send failed, will retry next cycle: %s", safeErr(err)))
}
