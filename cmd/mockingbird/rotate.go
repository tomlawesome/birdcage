package main

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var rotationLog = logging.New("rotation")

const (
	// rotationInterval is how often the agent asks birdcage to rotate
	// its token, after an initial rotation at startup. [contested]: #48's
	// process-composition note marks this cadence unratified -- "#32's
	// ~25h alarm implies daily, but 'daily' is the only ratified word."
	// 24h is the daily reading of that word.
	rotationInterval = 24 * time.Hour
	// rotationRetryInterval is how soon a failed rotation (a retryable
	// transport error, or a disk write failure) is retried, instead of
	// waiting the full rotationInterval. [contested], same note.
	rotationRetryInterval = 15 * time.Minute
)

// runRotationLoop rotates the agent's token once at startup, then every
// rotationInterval, retrying sooner on failure. Rotating on start rather
// than persisting a last-rotation timestamp is deliberate (#48's
// process-composition note): it is clock-free, which matters on a
// canary that may lack NTP; it clears a stale ~25h rotation-stalled
// alarm promptly after a long downtime; and its cost -- an extra mint
// during a crash loop -- is bounded by systemd's own restart backoff.
//
// Rotation is single-flight: this is TokenStore's only writer, so no
// other loop can swap the token underneath a request this loop makes --
// unlike heartbeat and the command poll a later slice adds, this loop
// does not need authedRetry's re-check-and-retry (see rotate below).
//
// All timing here is time.Timer, which the Go runtime drives from its
// monotonic clock, never wall time -- #48's hard constraint that no
// agent cadence may evaluate wall-clock time, since canary boxes may
// have no NTP and the wall clock can step backwards.
func runRotationLoop(ctx context.Context, c *client.Client, ts *TokenStore) {
	timer := time.NewTimer(0) // rotate immediately on start
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(rotate(ctx, c, ts))
		}
	}
}

// rotate performs one rotation attempt and returns how long to wait
// before the next one. The invariant throughout is #48 decision 4's:
// "never send any request with a token that is not durably on disk."
// Three crash windows, none of which locks the agent out:
//
//  1. Mint (c.RotateToken). Minting alone revokes nothing -- #32:
//     revocation happens only at the new token's first use -- so a crash
//     here, or a mint failure, leaves the old token fully valid and in
//     use; the never-minted or never-written token simply never exists
//     to matter.
//  2. Write the new token to disk, atomically, 0600, before it is used
//     for anything (writeFileAtomic). A crash here, or a write failure,
//     leaves the old token in TokenStore and on disk untouched --
//     writeFileAtomic never touches the destination path on failure --
//     so rotate reports the retry interval and the next attempt mints
//     again. The orphaned minted token dies at the next completed
//     rotation (#32's orphan rule); nothing here needs to tell birdcage
//     to forget it.
//  3. Swap (ts.set), only once the write above has returned nil. A crash
//     between the write succeeding and this swap running is also safe
//     without any special handling: the new token is already durable on
//     disk, and the *next* process start reads it back via
//     loadTokenStore -- exactly the value this rotation would have
//     swapped in, just one restart later.
func rotate(ctx context.Context, c *client.Client, ts *TokenStore) time.Duration {
	current := ts.Current()

	newToken, err := c.RotateToken(ctx, current)
	if err != nil {
		if client.IsUnauthorized(err) {
			// Rotation is single-flight and owns the only writer of
			// TokenStore, so there is no concurrently-swapped token to
			// re-check for the way authedRetry does for other loops:
			// a 401 here always means the current token itself is
			// refused. Log loudly and keep every other loop running --
			// the agent never invents a path back to a token mint;
			// recovery is re-enrolment (#47).
			rotationLog.Warn("token unauthorized -- this canary has no channel to birdcage; recovery is re-enrolment (#47)")
			return rotationInterval
		}
		rotationLog.Warn(fmt.Sprintf("mint failed, keeping current token: %s", safeErr(err)))
		return rotationRetryInterval
	}

	if err := writeFileAtomic(ts.path, []byte(newToken), 0o600); err != nil {
		// #48: "A write failure discards the new token unused and keeps
		// the old." newToken is never presented to birdcage, so it is
		// simply never used and expires unused at the next completed
		// rotation -- nothing here needs to revoke it. safeErr:
		// writeFileAtomic's own error wraps ts.path, which lives inside
		// StateDir -- one of the values this agent must never log (see
		// safelog.go).
		rotationLog.Warn(fmt.Sprintf("write new token to disk failed, keeping current token: %s", safeErr(err)))
		return rotationRetryInterval
	}

	ts.set(newToken)
	rotationLog.Info("token rotated")
	return rotationInterval
}
