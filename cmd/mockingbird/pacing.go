package main

import (
	"context"
	"sync"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// recoveryRequestsPerMinute and recoveryEventsPerMinute are #48's
// ratified recovery-pacing rule (decision 5, owner 2026-09-15): "paces
// its own backfill ... below #32's per-canary limits rather than as
// fast as it can." Half of client.RequestsPerMinuteLimit and
// client.EventsPerMinuteLimit -- the process-composition note's own
// numbers -- marked [contested] there, same here: "half" is not itself
// a ratified fraction, only "below the limit, so recovery never reads
// as throttled on #45" is. A caller with a better fraction should
// change these two constants; nothing else in this package assumes the
// value 2.
const (
	recoveryRequestsPerMinute = client.RequestsPerMinuteLimit / 2
	recoveryEventsPerMinute   = client.EventsPerMinuteLimit / 2
)

// tokenBucket is a minimal continuous-refill rate limiter, used to pace
// the sender's drain after birdcage has been unreachable (#48 decision
// 5) without needing to first detect "was there an outage" -- see
// pacer's doc comment for why applying it unconditionally is simpler
// and has the same effect.
//
// Timing is entirely time.Now()/time.Time subtraction, which Go's
// runtime backs with a monotonic reading as long as neither value has
// been serialized -- #48's hard constraint that no agent cadence may
// evaluate wall-clock time, since a canary may lack NTP and its wall
// clock can step backwards.
type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	ratePerSec float64
	last       time.Time
}

// newTokenBucket returns a bucket refilling at perMinute tokens per
// minute, starting full. Starting full means the first minute of a
// freshly started agent can burst up to perMinute immediately -- exactly
// the paced rate, never over it, so there is nothing to protect against
// by starting empty instead.
func newTokenBucket(perMinute int) *tokenBucket {
	rate := float64(perMinute) / 60
	return &tokenBucket{
		tokens:     float64(perMinute),
		capacity:   float64(perMinute),
		ratePerSec: rate,
		last:       time.Now(),
	}
}

// take blocks until n tokens are available (refilling continuously in
// the meantime) or ctx is done, whichever comes first.
func (b *tokenBucket) take(ctx context.Context, n int) error {
	for {
		wait, ok := b.tryTake(n)
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// tryTake attempts to deduct n tokens after applying whatever refill has
// accrued since the last call. ok is true when it succeeded; otherwise
// wait is how long the caller should sleep before trying again.
func (b *tokenBucket) tryTake(n int) (wait time.Duration, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.ratePerSec
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}

	if b.tokens >= float64(n) {
		b.tokens -= float64(n)
		return 0, true
	}
	need := float64(n) - b.tokens
	return time.Duration(need / b.ratePerSec * float64(time.Second)), false
}

// pacer bounds the sender's drain rate under both of #48's recovery caps
// at once -- one request per batch, plus the batch's own event count --
// so neither the request-per-minute nor the event-per-minute ceiling is
// crossed regardless of how the queue's backlog is shaped.
//
// Applied to every send, not only ones following a detected outage:
// #48's process-composition note only requires pacing "after birdcage
// has been unreachable," but distinguishing that case from ordinary
// operation would need its own state and its own bugs to get right, for
// no behavioral difference -- ordinary traffic runs at a small fraction
// of half of #32's per-canary limits, so the bucket only ever becomes
// the binding constraint exactly when there is a backlog large enough
// for pacing to matter, which is precisely recovery.
type pacer struct {
	requests *tokenBucket
	events   *tokenBucket
}

func newPacer() *pacer {
	return &pacer{
		requests: newTokenBucket(recoveryRequestsPerMinute),
		events:   newTokenBucket(recoveryEventsPerMinute),
	}
}

// wait blocks until sending a batch of n events is within both caps.
func (p *pacer) wait(ctx context.Context, n int) error {
	if err := p.requests.take(ctx, 1); err != nil {
		return err
	}
	return p.events.take(ctx, n)
}
