package main

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

// closeEnough reports whether got is within tol of want -- every
// tokenBucket assertion below expects a specific deduction, but the
// bucket also applies whatever real refill accrued in the microseconds
// between setup and the call under test, so an exact equality would be
// a flake waiting to happen rather than a check of the deduction itself.
func closeEnough(got, want, tol float64) bool {
	return math.Abs(got-want) <= tol
}

// TestTokenBucketTryTakeDeductsWhenAvailable proves the ordinary,
// non-blocking path: enough tokens deducts exactly n and reports ok.
func TestTokenBucketTryTakeDeductsWhenAvailable(t *testing.T) {
	b := newTokenBucket(60)
	wait, ok := b.tryTake(10)
	if !ok || wait != 0 {
		t.Fatalf("tryTake(10) on a full 60-capacity bucket = (%v, %v), want (0, true)", wait, ok)
	}
	if !closeEnough(b.tokens, 50, 0.01) {
		t.Errorf("tokens = %v after taking 10 of 60, want ~50", b.tokens)
	}
}

// TestTokenBucketTryTakeReportsWaitWhenShort proves the bucket refuses
// to overdraw and instead reports how long the caller must wait, rather
// than deducting a negative balance.
func TestTokenBucketTryTakeReportsWaitWhenShort(t *testing.T) {
	b := newTokenBucket(60) // 1 token/sec
	b.tokens = 0

	wait, ok := b.tryTake(5)
	if ok {
		t.Fatal("tryTake(5) on an empty bucket = ok, want false")
	}
	if wait < 4*time.Second || wait > 6*time.Second {
		t.Errorf("wait = %v, want close to 5s (5 tokens at 1/sec)", wait)
	}
	// tryTake still applies whatever refill accrued in the few
	// microseconds since b.tokens was zeroed above, so this checks "did
	// not deduct the requested 5" rather than an exact 0 -- a refused
	// take must never go negative, but a sliver of real refill between
	// setup and the call is not a defect to assert against.
	if b.tokens >= 1 {
		t.Errorf("tokens = %v after a refused tryTake, want it still under 1 (no deduction happened)", b.tokens)
	}
}

// TestTokenBucketTakeBlocksThenSucceeds proves take actually waits for
// the refill tryTake alone only reports, using a fast bucket (100
// tokens/sec, so the 1-token deficit tryTake reports refills in ~10ms)
// so the test itself stays fast rather than sleeping out a real
// production rate.
func TestTokenBucketTakeBlocksThenSucceeds(t *testing.T) {
	b := newTokenBucket(6000) // 100 tokens/sec
	b.tokens = 0

	start := time.Now()
	if err := b.take(context.Background(), 1); err != nil {
		t.Fatalf("take: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 5*time.Millisecond {
		t.Errorf("take returned after %v, want it to have actually waited for a refill", elapsed)
	}
}

// TestTokenBucketTakeReturnsCtxErrWhenCanceled proves take refuses to
// keep waiting once ctx ends, rather than blocking until the bucket
// refills regardless. An already-canceled context, and a bucket whose
// refill would take much longer than this test's timeout, makes the
// select's ctx.Done() case the only one that can win -- deterministic,
// no race against the refill timer.
func TestTokenBucketTakeReturnsCtxErrWhenCanceled(t *testing.T) {
	b := newTokenBucket(1) // 1 token/60s: nowhere near refilling in-test
	b.tokens = 0

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := b.take(ctx, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("take() = %v, want context.Canceled", err)
	}
	if b.tokens >= 1 {
		t.Errorf("tokens = %v after a canceled take, want it still under 1 (no deduction happened)", b.tokens)
	}
}

// TestPacerWaitAppliesBothCaps proves pacer.wait enforces the request
// cap and the event cap independently (#48 decision 5: "neither ...
// crossed regardless of how the queue's backlog is shaped"), each as
// its own refusal when ctx ends mid-wait, not just the ordinary combined
// success path.
func TestPacerWaitAppliesBothCaps(t *testing.T) {
	t.Run("succeeds and deducts both buckets", func(t *testing.T) {
		p := newPacer()
		if err := p.wait(context.Background(), 5); err != nil {
			t.Fatalf("wait: %v", err)
		}
		if !closeEnough(p.requests.tokens, recoveryRequestsPerMinute-1, 0.01) {
			t.Errorf("requests.tokens = %v, want ~%v (one request charged)", p.requests.tokens, recoveryRequestsPerMinute-1)
		}
		if !closeEnough(p.events.tokens, recoveryEventsPerMinute-5, 0.01) {
			t.Errorf("events.tokens = %v, want ~%v (5 events charged)", p.events.tokens, recoveryEventsPerMinute-5)
		}
	})

	t.Run("refuses when the request cap blocks and ctx ends", func(t *testing.T) {
		p := newPacer()
		p.requests.tokens = 0
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := p.wait(ctx, 5)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wait() = %v, want context.Canceled", err)
		}
		if !closeEnough(p.events.tokens, recoveryEventsPerMinute, 0.01) {
			t.Errorf("events.tokens = %v after a request-cap refusal, want the event bucket untouched at ~%v", p.events.tokens, recoveryEventsPerMinute)
		}
	})

	t.Run("refuses when the event cap blocks and ctx ends", func(t *testing.T) {
		p := newPacer()
		p.events.tokens = 0
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := p.wait(ctx, 5)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wait() = %v, want context.Canceled", err)
		}
		if !closeEnough(p.requests.tokens, recoveryRequestsPerMinute-1, 0.01) {
			t.Errorf("requests.tokens = %v, want ~%v (the request cap is charged before the event cap blocks)", p.requests.tokens, recoveryRequestsPerMinute-1)
		}
	})
}
