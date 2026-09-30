package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/ledger"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// testContextWithTimeout returns a context that gives a background loop
// enough time for one pass of its own logic (well under senderIdleInterval
// and senderRetryInterval's own waits are never reached within it) before
// the test moves on to assert what did or did not happen.
func testContextWithTimeout(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 500*time.Millisecond)
}

var sendValidID1 = strings.Repeat("1", 64)

// newApplyVerdictsIntake builds a bare Intake -- no receiver, no
// tailer.Follow running -- with one fresh ledger a test can Append to
// directly, for exercising applyVerdicts in isolation from the network
// and the log.
func newApplyVerdictsIntake(t *testing.T) *Intake {
	t.Helper()
	in, _ := newTestIntake(t, queue.Config{})
	ldg := ledger.New(ledger.DefaultCollisionWindow)
	in.ledgerPtr.Store(ldg)
	return in
}

// TestApplyVerdictsRetryLeavesPositionUnmoved proves #48's fail-closed
// rule for the ordinary Retry case: an id named as neither stored nor
// rejected (client.BatchResult's own "no ack at all" case) is left
// queued and unresolved, and the acknowledged position never advances
// past it.
func TestApplyVerdictsRetryLeavesPositionUnmoved(t *testing.T) {
	in := newApplyVerdictsIntake(t)
	ldg := in.Ledger()
	in.Queue.Push(queue.Event{ID: sendValidID1, Payload: []byte("{}")})
	ldg.Append(sendValidID1, queue.Position{Inode: 1, Offset: 10})

	in.applyVerdicts([]string{sendValidID1}, client.BatchResult{Retry: []string{sendValidID1}})

	if ldg.Len() != 1 {
		t.Fatalf("ledger.Len() = %d, want 1 (entry must stay unresolved)", ldg.Len())
	}
	if depth := in.Queue.Depth(); depth != 1 {
		t.Fatalf("Queue.Depth() = %d, want 1 (a Retry must never Ack or Reject)", depth)
	}
	if _, ok, err := in.PositionStore().Load(); err != nil || ok {
		t.Fatalf("PositionStore.Load() = (ok=%v, err=%v), want (false, nil): position must not advance on a Retry", ok, err)
	}
}

// TestApplyVerdictsContradictionLeavesPositionUnmoved is the case #48
// asks be tested explicitly: an unexpected or malformed response --
// here, birdcage naming the same id as both stored and rejected, which
// client.BatchResult's own contract promises never happens but this
// function must not simply trust -- leaves the entry unresolved and the
// saved position unmoved, rather than resolving on either verdict.
// ledger.Resolve's protective panic on an invalid Verdict is exactly
// what this function must never trigger by inventing a third verdict,
// and exactly what it must never bypass by guessing which of the two
// contradictory ones birdcage "really" meant.
func TestApplyVerdictsContradictionLeavesPositionUnmoved(t *testing.T) {
	in := newApplyVerdictsIntake(t)
	ldg := in.Ledger()
	in.Queue.Push(queue.Event{ID: sendValidID1, Payload: []byte("{}")})
	ldg.Append(sendValidID1, queue.Position{Inode: 1, Offset: 10})

	in.applyVerdicts([]string{sendValidID1}, client.BatchResult{
		Stored:   []string{sendValidID1},
		Rejected: map[string]string{sendValidID1: "some reason"},
	})

	if ldg.Len() != 1 {
		t.Fatalf("ledger.Len() = %d, want 1 (a contradictory response must leave the entry unresolved)", ldg.Len())
	}
	if depth := in.Queue.Depth(); depth != 1 {
		t.Fatalf("Queue.Depth() = %d, want 1 (a contradictory response must never Ack or Reject)", depth)
	}
	if _, ok, err := in.PositionStore().Load(); err != nil || ok {
		t.Fatalf("PositionStore.Load() = (ok=%v, err=%v), want (false, nil): position must not advance", ok, err)
	}
	if id := in.LastEventID(); id != "" {
		t.Fatalf("LastEventID() = %q, want empty: an unresolved id was never actually stored", id)
	}
}

// TestApplyVerdictsStoredAdvancesPosition is the positive control for
// the two tests above: a genuine Stored verdict does Ack, does Resolve,
// and does advance and save the position.
func TestApplyVerdictsStoredAdvancesPosition(t *testing.T) {
	in := newApplyVerdictsIntake(t)
	ldg := in.Ledger()
	in.Queue.Push(queue.Event{ID: sendValidID1, Payload: []byte("{}")})
	ldg.Append(sendValidID1, queue.Position{Inode: 1, Offset: 10})

	in.applyVerdicts([]string{sendValidID1}, client.BatchResult{Stored: []string{sendValidID1}})

	if depth := in.Queue.Depth(); depth != 0 {
		t.Fatalf("Queue.Depth() = %d, want 0 (Stored must Ack)", depth)
	}
	pos, ok, err := in.PositionStore().Load()
	if err != nil || !ok {
		t.Fatalf("PositionStore.Load() = (ok=%v, err=%v), want (true, nil)", ok, err)
	}
	if pos != (queue.Position{Inode: 1, Offset: 10}) {
		t.Fatalf("saved position = %+v, want {Inode:1 Offset:10}", pos)
	}
	if id := in.LastEventID(); id != sendValidID1 {
		t.Fatalf("LastEventID() = %q, want %q", id, sendValidID1)
	}
}

// TestRunSenderLoopMalformedResponseLeavesPositionUnmoved is #48's
// required "unexpected or malformed response" test at the transport
// level: a birdcage that answers 200 with an undecodable body makes
// client.PushBatch itself fail (a *client.RetryableError), and
// runSenderLoop must not resolve or advance anything for that batch --
// the event stays queued for the next attempt.
func TestRunSenderLoopMalformedResponseLeavesPositionUnmoved(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	in, _ := newTestIntake(t, queue.Config{})
	if err := in.webhookHandler(wrapWebhook(t, fixtureEvent(1))); err != nil {
		t.Fatalf("webhookHandler: %v", err)
	}

	runCtx, cancel := testContextWithTimeout(t)
	defer cancel()
	// One pass of the loop body is enough: call the loop's own retry
	// path once by racing it against a short-lived context rather than
	// waiting out senderRetryInterval (a full minute).
	go runSenderLoop(runCtx, c, newTokenStoreForTest("tok"), in, newPacer())
	<-runCtx.Done()

	if depth := in.Queue.Depth(); depth != 1 {
		t.Fatalf("Queue.Depth() = %d, want 1 (a malformed response must never Ack or Reject)", depth)
	}
	if _, ok, err := in.PositionStore().Load(); err != nil || ok {
		t.Fatalf("PositionStore.Load() = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

// TestRunSenderLoopReturnsImmediatelyWhenCtxAlreadyDone pins the loop's
// own top-of-iteration guard (`if ctx.Err() != nil { return }`, ahead of
// even the first Queue.Peek) with an already-canceled context, rather
// than relying on TestRunSenderLoopStopsOnContextCancel's real timing to
// land there: that test's cancel() races the loop's exact position
// between an iteration's top check and the idle select's own ctx.Done()
// case further down, and repeated -coverprofile runs showed the top
// check covered on some and not on others. An already-canceled context
// makes ctx.Err() non-nil on the very first check, before the loop ever
// touches c or ts -- both left nil here since nothing reaches them.
func TestRunSenderLoopReturnsImmediatelyWhenCtxAlreadyDone(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		runSenderLoop(ctx, nil, nil, in, newPacer())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runSenderLoop did not return immediately with an already-canceled context")
	}
}
