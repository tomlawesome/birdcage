package stream

import (
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

func testAlert(sourceIP string) store.AlertInsert {
	return store.AlertInsert{
		InstanceID: "node-1",
		SourceIP:   sourceIP,
		DestPort:   22,
		Service:    "ssh",
		Raw:        "raw",
		ReceivedAt: time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
	}
}

func TestSubscribeReceivesPublishedAlert(t *testing.T) {
	h := NewHub()
	ch, cancel, ok := h.Subscribe()
	if !ok {
		t.Fatalf("Subscribe: ok = false")
	}
	defer cancel()

	h.PublishAlert(testAlert("203.0.113.9"))

	select {
	case payload := <-ch:
		// The notification says an alert was stored and nothing more:
		// no alert content travels over the stream, so a connection
		// that outlives the session that opened it leaks nothing
		// (#44 research, 2026-09-15).
		if string(payload) != `{"type":"alert"}` {
			t.Errorf("payload = %s, want the contentless notification", payload)
		}
		if strings.Contains(string(payload), "203.0.113.9") {
			t.Errorf("payload carries alert content: %s", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published alert")
	}
}

// TestPublishDropsSlowestSubscriberRatherThanBlocking is issue #44's
// back-pressure requirement: a subscriber that never drains its channel
// must be evicted once its buffer fills, not allowed to block Publish or
// starve every other subscriber.
//
// The reader here acknowledges each event before the next is published.
// An earlier version fired every publish back to back and assumed a
// concurrently draining reader would keep up; nothing guaranteed the
// reader goroutine was scheduled between them, so under -race it
// sometimes wasn't, its buffer filled, and the hub correctly evicted it
// -- the test failed roughly twice in ten runs (docs/flakes.md). The
// hub's promise is to drop whoever is not keeping up at that moment, not
// to know why; so the reader has to actually keep up for the assertion
// to mean anything.
func TestPublishDropsSlowestSubscriberRatherThanBlocking(t *testing.T) {
	h := NewHub()

	slowCh, slowCancel, ok := h.Subscribe()
	if !ok {
		t.Fatalf("Subscribe(slow): ok = false")
	}
	defer slowCancel()

	fastCh, fastCancel, ok := h.Subscribe()
	if !ok {
		t.Fatalf("Subscribe(fast): ok = false")
	}
	defer fastCancel()

	// slowCh is never read, so its buffer fills and PublishAlert must
	// evict it rather than block on it. fastCh is read to completion
	// after every publish, so it is never behind when the next one
	// lands.
	fastClosedByHub := make(chan struct{})
	published := make(chan struct{})
	drained := make(chan struct{})
	stopDrain := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopDrain:
				return
			case <-published:
				select {
				case _, open := <-fastCh:
					if !open {
						close(fastClosedByHub)
						return
					}
				case <-stopDrain:
					return
				}
				drained <- struct{}{}
			}
		}
	}()

	// subscriberBuffer+1 publishes guarantees at least one publish finds
	// slowCh's buffer already full.
	for i := 0; i < subscriberBuffer+1; i++ {
		done := make(chan struct{})
		go func() {
			h.PublishAlert(testAlert("203.0.113.9"))
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("PublishAlert blocked on a slow subscriber instead of dropping it")
		}

		published <- struct{}{}
		select {
		case <-drained:
		case <-fastClosedByHub:
			t.Fatal("fast subscriber was evicted while it was keeping up; only the slow one should be")
		case <-time.After(time.Second):
			t.Fatal("the reading subscriber never received the published event")
		}
	}

	// The slow subscriber's channel must have been closed (evicted).
	select {
	case _, open := <-slowCh:
		if open {
			// Drain whatever made it into the buffer before eviction;
			// the channel must close eventually.
			for open {
				_, open = <-slowCh
			}
		}
	case <-time.After(time.Second):
		t.Fatal("slow subscriber's channel was never closed (not evicted)")
	}

	// The fast subscriber must not have been evicted just because
	// another subscriber was slow.
	select {
	case <-fastClosedByHub:
		t.Error("fast subscriber was evicted; only the slow one should be")
	default:
	}
	close(stopDrain)
}

func TestSubscribeFailsClosedAtCapacity(t *testing.T) {
	h := NewHub()
	var cancels []func()
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()

	for i := 0; i < maxSubscribers; i++ {
		_, cancel, ok := h.Subscribe()
		if !ok {
			t.Fatalf("Subscribe #%d: ok = false, want true", i)
		}
		cancels = append(cancels, cancel)
	}

	if _, _, ok := h.Subscribe(); ok {
		t.Fatal("Subscribe at capacity: ok = true, want false (fail closed)")
	}
	if got := h.Subscribers(); got != maxSubscribers {
		t.Errorf("Subscribers() = %d, want %d", got, maxSubscribers)
	}

	// Canceling one frees a slot.
	cancels[0]()
	cancels = cancels[1:]
	if _, cancel, ok := h.Subscribe(); !ok {
		t.Error("Subscribe after a cancel: ok = false, want true")
	} else {
		cancels = append(cancels, cancel)
	}
}

func TestCancelIsIdempotentAndUnsubscribes(t *testing.T) {
	h := NewHub()
	ch, cancel, ok := h.Subscribe()
	if !ok {
		t.Fatalf("Subscribe: ok = false")
	}
	cancel()
	cancel() // must not panic (double-close) or double-unregister.

	if got := h.Subscribers(); got != 0 {
		t.Errorf("Subscribers() after cancel = %d, want 0", got)
	}
	if _, open := <-ch; open {
		t.Error("channel still open after cancel")
	}

	// Publishing after every subscriber has canceled must not panic.
	h.PublishAlert(testAlert("203.0.113.9"))
}
