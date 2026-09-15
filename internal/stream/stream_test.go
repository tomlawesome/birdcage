package stream

import (
	"encoding/json"
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
		var got store.AlertInsert
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatalf("unmarshal payload: %v; payload=%s", err, payload)
		}
		if got.SourceIP != "203.0.113.9" {
			t.Errorf("SourceIP = %q, want 203.0.113.9", got.SourceIP)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published alert")
	}
}

// TestPublishDropsSlowestSubscriberRatherThanBlocking is issue #44's
// back-pressure requirement: a subscriber that never drains its channel
// must be evicted once its buffer fills, not allowed to block Publish or
// starve every other subscriber.
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

	// fastCh is drained concurrently, exactly like a healthy dashboard
	// connection reading as events arrive -- it must never be evicted.
	// slowCh is never read, so its buffer fills and PublishAlert must
	// evict it rather than block on it.
	fastClosedByHub := make(chan struct{})
	stopDrain := make(chan struct{})
	go func() {
		for {
			select {
			case _, open := <-fastCh:
				if !open {
					close(fastClosedByHub)
					return
				}
			case <-stopDrain:
				return
			}
		}
	}()

	// subscriberBuffer+1 publishes guarantees at least one publish finds
	// slowCh's buffer already full.
	done := make(chan struct{})
	go func() {
		for i := 0; i < subscriberBuffer+1; i++ {
			h.PublishAlert(testAlert("203.0.113.9"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PublishAlert blocked on a slow subscriber instead of dropping it")
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
	case <-time.After(100 * time.Millisecond):
		// Remained open throughout the publish storm -- good.
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
