package mail

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// enqueueSender builds a Sender whose SMTP side is never used: these
// tests are about which alerts get written at all, which is settled
// before anything is sent.
func enqueueSender(database *db.DB) *Sender {
	return New(database, Config{
		Host: "smtp.example.invalid:465", Username: smtpUser, Password: smtpPass,
		From: fromAddr, To: toAddr,
	}, quietLogger())
}

func pendingCount(t *testing.T, database *db.DB) int {
	t.Helper()
	status, err := store.GetMailStatus(context.Background(), database)
	if err != nil {
		t.Fatalf("GetMailStatus: %v", err)
	}
	return status.Pending
}

func latestFor(t *testing.T, database *db.DB, canaryID string) *store.MailMessage {
	t.Helper()
	m, err := store.LatestMail(context.Background(), database, store.MailKindTokenConflict, canaryID)
	if err != nil {
		t.Fatalf("LatestMail(%s): %v", canaryID, err)
	}
	return m
}

// The per-canary cooldown: a second conflict inside the hour is
// suppressed, and one exactly on the hour is not. The boundary is
// inclusive, the same way internal/history's collapseWindow is.
func TestPerCanaryCooldownBoundary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		sender := enqueueSender(database)
		start := pinnedNow

		if err := sender.EnqueueTokenConflict(ctx, database, "canary-iot", "canary-iot", start); err != nil {
			t.Fatalf("first enqueue: %v", err)
		}
		if got := pendingCount(t, database); got != 1 {
			t.Fatalf("after the first conflict, %d messages are owed, want 1", got)
		}

		// One second inside the window: suppressed, and counted.
		justInside := start.Add(perCanaryCooldown - time.Second)
		if err := sender.EnqueueTokenConflict(ctx, database, "canary-iot", "canary-iot", justInside); err != nil {
			t.Fatalf("enqueue just inside the cooldown: %v", err)
		}
		if got := pendingCount(t, database); got != 1 {
			t.Fatalf("a conflict inside the cooldown was mailed (%d owed, want 1)", got)
		}
		if m := latestFor(t, database, "canary-iot"); m.SuppressedCount != 1 {
			t.Errorf("SuppressedCount = %d after one suppression, want 1", m.SuppressedCount)
		}

		// Exactly on the boundary: mailed, and the new message reports
		// what was suppressed while the previous one was the latest.
		onBoundary := start.Add(perCanaryCooldown)
		if err := sender.EnqueueTokenConflict(ctx, database, "canary-iot", "canary-iot", onBoundary); err != nil {
			t.Fatalf("enqueue on the boundary: %v", err)
		}
		if got := pendingCount(t, database); got != 2 {
			t.Fatalf("a conflict exactly on the boundary was suppressed (%d owed, want 2)", got)
		}
		latest := latestFor(t, database, "canary-iot")
		if !strings.Contains(latest.Body, "1 further alert was suppressed since "+start.Format(time.RFC1123)) {
			t.Errorf("the new message does not report the suppressed alert:\n%s", latest.Body)
		}
		if latest.SuppressedCount != 0 {
			t.Errorf("the new message starts with SuppressedCount = %d, want 0", latest.SuppressedCount)
		}
	})
}

// A suppression is never reported twice: the count lives on whichever
// row was most recent at the time, and the message that reports it
// leaves that row alone and starts its own count at zero.
func TestSuppressionsAreReportedExactlyOnce(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		sender := enqueueSender(database)
		start := pinnedNow

		if err := sender.EnqueueTokenConflict(ctx, database, "canary-iot", "canary-iot", start); err != nil {
			t.Fatalf("first enqueue: %v", err)
		}
		for i := 1; i <= 3; i++ {
			at := start.Add(time.Duration(i) * time.Minute)
			if err := sender.EnqueueTokenConflict(ctx, database, "canary-iot", "canary-iot", at); err != nil {
				t.Fatalf("suppressed enqueue %d: %v", i, err)
			}
		}
		second := start.Add(perCanaryCooldown)
		if err := sender.EnqueueTokenConflict(ctx, database, "canary-iot", "canary-iot", second); err != nil {
			t.Fatalf("second enqueue: %v", err)
		}
		if body := latestFor(t, database, "canary-iot").Body; !strings.Contains(body, "3 further alerts were suppressed") {
			t.Errorf("the second message does not report three suppressions:\n%s", body)
		}

		// A third message, with nothing suppressed in between, must not
		// repeat the count.
		third := second.Add(perCanaryCooldown)
		if err := sender.EnqueueTokenConflict(ctx, database, "canary-iot", "canary-iot", third); err != nil {
			t.Fatalf("third enqueue: %v", err)
		}
		if body := latestFor(t, database, "canary-iot").Body; strings.Contains(body, "suppressed") {
			t.Errorf("the third message repeats a suppression count:\n%s", body)
		}
	})
}

// The cooldown is per canary: a second canary conflicting inside the
// same hour gets its own message.
func TestCooldownIsPerCanary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		sender := enqueueSender(database)
		for _, id := range []string{"canary-lan", "canary-iot", "canary-srv"} {
			if err := sender.EnqueueTokenConflict(ctx, database, id, id, pinnedNow); err != nil {
				t.Fatalf("enqueue for %s: %v", id, err)
			}
		}
		if got := pendingCount(t, database); got != 3 {
			t.Errorf("%d messages owed for three canaries, want 3", got)
		}
	})
}

// The fleet-wide cap: the twentieth message inside the rolling hour is
// written, the twenty-first is suppressed. Each canary is distinct, so
// the per-canary cooldown is not what stops it.
func TestFleetHourlyCap(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		sender := enqueueSender(database)

		for i := 1; i <= fleetHourlyCap; i++ {
			id := fmt.Sprintf("canary-%02d", i)
			at := pinnedNow.Add(time.Duration(i) * time.Second)
			if err := sender.EnqueueTokenConflict(ctx, database, id, id, at); err != nil {
				t.Fatalf("enqueue %d: %v", i, err)
			}
			if got := pendingCount(t, database); got != i {
				t.Fatalf("after conflict %d, %d messages are owed, want %d", i, got, i)
			}
		}

		// The twenty-first, from a canary that has never been mailed
		// about, is over the cap.
		overID := fmt.Sprintf("canary-%02d", fleetHourlyCap+1)
		at := pinnedNow.Add(time.Duration(fleetHourlyCap+1) * time.Second)
		if err := sender.EnqueueTokenConflict(ctx, database, overID, overID, at); err != nil {
			t.Fatalf("enqueue over the cap: %v", err)
		}
		if got := pendingCount(t, database); got != fleetHourlyCap {
			t.Fatalf("the message over the cap was written (%d owed, want %d)", got, fleetHourlyCap)
		}
		if m := latestFor(t, database, overID); m != nil {
			t.Error("a message exists for the canary that was over the cap")
		}
		// It was counted, not dropped: the most recent message of this
		// kind carries it, and will report it.
		if m := latestFor(t, database, ""); m == nil || m.SuppressedCount != 1 {
			t.Errorf("the suppressed alert was not counted anywhere: %+v", m)
		}
	})
}

// The cap window rolls: once the first hour's messages are outside it,
// mail flows again.
func TestFleetCapWindowRolls(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		sender := enqueueSender(database)

		for i := 1; i <= fleetHourlyCap; i++ {
			id := fmt.Sprintf("canary-%02d", i)
			if err := sender.EnqueueTokenConflict(ctx, database, id, id, pinnedNow); err != nil {
				t.Fatalf("enqueue %d: %v", i, err)
			}
		}
		later := pinnedNow.Add(fleetCapWindow + time.Second)
		id := "canary-99"
		if err := sender.EnqueueTokenConflict(ctx, database, id, id, later); err != nil {
			t.Fatalf("enqueue after the window: %v", err)
		}
		if got := pendingCount(t, database); got != fleetHourlyCap+1 {
			t.Errorf("%d messages owed after the window rolled, want %d", got, fleetHourlyCap+1)
		}
	})
}

// The recorder's hook is installed unconditionally, so a nil Sender --
// cmd/birdcage's way of saying mail is off -- must simply do nothing.
func TestNilSenderEnqueueIsANoOp(t *testing.T) {
	var s *Sender
	if err := s.EnqueueTokenConflict(context.Background(), nil, "canary-iot", "canary-iot", pinnedNow); err != nil {
		t.Errorf("EnqueueTokenConflict on a nil Sender: %v", err)
	}
}

// Suppression is about mail only. Nothing in this path writes to, reads
// from or otherwise touches canary_state_periods, which is what the
// dashboard's tile is drawn from -- the state is the state whether or
// not an email went out about it.
func TestSuppressionNeverTouchesTheStateHistory(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		sender := enqueueSender(database)

		for i := 0; i < 5; i++ {
			at := pinnedNow.Add(time.Duration(i) * time.Minute)
			if err := sender.EnqueueTokenConflict(ctx, database, "canary-iot", "canary-iot", at); err != nil {
				t.Fatalf("enqueue %d: %v", i, err)
			}
		}
		periods, err := store.ListStatePeriods(ctx, database, pinnedNow.Add(-time.Hour), pinnedNow.Add(time.Hour), "")
		if err != nil {
			t.Fatalf("ListStatePeriods: %v", err)
		}
		if len(periods) != 0 {
			t.Errorf("the mail path wrote %d state periods, want 0", len(periods))
		}
	})
}
