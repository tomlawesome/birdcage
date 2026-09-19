package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// approvalFixture is a verified approval, for a test to spoil one field
// of. Raw is a plausible message rather than a real signed one: this
// file is about storage, and whether the bytes verify is
// internal/agent/approval's question, tested there.
func approvalFixture(t *testing.T, messageID, reference string, receivedAt time.Time) Approval {
	t.Helper()
	verified := receivedAt
	return Approval{
		MessageID:   messageID,
		FromAddress: "admin@example.net",
		Subject:     "Re: [birdcage " + reference + "] upgrade mockingbird",
		Reference:   reference,
		ReceivedAt:  receivedAt,
		VerifiedAt:  &verified,
		Raw:         []byte("From: admin@example.net\r\nSubject: Re: [birdcage " + reference + "]\r\n\r\nyes\r\n"),
	}
}

func rejected(a Approval, reason string) Approval {
	a.VerifiedAt = nil
	a.RejectReason = &reason
	return a
}

func TestRecordAndReadBackAnApproval(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		at := mustParse(t, "2026-09-19T09:00:00Z")
		want := approvalFixture(t, "<reply-1@example.net>", "u-1", at)

		if err := RecordApproval(ctx, database, want); err != nil {
			t.Fatalf("RecordApproval: %v", err)
		}

		got, err := ApprovalByReference(ctx, database, "u-1")
		if err != nil {
			t.Fatalf("ApprovalByReference: %v", err)
		}
		if got == nil {
			t.Fatal("ApprovalByReference found nothing")
		}
		if got.MessageID != want.MessageID || got.FromAddress != want.FromAddress || got.Subject != want.Subject {
			t.Errorf("read back %+v, want the row that went in", got)
		}
		if !got.ReceivedAt.Equal(at) {
			t.Errorf("ReceivedAt = %s, want %s", got.ReceivedAt, at)
		}
		if !got.Verified() {
			t.Error("the row read back as unverified")
		}
		if got.RejectReason != nil {
			t.Errorf("RejectReason = %q on a verified approval", *got.RejectReason)
		}
		if got.AppliedAt != nil {
			t.Error("AppliedAt is set; nothing is applied in slice 1")
		}
		// The raw message is the evidence each agent re-verifies for
		// itself, so it has to come back byte for byte.
		if !bytes.Equal(got.Raw, want.Raw) {
			t.Errorf("Raw came back changed:\n got: %q\nwant: %q", got.Raw, want.Raw)
		}
	})
}

func TestRecordARejectedApproval(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		at := mustParse(t, "2026-09-19T09:00:00Z")
		a := rejected(approvalFixture(t, "<reply-2@example.net>", "u-2", at),
			"approval: the message carries no DKIM signature")

		if err := RecordApproval(ctx, database, a); err != nil {
			t.Fatalf("RecordApproval: %v", err)
		}
		got, err := ApprovalByReference(ctx, database, "u-2")
		if err != nil {
			t.Fatalf("ApprovalByReference: %v", err)
		}
		if got.Verified() {
			t.Error("a rejected approval read back as verified")
		}
		if got.RejectReason == nil || !strings.Contains(*got.RejectReason, "no DKIM signature") {
			t.Errorf("RejectReason = %v, want the verifier's own wording", got.RejectReason)
		}
	})
}

// An approval is used once. The same signed message replayed later
// carries a signature that is still perfectly valid, so "have I seen
// this Message-ID?" is what stands between one approval and its reuse.
func TestApprovalSeenAndTheReplayConstraint(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		at := mustParse(t, "2026-09-19T09:00:00Z")
		a := approvalFixture(t, "<reply-3@example.net>", "u-3", at)

		seen, err := ApprovalSeen(ctx, database, a.MessageID)
		if err != nil {
			t.Fatalf("ApprovalSeen before recording: %v", err)
		}
		if seen {
			t.Error("ApprovalSeen said yes before anything was recorded")
		}

		if err := RecordApproval(ctx, database, a); err != nil {
			t.Fatalf("RecordApproval: %v", err)
		}

		seen, err = ApprovalSeen(ctx, database, a.MessageID)
		if err != nil {
			t.Fatalf("ApprovalSeen after recording: %v", err)
		}
		if !seen {
			t.Error("ApprovalSeen said no about a Message-ID that is in the table")
		}

		// A second write of the same Message-ID is the replay case, and
		// it is reported as such rather than as a raw constraint
		// violation the caller would have to pattern-match on.
		replay := approvalFixture(t, a.MessageID, "u-3", at.Add(time.Hour))
		if err := RecordApproval(ctx, database, replay); !errors.Is(err, ErrApprovalAlreadyRecorded) {
			t.Errorf("RecordApproval on a replay returned %v, want ErrApprovalAlreadyRecorded", err)
		}
	})
}

// An administrator may reply twice -- a rejected first attempt and a
// good second one. Both are kept, and the most recent is what a caller
// asking about the request gets.
func TestApprovalByReferenceReturnsTheMostRecent(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		first := mustParse(t, "2026-09-19T09:00:00Z")
		second := mustParse(t, "2026-09-19T09:30:00Z")

		if err := RecordApproval(ctx, database,
			rejected(approvalFixture(t, "<reply-4a@example.net>", "u-4", first), "approval: the Date header could not be read")); err != nil {
			t.Fatalf("RecordApproval (first): %v", err)
		}
		if err := RecordApproval(ctx, database,
			approvalFixture(t, "<reply-4b@example.net>", "u-4", second)); err != nil {
			t.Fatalf("RecordApproval (second): %v", err)
		}

		got, err := ApprovalByReference(ctx, database, "u-4")
		if err != nil {
			t.Fatalf("ApprovalByReference: %v", err)
		}
		if got.MessageID != "<reply-4b@example.net>" {
			t.Errorf("ApprovalByReference returned %s, want the later reply", got.MessageID)
		}
		if !got.Verified() {
			t.Error("the later reply read back as unverified")
		}
	})
}

func TestApprovalByReferenceFindsNothingForAnUnknownReference(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		got, err := ApprovalByReference(context.Background(), database, "never-used")
		if err != nil {
			t.Fatalf("ApprovalByReference: %v", err)
		}
		if got != nil {
			t.Errorf("ApprovalByReference found %+v for a reference nothing was recorded against", got)
		}
	})
}

func TestRecordApprovalRejectsBadInput(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ctx := context.Background()
		at := mustParse(t, "2026-09-19T09:00:00Z")
		base := approvalFixture(t, "<reply-5@example.net>", "u-5", at)

		reason := "some reason"
		cases := map[string]func(*Approval){
			"empty Message-ID":        func(a *Approval) { a.MessageID = "" },
			"zero ReceivedAt":         func(a *Approval) { a.ReceivedAt = time.Time{} },
			"empty Raw":               func(a *Approval) { a.Raw = nil },
			"oversized Raw":           func(a *Approval) { a.Raw = make([]byte, MaxApprovalRawSize+1) },
			"verified and rejected":   func(a *Approval) { a.RejectReason = &reason },
			"neither verified nor re": func(a *Approval) { a.VerifiedAt = nil },
		}
		for name, spoil := range cases {
			bad := base
			spoil(&bad)
			if err := RecordApproval(ctx, database, bad); err == nil {
				t.Errorf("RecordApproval accepted an approval with %s", name)
			}
		}
	})
}

func TestApprovalSeenRefusesAnEmptyMessageID(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		if _, err := ApprovalSeen(context.Background(), database, ""); err == nil {
			t.Error("ApprovalSeen accepted an empty Message-ID")
		}
	})
}
