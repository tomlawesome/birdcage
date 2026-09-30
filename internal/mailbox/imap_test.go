package mailbox

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// collector is the handler most tests use: it records what it was given
// and can be told to fail.
type collector struct {
	seen []string
	fail error
}

func (c *collector) handle(_ context.Context, raw []byte) error {
	if c.fail != nil {
		return c.fail
	}
	c.seen = append(c.seen, subjectOf(raw))
	return nil
}

func subjectOf(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\r\n") {
		if rest, ok := strings.CutPrefix(line, "Subject: "); ok {
			return rest
		}
	}
	return ""
}

func TestPollHandsOverMatchingMessagesAndMarksThemRead(t *testing.T) {
	srv := newTestServer(t)
	srv.deliver(t, testMessage("Re: [birdcage u-1] upgrade", 100))
	srv.deliver(t, testMessage("Re: [birdcage u-2] upgrade", 100))
	// Not an approval reply: no reference token, so the server-side
	// search never returns it.
	srv.deliver(t, testMessage("Your invoice is ready", 100))

	r := srv.reader(t)
	var got collector
	n, err := r.Poll(context.Background(), got.handle)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if n != 2 {
		t.Errorf("Poll handled %d messages, want 2", n)
	}
	want := []string{"Re: [birdcage u-1] upgrade", "Re: [birdcage u-2] upgrade"}
	if fmt.Sprint(got.seen) != fmt.Sprint(want) {
		t.Errorf("handler saw %v, want %v", got.seen, want)
	}

	// The second poll proves the first marked them \Seen: a message
	// handled twice would be an approval applied twice.
	var again collector
	n, err = r.Poll(context.Background(), again.handle)
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if n != 0 || len(again.seen) != 0 {
		t.Errorf("second Poll handled %d messages (%v), want none -- the first poll should have marked them read", n, again.seen)
	}
}

func TestPollOnAnEmptyMailbox(t *testing.T) {
	srv := newTestServer(t)
	var got collector
	n, err := srv.reader(t).Poll(context.Background(), got.handle)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if n != 0 {
		t.Errorf("Poll handled %d messages on an empty mailbox", n)
	}
}

// A message the handler could not deal with -- the database was
// unavailable, say -- must stay unread, so the next poll owes it still.
func TestPollLeavesAMessageUnreadWhenTheHandlerFails(t *testing.T) {
	srv := newTestServer(t)
	srv.deliver(t, testMessage("Re: [birdcage u-1] upgrade", 100))

	r := srv.reader(t)
	failing := &collector{fail: errors.New("the database is not available")}
	if _, err := r.Poll(context.Background(), failing.handle); err == nil {
		t.Fatal("Poll succeeded despite the handler failing")
	}

	var retry collector
	n, err := r.Poll(context.Background(), retry.handle)
	if err != nil {
		t.Fatalf("retry Poll: %v", err)
	}
	if n != 1 {
		t.Errorf("retry Poll handled %d messages, want the one the failed handler left behind", n)
	}
}

// An oversized message is skipped rather than downloaded, and is marked
// read so it cannot block the mailbox forever.
func TestPollSkipsAnOversizedMessage(t *testing.T) {
	srv := newTestServer(t)
	srv.deliver(t, testMessage("Re: [birdcage u-big] upgrade", MaxMessageSize+1024))
	srv.deliver(t, testMessage("Re: [birdcage u-ok] upgrade", 100))

	r := srv.reader(t)
	var got collector
	n, err := r.Poll(context.Background(), got.handle)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if n != 1 {
		t.Fatalf("Poll handled %d messages, want only the small one", n)
	}
	if len(got.seen) != 1 || !strings.Contains(got.seen[0], "u-ok") {
		t.Errorf("handler saw %v, want only the u-ok message", got.seen)
	}

	var again collector
	if n, err := r.Poll(context.Background(), again.handle); err != nil || n != 0 {
		t.Errorf("second Poll handled %d messages (err %v), want none -- the oversized one should have been marked read", n, err)
	}
}

// A mailbox full of rubbish is not allowed to make one poll unbounded.
// The rest are still unread, so the next poll picks them up.
func TestPollHandlesAtMostFiftyMessagesPerPass(t *testing.T) {
	srv := newTestServer(t)
	const total = maxMessagesPerPoll + 5
	for i := 0; i < total; i++ {
		srv.deliver(t, testMessage(fmt.Sprintf("Re: [birdcage u-%02d] upgrade", i), 100))
	}

	r := srv.reader(t)
	var first collector
	n, err := r.Poll(context.Background(), first.handle)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if n != maxMessagesPerPoll {
		t.Errorf("first Poll handled %d messages, want %d", n, maxMessagesPerPoll)
	}

	var second collector
	n, err = r.Poll(context.Background(), second.handle)
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if n != total-maxMessagesPerPoll {
		t.Errorf("second Poll handled %d messages, want the remaining %d", n, total-maxMessagesPerPoll)
	}
}

// There is no skip-verify knob, so a server whose certificate does not
// verify is a failed poll rather than a silently accepted connection.
func TestPollRefusesAnUntrustedCertificate(t *testing.T) {
	srv := newTestServer(t)
	srv.deliver(t, testMessage("Re: [birdcage u-1] upgrade", 100))

	r := srv.reader(t)
	r.testRoots = x509.NewCertPool() // trusts nothing

	var got collector
	if _, err := r.Poll(context.Background(), got.handle); err == nil {
		t.Fatal("Poll accepted a server whose certificate does not verify")
	} else if !strings.Contains(err.Error(), "TLS handshake") {
		t.Errorf("Poll failed with %v, want a TLS handshake failure", err)
	}
	if len(got.seen) != 0 {
		t.Errorf("the handler was given %v over an unverified connection", got.seen)
	}
}

// The password is a credential: it must not turn up in an error, which
// is a line in the log and a row in the database.
func TestPollDoesNotLeakThePasswordOnALoginFailure(t *testing.T) {
	srv := newTestServer(t)
	r := srv.reader(t)
	r.cfg.Password = "not-the-password"

	var got collector
	_, err := r.Poll(context.Background(), got.handle)
	if err == nil {
		t.Fatal("Poll succeeded with the wrong password")
	}
	if strings.Contains(err.Error(), "not-the-password") {
		t.Errorf("the login error quotes the password back: %v", err)
	}
	if !strings.Contains(err.Error(), testUser) {
		t.Errorf("the login error does not name the username, so it is hard to act on: %v", err)
	}
}

func TestPollStopsOnACancelledContext(t *testing.T) {
	srv := newTestServer(t)
	srv.deliver(t, testMessage("Re: [birdcage u-1] upgrade", 100))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var got collector
	if _, err := srv.reader(t).Poll(ctx, got.handle); err == nil {
		t.Fatal("Poll ran to completion with a cancelled context")
	}
	if len(got.seen) != 0 {
		t.Errorf("the handler was given %v after cancellation", got.seen)
	}
}

func TestPollNeedsAHandler(t *testing.T) {
	srv := newTestServer(t)
	if _, err := srv.reader(t).Poll(context.Background(), nil); err == nil {
		t.Fatal("Poll accepted a nil handler")
	}
}

// The mailbox name is configurable, and a name that does not exist is a
// clear failure rather than a poll that quietly finds nothing.
func TestPollReportsAMissingMailbox(t *testing.T) {
	srv := newTestServer(t)
	r := srv.reader(t)
	r.cfg.Mailbox = "Approvals"

	var got collector
	_, err := r.Poll(context.Background(), got.handle)
	if err == nil {
		t.Fatal("Poll succeeded against a mailbox that does not exist")
	}
	if !strings.Contains(err.Error(), "Approvals") {
		t.Errorf("the error does not name the mailbox: %v", err)
	}
}
