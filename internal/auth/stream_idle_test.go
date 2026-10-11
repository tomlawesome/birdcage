package auth_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/auth"
)

// Issue #190: the re-check an open /api/stream makes must answer "is this
// session still signed in?" without extending the session. An open tab then
// idles out like any other client, and a stream no longer keeps a session alive
// forever.
//
// The session idle limit is read when auth.Open builds the session store, so
// each test sets it (auth.SetSessionIdle, export_test.go) BEFORE startSystem.
// The limit is long enough that registering and signing in finish well inside
// it, and short enough that the tests stay quick. The re-check interval is the
// shared testRecheck from stream_signout_test.go.
const (
	testIdleLimit = 3 * time.Second
	// testIdleSlack is generous scheduling slack on a busy runner.
	testIdleSlack = 3 * time.Second
)

// TestStreamEndsOnceTheSessionHasIdledOut: a stream opened with a session and
// held open, with no other request, ends once the session's idle limit has
// passed, because the re-checks do not extend it.
func TestStreamEndsOnceTheSessionHasIdledOut(t *testing.T) {
	auth.SetSessionIdle(t, testIdleLimit)
	shortenRecheck(t)
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)

	opened := time.Now()
	stream := openEventStream(t, admin, sys.server.URL, nil)

	if !stream.waitEnded(testIdleLimit + testIdleSlack) {
		t.Fatalf("the stream is still open %s after it was opened with the session idle limit at %s and no other request, want it ended: the re-checks must not keep the session alive", time.Since(opened).Round(time.Millisecond), testIdleLimit)
	}
}

// TestStreamRecheckDoesNotExtendTheSession: while a stream sits open and
// re-checks several times, the session still expires on schedule. After the idle
// limit, counted from the last real request (opening the stream), an ordinary
// dashboard request with the same cookie answers 401.
func TestStreamRecheckDoesNotExtendTheSession(t *testing.T) {
	auth.SetSessionIdle(t, testIdleLimit)
	shortenRecheck(t)
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)
	base := sys.server.URL

	opened := time.Now()
	_ = openEventStream(t, admin, base, nil)

	// Well past the idle limit, with roughly a dozen re-checks in between and
	// no other request from the client.
	time.Sleep(time.Until(opened.Add(testIdleLimit + time.Second)))

	status, body := call(t, admin, http.MethodGet, base+"/api/stats", nil, nil)
	if status != http.StatusUnauthorized {
		t.Errorf("GET /api/stats %s after the last real request, past the %s idle limit, with a stream re-checking in between: status %d, want 401 (a re-check must not extend the session); body=%s",
			time.Since(opened).Round(time.Millisecond), testIdleLimit, status, body)
	}
}

// TestStreamStaysOpenWhileTheSessionIsWithinItsIdleLimit: the re-checks do not
// close a stream whose session is still valid. Several re-check intervals pass,
// all inside the idle limit, and the stream is still open.
func TestStreamStaysOpenWhileTheSessionIsWithinItsIdleLimit(t *testing.T) {
	auth.SetSessionIdle(t, testIdleLimit)
	shortenRecheck(t)
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)

	stream := openEventStream(t, admin, sys.server.URL, nil)

	// Six re-check intervals, about half the idle limit.
	if stream.waitEnded(6 * testRecheck) {
		t.Errorf("the stream ended within %s of opening, inside the %s idle limit, want it open while the session is valid", 6*testRecheck, testIdleLimit)
	}
}

// Sign-out and read-token revocation ending a stream are already covered by
// stream_signout_test.go (TestStreamOpenedWithASessionEndsWhenTheSessionSignsOut
// and TestStreamOpenedWithAReadTokenEndsWhenTheTokenIsRevoked), so they are not
// repeated here.
