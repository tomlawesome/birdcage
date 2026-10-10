package auth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/api"
)

// Review fix 11: an open /api/stream ends after sign-out.
//
// ASSUMED SEAM: api.StreamRecheckInterval, a package-level variable of type
// time.Duration. The stream handler re-checks the caller's session or token
// on every tick of this interval (the keep-alive tick), as ai/mikroview#375
// does, and ends the stream when the check fails. internal/api exports no way
// to shorten the real interval today, so these tests set it to a few hundred
// milliseconds before any stream is opened.
const (
	testRecheck   = 250 * time.Millisecond
	testEndWithin = 3 * time.Second // generous: one interval plus scheduling slack
)

// openStream is one open GET /api/stream, read in the background.
type openStream struct {
	status int
	done   chan struct{} // closed when the response body ends or breaks
}

// shortenRecheck sets api.StreamRecheckInterval for the test.
func shortenRecheck(t *testing.T) {
	t.Helper()
	old := api.StreamRecheckInterval
	api.StreamRecheckInterval = testRecheck
	t.Cleanup(func() { api.StreamRecheckInterval = old })
}

// openEventStream opens /api/stream as client with header and reads its body
// in the background. The request is cancelled when the test ends, so a stream
// that should have ended cannot hold the test server open.
func openEventStream(t *testing.T, client *http.Client, base string, header map[string]string) *openStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/stream", nil)
	if err != nil {
		t.Fatalf("new stream request: %v", err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /api/stream: %v", err)
	}
	s := &openStream{status: resp.StatusCode, done: make(chan struct{})}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		t.Fatalf("GET /api/stream: status %d, want 200", resp.StatusCode)
	}
	go func() {
		defer close(s.done)
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}()
	return s
}

func (s *openStream) ended() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// waitEnded reports whether the stream ends within d.
func (s *openStream) waitEnded(d time.Duration) bool {
	select {
	case <-s.done:
		return true
	case <-time.After(d):
		return false
	}
}

// mintReadTokenWithID has the signed-in admin mint a read API token and
// returns its value and its id (the id is what revoking takes).
func (s *system) mintReadTokenWithID(t *testing.T, client *http.Client) (value, id string) {
	t.Helper()
	status, body := post(t, client, s.server.URL+"/api/tokens", map[string]string{"name": "stream-journey", "password": testAdminPassword})
	if status != http.StatusCreated {
		t.Fatalf("mint API token: status %d, want 201; body=%s", status, body)
	}
	var tok struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.Value == "" || tok.ID == "" {
		t.Fatalf("token response has no id or value: %v; body=%s", err, body)
	}
	return tok.Value, tok.ID
}

// TestStreamOpenedWithAReadTokenEndsWhenTheTokenIsRevoked: a stream opened
// with a read token as a bearer ends within one recheck interval of the
// admin revoking that token (DELETE /api/tokens/{id}). A second stream, opened
// with the admin's own session, is still open when the first has ended.
func TestStreamOpenedWithAReadTokenEndsWhenTheTokenIsRevoked(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)
	shortenRecheck(t)
	base := sys.server.URL

	token, id := sys.mintReadTokenWithID(t, admin)
	byToken := openEventStream(t, newClient(t), base, map[string]string{"Authorization": "Bearer " + token})
	bySession := openEventStream(t, admin, base, nil)

	if status, body := call(t, admin, http.MethodDelete, base+"/api/tokens/"+id, nil, withCSRF); status != http.StatusOK {
		t.Fatalf("revoke the read token: status %d, want 200; body=%s", status, body)
	}
	if !byToken.waitEnded(testEndWithin) {
		t.Errorf("the stream opened with the revoked token is still open %s after the revoke, want it ended within one recheck interval (%s)", testEndWithin, testRecheck)
	}
	if bySession.ended() {
		t.Error("the stream opened with the admin's session ended when only the token was revoked, want it still open")
	}
}

// TestStreamOpenedWithASessionEndsWhenTheSessionSignsOut: a stream opened
// with a session ends within one recheck interval of that session signing out
// (POST /api/auth/logout).
func TestStreamOpenedWithASessionEndsWhenTheSessionSignsOut(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)
	shortenRecheck(t)
	base := sys.server.URL

	token, _ := sys.mintReadTokenWithID(t, admin)
	byToken := openEventStream(t, newClient(t), base, map[string]string{"Authorization": "Bearer " + token})
	bySession := openEventStream(t, admin, base, nil)

	if status, body := post(t, admin, base+"/api/auth/logout", struct{}{}); status != http.StatusOK {
		t.Fatalf("sign out: status %d, want 200; body=%s", status, body)
	}
	if !bySession.waitEnded(testEndWithin) {
		t.Errorf("the stream opened with the signed-out session is still open %s after sign-out, want it ended within one recheck interval (%s)", testEndWithin, testRecheck)
	}
	if byToken.ended() {
		t.Error("the stream opened with a read token ended when only a session signed out, want it still open")
	}
}

// TestStreamsStayOpenWhileTheirCredentialsAreValid: with nothing revoked, a
// stream opened with a session and one opened with a read token are both
// still open after several recheck intervals, so the recheck does not just
// close every stream.
func TestStreamsStayOpenWhileTheirCredentialsAreValid(t *testing.T) {
	database := openDatabase(t)
	sys := startSystem(t, database, testKey('a'))
	admin := sys.signInFirstAdmin(t)
	shortenRecheck(t)
	base := sys.server.URL

	token, _ := sys.mintReadTokenWithID(t, admin)
	byToken := openEventStream(t, newClient(t), base, map[string]string{"Authorization": "Bearer " + token})
	bySession := openEventStream(t, admin, base, nil)

	time.Sleep(5 * testRecheck)
	if byToken.ended() {
		t.Error("the stream opened with a valid read token ended after several recheck intervals, want it open")
	}
	if bySession.ended() {
		t.Error("the stream opened with a valid session ended after several recheck intervals, want it open")
	}
}

// signInFirstAdmin registers the first admin and returns a client signed in
// as that admin: a fresh system per test, since a TOTP code is single use.
func (s *system) signInFirstAdmin(t *testing.T) *http.Client {
	t.Helper()
	secret := s.registerFirstAdmin(t, newClient(t))
	return s.signIn(t, secret)
}
