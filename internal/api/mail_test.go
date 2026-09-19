package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// mailBody is the shape GET /api/mail promises. Decoded into a struct
// of pointers so "the field was absent" and "the field was null" are
// distinguishable -- the frontend switches on null, so an omitted field
// would be a silent contract change.
type mailBody struct {
	Configured   *bool   `json:"configured"`
	LastSentAt   *string `json:"last_sent_at"`
	FailingSince *string `json:"failing_since"`
	LastError    *string `json:"last_error"`
	Pending      *int    `json:"pending"`
	Suppressed   *int64  `json:"suppressed"`
}

func getMail(t *testing.T, h http.Handler) (*httptest.ResponseRecorder, mailBody) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/mail", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/mail = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body mailBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /api/mail: %v (%s)", err, rec.Body.String())
	}
	return rec, body
}

func enqueue(t *testing.T, database *db.DB, canaryID string, at time.Time) int64 {
	t.Helper()
	id := canaryID
	if err := store.EnqueueMail(context.Background(), database, store.MailMessage{
		Kind:          string(store.MailKindTokenConflict),
		CanaryID:      &id,
		Subject:       "birdcage: a canary presented a revoked credential",
		Body:          "body",
		CreatedAt:     at,
		NextAttemptAt: at,
	}); err != nil {
		t.Fatalf("EnqueueMail: %v", err)
	}
	m, err := store.LatestMail(context.Background(), database, store.MailKindTokenConflict, canaryID)
	if err != nil || m == nil {
		t.Fatalf("LatestMail(%s): %v", canaryID, err)
	}
	return m.ID
}

// With no mail configured, the endpoint says so -- and every other
// field is still present and null, so the dashboard can render "mail
// off" without a special case for a missing key.
func TestHandleMailReportsNotConfigured(t *testing.T) {
	database := openTempDB(t)
	_, body := getMail(t, newHandlerWithMail(database, time.Now, false))

	if body.Configured == nil || *body.Configured {
		t.Errorf("configured = %v, want false", body.Configured)
	}
	if body.LastSentAt != nil || body.FailingSince != nil || body.LastError != nil {
		t.Errorf("a fresh, unconfigured instance reports %+v", body)
	}
	if body.Pending == nil || *body.Pending != 0 {
		t.Errorf("pending = %v, want 0", body.Pending)
	}
	if body.Suppressed == nil || *body.Suppressed != 0 {
		t.Errorf("suppressed = %v, want 0", body.Suppressed)
	}
}

// Configured and working: the last send is reported and nothing is
// failing.
func TestHandleMailReportsASuccessfulSend(t *testing.T) {
	database := openTempDB(t)
	now := time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)
	sentAt := now.Add(-2 * time.Hour)

	id := enqueue(t, database, "canary-iot", sentAt)
	if err := store.MarkMailSent(context.Background(), database, id, sentAt); err != nil {
		t.Fatalf("MarkMailSent: %v", err)
	}

	_, body := getMail(t, newHandlerWithMail(database, fixedNow(now), true))
	if body.Configured == nil || !*body.Configured {
		t.Errorf("configured = %v, want true", body.Configured)
	}
	if body.LastSentAt == nil {
		t.Fatal("last_sent_at is null after a successful send")
	}
	got, err := time.Parse(time.RFC3339Nano, *body.LastSentAt)
	if err != nil {
		t.Fatalf("parse last_sent_at %q: %v", *body.LastSentAt, err)
	}
	if !got.Equal(sentAt) {
		t.Errorf("last_sent_at = %s, want %s", got, sentAt)
	}
	if body.FailingSince != nil || body.LastError != nil {
		t.Errorf("a working mailer reports failing_since=%v last_error=%v", body.FailingSince, body.LastError)
	}
	if body.Pending == nil || *body.Pending != 0 {
		t.Errorf("pending = %v, want 0", body.Pending)
	}
}

// Failing: failing_since is the oldest unsent row that has actually
// been tried, and last_error is that same row's error -- the two always
// describe one failure.
func TestHandleMailReportsFailure(t *testing.T) {
	database := openTempDB(t)
	now := time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)
	failingSince := now.Add(-3 * time.Hour)

	id := enqueue(t, database, "canary-iot", failingSince)
	enqueue(t, database, "canary-lan", now.Add(-time.Hour)) // owed, never tried
	if err := store.RecordMailFailure(context.Background(), database, id,
		"could not send the token_conflict alert: TLS connect to smtp.example.invalid:465: connection refused",
		now.Add(time.Minute)); err != nil {
		t.Fatalf("RecordMailFailure: %v", err)
	}

	_, body := getMail(t, newHandlerWithMail(database, fixedNow(now), true))
	if body.FailingSince == nil {
		t.Fatal("failing_since is null while a message is failing")
	}
	got, err := time.Parse(time.RFC3339Nano, *body.FailingSince)
	if err != nil {
		t.Fatalf("parse failing_since %q: %v", *body.FailingSince, err)
	}
	if !got.Equal(failingSince) {
		t.Errorf("failing_since = %s, want the failing row's created_at %s", got, failingSince)
	}
	if body.LastError == nil || *body.LastError == "" {
		t.Error("last_error is empty while a message is failing")
	}
	if body.Pending == nil || *body.Pending != 2 {
		t.Errorf("pending = %v, want 2", body.Pending)
	}
}

// The route lives behind the same requireAuth seam as every other
// dashboard read, and answers only GET.
func TestHandleMailIsOnTheDashboardRouter(t *testing.T) {
	database := openTempDB(t)
	h := newHandlerWithMail(database, time.Now, false)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/mail", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/mail = %d, want 405", rec.Code)
	}

	rec, _ = getMail(t, h)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
