package auth_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/db"
)

const (
	testPlainName     = "ordinary-user"
	testPlainPassword = "lantern cobalt thistle 58 meadow"
)

// recordingRunner stands in for the self-test scheduler behind the admin
// routes: it counts run-now requests and answers as the scheduler does.
type recordingRunner struct{ calls []string }

func (r *recordingRunner) RunNow(_ context.Context, canaryID string) (string, bool, error) {
	r.calls = append(r.calls, canaryID)
	return "cmd-" + canaryID, true, nil
}

// startAdminSystem is startSystem with the admin write routes mounted
// (Service.WrapWithAdmin) and BIRDCAGE_PUBLIC_URL set to the test
// server's own address, so a matching Origin is the server's own URL.
func startAdminSystem(t *testing.T, database *db.DB, key []byte) (*system, *recordingRunner) {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	publicURL := "http://" + server.Listener.Addr().String()
	logger, capture := newLogCapture()
	svc, err := auth.Open(context.Background(), database, auth.Config{Key: key, PublicURL: publicURL}, logger)
	if err != nil {
		t.Fatalf("auth.Open: %v", err)
	}
	t.Cleanup(svc.Close)
	svc.ReleaseCodes()
	runner := &recordingRunner{}
	mux := http.NewServeMux()
	mux.Handle("/api/", api.NewHandler(database, nil, "test"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<!doctype html><title>birdcage frontend stand-in</title>")
	})
	admin := api.NewAdminHandler(database, nil, runner)
	server.Config.Handler = svc.WrapWithAdmin(mux, admin)
	server.Start()
	t.Cleanup(server.Close)
	return &system{svc: svc, log: capture, server: server, database: database}, runner
}

// signInPlainUser has the signed-in admin create an ordinary (role "user")
// account and returns a client signed in as it.
func (s *system) signInPlainUser(t *testing.T, admin *http.Client) *http.Client {
	t.Helper()
	status, body := post(t, admin, s.server.URL+"/api/auth/users", map[string]string{
		"username": testPlainName, "password": testPlainPassword, "role": "user",
	})
	if status != http.StatusCreated {
		t.Fatalf("create ordinary user: status %d, want 201; body=%s", status, body)
	}
	client := newClient(t)
	status, body = post(t, client, s.server.URL+"/api/auth/login", map[string]string{"username": testPlainName, "password": testPlainPassword})
	if status != http.StatusOK {
		t.Fatalf("ordinary user sign-in: status %d, want 200; body=%s", status, body)
	}
	base := s.server.URL
	status, body = post(t, client, base+"/api/auth/totp/enrol", map[string]string{"password": testPlainPassword})
	var enrol struct {
		Secret string `json:"secret"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &enrol) != nil || enrol.Secret == "" {
		t.Fatalf("ordinary user enrol authenticator: status %d; body=%s", status, body)
	}
	if status, body = post(t, client, base+"/api/auth/totp/confirm", map[string]string{"code": totpCode(t, enrol.Secret, counterNow())}); status != http.StatusOK {
		t.Fatalf("ordinary user confirm authenticator: status %d; body=%s", status, body)
	}
	if status, body = post(t, client, base+"/api/auth/recovery-codes/confirm", struct{}{}); status != http.StatusOK {
		t.Fatalf("ordinary user confirm recovery codes: status %d; body=%s", status, body)
	}
	signedIn := newClient(t)
	if status, body = post(t, signedIn, base+"/api/auth/login", map[string]string{"username": testPlainName, "password": testPlainPassword}); status != http.StatusOK {
		t.Fatalf("ordinary user password step: status %d; body=%s", status, body)
	}
	if status, body = post(t, signedIn, base+"/api/auth/login/factor", map[string]string{"code": totpCode(t, enrol.Secret, counterNow()+1)}); status != http.StatusOK {
		t.Fatalf("ordinary user factor step: status %d; body=%s", status, body)
	}
	if st, b := call(t, signedIn, http.MethodGet, base+"/api/alerts", nil, nil); st != http.StatusOK {
		t.Fatalf("ordinary user cannot read the dashboard after sign-in: status %d; body=%s", st, b)
	}
	return signedIn
}
