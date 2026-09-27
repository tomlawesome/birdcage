package upgradetoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testToken is 64 lowercase hex characters, built so it reads as the
// placeholder it is.
var testToken = strings.Repeat("0123456789abcdef", 4)

const testBearer = "bearer-token-for-the-test"

func selfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// stateDir writes an enrolled agent's state files, pointing at ts, and
// returns the directory.
func stateDir(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	dir := t.TempDir()
	cert, key := selfSigned(t)
	files := map[string][]byte{
		ingestURLFileName:  []byte(ts.URL + "\n"),
		caFileName:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}),
		clientCertFileName: cert,
		clientKeyFileName:  key,
		tokenFileName:      []byte(testBearer + "\n"),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// snapshot is every file in dir with its contents and mode, so a test
// can prove Run wrote nothing.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e.Name()+" "+info.Mode().String()+" "+info.ModTime().String()+" "+string(b))
	}
	sort.Strings(out)
	return strings.Join(out, "\n")
}

// fakeBirdcage answers POST /ingest/upgrade-token with each of answers
// in turn (status, body), recording what it was sent.
type fakeBirdcage struct {
	answers []struct {
		status int
		body   string
	}
	calls   atomic.Int32
	bodies  []string
	bearers []string
}

func (f *fakeBirdcage) serve(t *testing.T) *httptest.Server {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ingest/upgrade-token" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		f.bodies = append(f.bodies, string(b))
		f.bearers = append(f.bearers, r.Header.Get("Authorization"))
		i := int(f.calls.Add(1)) - 1
		if i >= len(f.answers) {
			i = len(f.answers) - 1
		}
		w.WriteHeader(f.answers[i].status)
		_, _ = w.Write([]byte(f.answers[i].body))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (f *fakeBirdcage) answer(status int, body string) *fakeBirdcage {
	f.answers = append(f.answers, struct {
		status int
		body   string
	}{status, body})
	return f
}

func noSleep(context.Context, time.Duration) error { return nil }

func run(t *testing.T, dir, stdin string) (string, error) {
	t.Helper()
	var out strings.Builder
	err := Run(context.Background(), Options{StateDir: dir, Stdin: strings.NewReader(stdin), Stdout: &out, Sleep: noSleep})
	return out.String(), err
}

// TestRunAccepted: the token goes to birdcage once, in the body, over
// the agent's own bearer token; the one line printed says accepted and
// never repeats the token; and the state directory is untouched.
func TestRunAccepted(t *testing.T) {
	f := (&fakeBirdcage{}).answer(http.StatusOK, `{"outcome":"accepted","window_until":"2026-09-27T12:05:00Z"}`)
	ts := f.serve(t)
	dir := stateDir(t, ts)
	before := snapshot(t, dir)

	out, err := run(t, dir, "  "+testToken+"\n")
	if err != nil {
		t.Fatalf("Run: %v (output %q)", err, out)
	}
	if out != "upgrade token accepted: until 2026-09-27T12:05:00Z birdcage will not flag this agent's old build as credential_conflict\n" {
		t.Errorf("output = %q", out)
	}
	if strings.Contains(out, testToken) {
		t.Error("the output repeats the token")
	}
	if f.calls.Load() != 1 {
		t.Errorf("birdcage was called %d times, want 1", f.calls.Load())
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(f.bodies[0]), &body); err != nil || body["upgrade_token"] != testToken || len(body) != 1 {
		t.Errorf("body = %s, want exactly the token", f.bodies[0])
	}
	if f.bearers[0] != "Bearer "+testBearer {
		t.Errorf("Authorization = %q, want the agent's own bearer token", f.bearers[0])
	}
	if after := snapshot(t, dir); after != before {
		t.Errorf("the state directory changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestRunRefused: a refusal is ErrRefused and says why.
func TestRunRefused(t *testing.T) {
	ts := (&fakeBirdcage{}).answer(http.StatusOK, `{"outcome":"refused","reason":"already used"}`).serve(t)
	out, err := run(t, stateDir(t, ts), testToken)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
	if !strings.HasPrefix(out, "upgrade token refused: already used.") {
		t.Errorf("output = %q", out)
	}
}

// TestRunRetriesUntilAnswered: birdcage briefly unavailable is retried;
// its first real answer ends the run.
func TestRunRetriesUntilAnswered(t *testing.T) {
	f := (&fakeBirdcage{}).
		answer(http.StatusServiceUnavailable, `{"error":"service unavailable"}`).
		answer(http.StatusTooManyRequests, `{"error":"rate limit exceeded"}`).
		answer(http.StatusOK, `{"outcome":"accepted","window_until":"2026-09-27T12:05:00Z"}`)
	ts := f.serve(t)
	if _, err := run(t, stateDir(t, ts), testToken); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if f.calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", f.calls.Load())
	}
}

// TestRunGivesUp: never answered within RetryFor is ErrRefused, having
// said so.
func TestRunGivesUp(t *testing.T) {
	ts := (&fakeBirdcage{}).answer(http.StatusServiceUnavailable, `{"error":"service unavailable"}`).serve(t)
	var out strings.Builder
	err := Run(context.Background(), Options{
		StateDir: stateDir(t, ts), Stdin: strings.NewReader(testToken), Stdout: &out,
		RetryFor: 3 * time.Second, Sleep: func(context.Context, time.Duration) error { time.Sleep(10 * time.Millisecond); return nil },
	})
	if !errors.Is(err, ErrRefused) || !strings.HasPrefix(out.String(), "upgrade token not presented: birdcage did not answer") {
		t.Errorf("err = %v, output %q", err, out.String())
	}
}

// TestRunUnauthorized: the agent's own credential refused is final.
func TestRunUnauthorized(t *testing.T) {
	f := (&fakeBirdcage{}).answer(http.StatusUnauthorized, `{"error":"unauthorized"}`)
	ts := f.serve(t)
	out, err := run(t, stateDir(t, ts), testToken)
	if !errors.Is(err, ErrRefused) || !strings.Contains(out, "(401)") || f.calls.Load() != 1 {
		t.Errorf("err = %v, output %q, calls %d", err, out, f.calls.Load())
	}
}

// TestRunRejectsInputThatIsNotAToken: nothing reaches birdcage, and the
// error never echoes what was read.
func TestRunRejectsInputThatIsNotAToken(t *testing.T) {
	f := (&fakeBirdcage{}).answer(http.StatusOK, `{"outcome":"accepted","window_until":"2026-09-27T12:05:00Z"}`)
	ts := f.serve(t)
	dir := stateDir(t, ts)
	for _, in := range []string{
		"",
		"\n",
		testToken[:63],
		strings.ToUpper(testToken),
		testToken + " " + testToken,
		"secret-looking-value-" + strings.Repeat("x", 300),
	} {
		out, err := run(t, dir, in)
		if !errors.Is(err, ErrUsage) {
			t.Errorf("input %q: err = %v, want ErrUsage", in, err)
		}
		if strings.Contains(out, "secret-looking-value") || (len(in) > 10 && strings.Contains(out, strings.TrimSpace(in))) {
			t.Errorf("input %q echoed in %q", in, out)
		}
	}
	if f.calls.Load() != 0 {
		t.Errorf("birdcage was called %d times for input that is not a token", f.calls.Load())
	}
}

// TestRunMissingState: a state directory without a credential names the
// missing file by its bare name, never the directory.
func TestRunMissingState(t *testing.T) {
	ts := (&fakeBirdcage{}).answer(http.StatusOK, `{}`).serve(t)
	dir := stateDir(t, ts)
	if err := os.Remove(filepath.Join(dir, clientKeyFileName)); err != nil {
		t.Fatal(err)
	}
	_, err := run(t, dir, testToken)
	if err == nil || !strings.Contains(err.Error(), clientKeyFileName) || strings.Contains(err.Error(), dir) {
		t.Errorf("err = %v, want one naming %s and not the directory", err, clientKeyFileName)
	}
}
