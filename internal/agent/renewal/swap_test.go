package renewal

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	keyFileName  = "client-key.pem"
	certFileName = "client.pem"
)

func writeFile(t *testing.T, path string, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data), true
}

// TestStageAndSwapEndToEnd proves the plain success path: staging files
// are consumed and the live pair becomes exactly the new key/cert.
func TestStageAndSwapEndToEnd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, keyFileName), "old-key")
	writeFile(t, filepath.Join(dir, certFileName), "old-cert")

	if err := StageAndSwap(dir, keyFileName, certFileName, []byte("new-key"), []byte("new-cert")); err != nil {
		t.Fatalf("StageAndSwap: %v", err)
	}

	if got, ok := readFile(t, filepath.Join(dir, keyFileName)); !ok || got != "new-key" {
		t.Fatalf("live key = %q, ok=%v, want new-key", got, ok)
	}
	if got, ok := readFile(t, filepath.Join(dir, certFileName)); !ok || got != "new-cert" {
		t.Fatalf("live cert = %q, ok=%v, want new-cert", got, ok)
	}
	if _, ok := readFile(t, filepath.Join(dir, keyFileName+stagingSuffix)); ok {
		t.Fatal("staging key file left behind after a successful swap")
	}
	if _, ok := readFile(t, filepath.Join(dir, certFileName+stagingSuffix)); ok {
		t.Fatal("staging cert file left behind after a successful swap")
	}

	// Perm check -- StageAndSwap must never leave the live files anything
	// but 0600, matching every other agent credential on disk.
	info, err := os.Stat(filepath.Join(dir, keyFileName))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestRecoverPendingSwapNothingStagedIsNoOp proves an ordinary boot with
// no interrupted renewal leaves the live pair completely untouched.
func TestRecoverPendingSwapNothingStagedIsNoOp(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, keyFileName), "live-key")
	writeFile(t, filepath.Join(dir, certFileName), "live-cert")

	if err := RecoverPendingSwap(dir, keyFileName, certFileName); err != nil {
		t.Fatalf("RecoverPendingSwap: %v", err)
	}
	if got, _ := readFile(t, filepath.Join(dir, keyFileName)); got != "live-key" {
		t.Fatalf("key = %q, want untouched live-key", got)
	}
	if got, _ := readFile(t, filepath.Join(dir, certFileName)); got != "live-cert" {
		t.Fatalf("cert = %q, want untouched live-cert", got)
	}
}

// TestRecoverPendingSwapBothStagedAppliesBoth proves the crash-before-
// any-rename case: both staging files present, live pair still old.
// Recovery must apply both.
func TestRecoverPendingSwapBothStagedAppliesBoth(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, keyFileName), "old-key")
	writeFile(t, filepath.Join(dir, certFileName), "old-cert")
	writeFile(t, filepath.Join(dir, keyFileName+stagingSuffix), "new-key")
	writeFile(t, filepath.Join(dir, certFileName+stagingSuffix), "new-cert")

	if err := RecoverPendingSwap(dir, keyFileName, certFileName); err != nil {
		t.Fatalf("RecoverPendingSwap: %v", err)
	}
	if got, _ := readFile(t, filepath.Join(dir, keyFileName)); got != "new-key" {
		t.Fatalf("key = %q, want new-key", got)
	}
	if got, _ := readFile(t, filepath.Join(dir, certFileName)); got != "new-cert" {
		t.Fatalf("cert = %q, want new-cert", got)
	}
}

// TestRecoverPendingSwapCertOnlyStagedFinishesSwap proves the crash-
// between-the-two-renames case: the key half already landed live (the
// staging key is gone), the cert half is still staged. Recovery must
// finish it, never leave the mismatched pair standing.
func TestRecoverPendingSwapCertOnlyStagedFinishesSwap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, keyFileName), "new-key") // already swapped
	writeFile(t, filepath.Join(dir, certFileName), "old-cert")
	writeFile(t, filepath.Join(dir, certFileName+stagingSuffix), "new-cert")

	if err := RecoverPendingSwap(dir, keyFileName, certFileName); err != nil {
		t.Fatalf("RecoverPendingSwap: %v", err)
	}
	if got, _ := readFile(t, filepath.Join(dir, keyFileName)); got != "new-key" {
		t.Fatalf("key = %q, want new-key", got)
	}
	if got, _ := readFile(t, filepath.Join(dir, certFileName)); got != "new-cert" {
		t.Fatalf("cert = %q, want new-cert (recovery must finish the interrupted swap)", got)
	}
}

// TestRecoverPendingSwapKeyOnlyStagedDiscardsIt proves the crash-during-
// staging case: only the key half was ever staged (the certificate half
// never got written), so the live pair was never touched. Recovery must
// discard the stray staged key rather than pairing it with the still-old
// live certificate.
func TestRecoverPendingSwapKeyOnlyStagedDiscardsIt(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, keyFileName), "old-key")
	writeFile(t, filepath.Join(dir, certFileName), "old-cert")
	writeFile(t, filepath.Join(dir, keyFileName+stagingSuffix), "half-staged-key")

	if err := RecoverPendingSwap(dir, keyFileName, certFileName); err != nil {
		t.Fatalf("RecoverPendingSwap: %v", err)
	}
	if got, _ := readFile(t, filepath.Join(dir, keyFileName)); got != "old-key" {
		t.Fatalf("key = %q, want untouched old-key (must not pair a stray staged key with the old cert)", got)
	}
	if got, _ := readFile(t, filepath.Join(dir, certFileName)); got != "old-cert" {
		t.Fatalf("cert = %q, want untouched old-cert", got)
	}
	if _, ok := readFile(t, filepath.Join(dir, keyFileName+stagingSuffix)); ok {
		t.Fatal("stray staged key left behind, want discarded")
	}
}

// TestRecoverPendingSwapIsIdempotent proves calling it twice in a row
// (e.g. StageAndSwap's own call, then a boot-time recovery pass finding
// nothing left) is harmless.
func TestRecoverPendingSwapIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, keyFileName), "old-key")
	writeFile(t, filepath.Join(dir, certFileName), "old-cert")
	writeFile(t, filepath.Join(dir, keyFileName+stagingSuffix), "new-key")
	writeFile(t, filepath.Join(dir, certFileName+stagingSuffix), "new-cert")

	if err := RecoverPendingSwap(dir, keyFileName, certFileName); err != nil {
		t.Fatalf("first RecoverPendingSwap: %v", err)
	}
	if err := RecoverPendingSwap(dir, keyFileName, certFileName); err != nil {
		t.Fatalf("second RecoverPendingSwap: %v", err)
	}
	if got, _ := readFile(t, filepath.Join(dir, keyFileName)); got != "new-key" {
		t.Fatalf("key = %q, want new-key", got)
	}
	if got, _ := readFile(t, filepath.Join(dir, certFileName)); got != "new-cert" {
		t.Fatalf("cert = %q, want new-cert", got)
	}
}
