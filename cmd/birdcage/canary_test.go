package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/ingest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// insertTestCanary registers canaryID in the canaries table so
// store.RevokeCanaryCredentials (which, unlike a plain token mint, does
// require a canaries row -- see its ErrCanaryNotFound) has something to
// find. A canary token can exist with no matching canaries row (the two
// tables carry no foreign key), but a canary's credentials cannot be
// revoked as a canary until it is registered.
func insertTestCanary(t *testing.T, database *db.DB, canaryID string) {
	t.Helper()
	if err := store.InsertCanary(context.Background(), database, store.Canary{
		ID: canaryID, Name: canaryID, Lane: "lan", Kind: agentkind.Honeypot,
		HeartbeatIntervalS: store.DefaultHeartbeatIntervalS, EnrolledAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("insertTestCanary(%s): %v", canaryID, err)
	}
}

// testDBPath points BIRDCAGE_DB_PATH at a fresh SQLite file per test, so
// each test's canary tokens and audit rows are isolated. Postgres is not
// exercised here: these CLI commands go through the same internal/store
// functions internal/ingest already tests against both engines
// (forEachEngine), so this file's job is the CLI wiring -- argument
// handling, output shape, and the mint/revoke-plus-audit transactions --
// not re-proving store behavior per engine.
func testDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "birdcage-cli-test.db")
}

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything fn printed. Not safe to run in parallel with another test
// doing the same (os.Stdout is process-global), which is why no test in
// this file calls t.Parallel().
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fnErr := fn()
	if cerr := w.Close(); cerr != nil {
		t.Fatalf("close pipe writer: %v", cerr)
	}
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out), fnErr
}

// extractMintedToken pulls the raw token value out of runCanaryMint's
// printed output.
func extractMintedToken(t *testing.T, mintOutput string) string {
	t.Helper()
	const marker = "token (shown once, record it now): "
	idx := strings.Index(mintOutput, marker)
	if idx < 0 {
		t.Fatalf("mint output %q missing token marker", mintOutput)
	}
	line, _, _ := strings.Cut(mintOutput[idx+len(marker):], "\n")
	return strings.TrimSpace(line)
}

// extractMintedTokenID pulls the token id (canary_tokens.id, not the raw
// token) out of runCanaryMint's printed output.
func extractMintedTokenID(t *testing.T, mintOutput string) string {
	t.Helper()
	const prefix = "minted token "
	if !strings.HasPrefix(mintOutput, prefix) {
		t.Fatalf("mint output %q missing %q prefix", mintOutput, prefix)
	}
	id, _, found := strings.Cut(strings.TrimPrefix(mintOutput, prefix), " for agent ")
	if !found {
		t.Fatalf("mint output %q missing ' for agent ' marker", mintOutput)
	}
	return id
}

// heartbeatStatus sends a minimal, well-formed POST /ingest/heartbeat
// request bearing raw as its token and returns the response status. A
// canary token with no matching canaries row still authenticates (the
// two tables carry no foreign key, per 0004_canary_tokens.sql) and gets
// 404 further in, not 401 -- so any non-401 status here is proof the
// token itself was accepted, which is all these tests need: they compare
// this status before and after revocation, never assert a specific
// success code.
func heartbeatStatus(h http.Handler, raw string) int {
	req := httptest.NewRequest(http.MethodPost, "/ingest/heartbeat",
		strings.NewReader(`{"queue_depth":0,"log_read_ok":true}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestCanaryListNeverPrintsAToken is issue #32 slice 6's first required
// test: "list never prints a token". Proved two ways, both stricter than
// "does not repeat the exact raw string": list's output must contain
// neither the raw value mint just produced, nor its SHA-256 hash (the
// form actually stored in canary_tokens.token_hash) -- store.CanaryToken
// (what ListCanaryTokens reads and runCanaryList prints) has no field
// for either, so this also stands as a regression test against a future
// change that adds one.
func TestCanaryListNeverPrintsAToken(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	mintOut, err := captureStdout(t, func() error { return runCanaryMint([]string{"canary-list-test"}) })
	if err != nil {
		t.Fatalf("runCanaryMint: %v", err)
	}
	raw := extractMintedToken(t, mintOut)
	hash := store.HashToken(raw)

	listOut, err := captureStdout(t, func() error { return runCanaryList(nil) })
	if err != nil {
		t.Fatalf("runCanaryList: %v", err)
	}

	if strings.Contains(listOut, raw) {
		t.Fatalf("list output contains the raw token value: %q", listOut)
	}
	if strings.Contains(listOut, hash) {
		t.Fatalf("list output contains the token's hash: %q", listOut)
	}
	if !strings.Contains(listOut, "canary-list-test") {
		t.Fatalf("list output = %q, want it to mention canary-list-test", listOut)
	}
}

// TestCanaryRevokeTakesEffectImmediately is issue #32 slice 6's second
// required test: "revoke takes effect immediately". A token that
// authenticates a request before runCanaryRevoke is refused (401) on the
// very next request after it, with no delay and nothing else changed --
// proving store.RevokeCanaryToken's write and the ingest auth path's
// fresh-per-request lookup (internal/ingest/auth.go via
// store.LookupCanaryTokenByHash) actually compose the way both are
// documented to.
func TestCanaryRevokeTakesEffectImmediately(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	mintOut, err := captureStdout(t, func() error { return runCanaryMint([]string{"canary-revoke-test"}) })
	if err != nil {
		t.Fatalf("runCanaryMint: %v", err)
	}
	raw := extractMintedToken(t, mintOut)

	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	insertTestCanary(t, database, "canary-revoke-test")
	h := ingest.NewHandler(database, nil, store.NewSelfTestIndex(), nil)

	if status := heartbeatStatus(h, raw); status == http.StatusUnauthorized {
		t.Fatalf("token was refused (401) before revocation; test setup is broken")
	}

	if _, err := captureStdout(t, func() error { return runCanaryRevoke([]string{"canary-revoke-test"}) }); err != nil {
		t.Fatalf("runCanaryRevoke: %v", err)
	}

	if status := heartbeatStatus(h, raw); status != http.StatusUnauthorized {
		t.Fatalf("revoked token still authenticates: status = %d, want %d", status, http.StatusUnauthorized)
	}
}

// TestCanaryRevokeRecordsAuditEntries proves issue #32 item 10 for the
// CLI path specifically: mint and revoke are each written to the audit
// log, under the canary they act on.
func TestCanaryMintAndRevokeRecordAuditEntries(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	insertTestCanary(t, database, "canary-audit-test")
	closeCanaryDB(database)

	if _, err := captureStdout(t, func() error { return runCanaryMint([]string{"canary-audit-test"}) }); err != nil {
		t.Fatalf("runCanaryMint: %v", err)
	}

	if _, err := captureStdout(t, func() error { return runCanaryRevoke([]string{"canary-audit-test"}) }); err != nil {
		t.Fatalf("runCanaryRevoke: %v", err)
	}

	database, err = openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)

	var mintCount, revokeCount int
	if err := database.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action = ? AND target = ?`,
		"canary.token_minted", "canary-audit-test").Scan(&mintCount); err != nil {
		t.Fatalf("count mint audit rows: %v", err)
	}
	if mintCount != 1 {
		t.Errorf("canary.token_minted audit rows for canary-audit-test = %d, want 1", mintCount)
	}
	if err := database.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action = ? AND target = ?`,
		"canary.revoked", "canary-audit-test").Scan(&revokeCount); err != nil {
		t.Fatalf("count revoke audit rows: %v", err)
	}
	if revokeCount != 1 {
		t.Errorf("canary.revoked audit rows for canary-audit-test = %d, want 1", revokeCount)
	}
}

// TestCanaryMintFailsWithFailedAuditWrite is issue #32 item 10's
// fail-closed rule applied to the CLI mint path: "a mint ... whose audit
// write fails, fails with it". audit_log is dropped so canary_tokens is
// still writable and only the audit append fails, mirroring
// internal/ingest/rotate_test.go's
// TestRotateAuditFailureReturns503LeavesPresentedTokenWorkingAndNoUsableNewToken.
// Proves the command errors out, and that the mint did not persist: the
// transaction rolled back rather than leaving an orphaned, usable token
// with no audit trail behind it.
func TestCanaryMintFailsWithFailedAuditWrite(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	if _, err := database.Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatalf("drop audit_log: %v", err)
	}
	closeCanaryDB(database)

	if _, err := captureStdout(t, func() error { return runCanaryMint([]string{"canary-mint-fail-test"}) }); err == nil {
		t.Fatal("runCanaryMint succeeded despite a failed audit write, want an error")
	}

	database, err = openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB (recheck): %v", err)
	}
	defer closeCanaryDB(database)
	var n int
	if err := database.QueryRow(`SELECT COUNT(*) FROM agent_tokens WHERE agent_id = ?`, "canary-mint-fail-test").Scan(&n); err != nil {
		t.Fatalf("count canary_tokens: %v", err)
	}
	if n != 0 {
		t.Fatalf("canary_tokens rows for canary-mint-fail-test = %d, want 0 (the failed mint must not persist)", n)
	}
}

// TestCanaryRevokeFailsWithFailedAuditWriteAndTokenStaysLive is issue
// #32 item 10's fail-closed rule applied to the CLI revoke path: "a ...
// revoke whose audit write fails, fails with it". If the revoke's own
// UPDATE were allowed to commit while only its audit entry failed, a
// revocation would be silently unrecorded and the token would still
// stop working -- the reverse of "fails with it". This proves the
// stronger, transactional guarantee instead: the token is still live
// afterwards, exactly as internal/ingest/rotate.go's fail-closed
// rotation mint leaves the presented token untouched by a failed audit
// write.
func TestCanaryRevokeFailsWithFailedAuditWriteAndTokenStaysLive(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	mintOut, err := captureStdout(t, func() error { return runCanaryMint([]string{"canary-revoke-fail-test"}) })
	if err != nil {
		t.Fatalf("runCanaryMint: %v", err)
	}
	raw := extractMintedToken(t, mintOut)

	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	insertTestCanary(t, database, "canary-revoke-fail-test")
	if _, err := database.Exec(`DROP TABLE audit_log`); err != nil {
		t.Fatalf("drop audit_log: %v", err)
	}
	closeCanaryDB(database)

	if _, err := captureStdout(t, func() error { return runCanaryRevoke([]string{"canary-revoke-fail-test"}) }); err == nil {
		t.Fatal("runCanaryRevoke succeeded despite a failed audit write, want an error")
	}

	database, err = openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB (recheck): %v", err)
	}
	defer closeCanaryDB(database)
	h := ingest.NewHandler(database, nil, store.NewSelfTestIndex(), nil)
	if status := heartbeatStatus(h, raw); status == http.StatusUnauthorized {
		t.Fatal("token stopped authenticating despite the revoke failing; the revoke must roll back with its audit write")
	}
}

// TestCanaryRevokeUnknownID proves #130's B5 CLI path refuses a
// mistyped or nonexistent canary id (store.ErrCanaryNotFound) rather
// than silently doing nothing.
func TestCanaryRevokeUnknownID(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	err := runCanaryRevoke([]string{"no-such-canary"})
	if !errors.Is(err, store.ErrCanaryNotFound) {
		t.Fatalf("runCanaryRevoke(no-such-canary) err = %v, want ErrCanaryNotFound", err)
	}
}

// TestCanaryOutputEscapesControlCharactersInID is issue #52's proof for
// the CLI: a canary id containing a terminal control sequence -- here
// ESC "[2J" (\x1b[2J), which clears the screen -- must reach mint,
// list, and revoke's stdout as literal escaped text, never as the raw
// ESC byte a terminal would act on. The stored value is untouched
// throughout: SECURITY.md's rule is that birdcage never strips or
// rewrites text it didn't generate at the point of storage, only at the
// point it prints it, so the row is read back directly (bypassing every
// command's own stdout) and compared against the original, unescaped
// string.
func TestCanaryOutputEscapesControlCharactersInID(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	const canaryID = "canary-\x1b[2J-evil"

	mintOut, err := captureStdout(t, func() error { return runCanaryMint([]string{canaryID}) })
	if err != nil {
		t.Fatalf("runCanaryMint: %v", err)
	}
	assertNoRawESC(t, "mint", mintOut)
	if !strings.Contains(mintOut, `canary-\x1b[2J-evil`) {
		t.Fatalf("mint output %q does not contain the escaped canary id", mintOut)
	}
	tokenID := extractMintedTokenID(t, mintOut)

	listOut, err := captureStdout(t, func() error { return runCanaryList(nil) })
	if err != nil {
		t.Fatalf("runCanaryList: %v", err)
	}
	assertNoRawESC(t, "list", listOut)
	if !strings.Contains(listOut, `canary-\x1b[2J-evil`) {
		t.Fatalf("list output %q does not contain the escaped canary id", listOut)
	}

	setupDB, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	insertTestCanary(t, setupDB, canaryID)
	closeCanaryDB(setupDB)

	revokeOut, err := captureStdout(t, func() error { return runCanaryRevoke([]string{canaryID}) })
	if err != nil {
		t.Fatalf("runCanaryRevoke: %v", err)
	}
	assertNoRawESC(t, "revoke", revokeOut)
	if !strings.Contains(revokeOut, `canary-\x1b[2J-evil`) {
		t.Fatalf("revoke output %q does not contain the escaped canary id", revokeOut)
	}

	// The stored row is read back directly, not through any command's
	// stdout, and must still carry the original, unaltered byte -- proof
	// that escaping happened only at the three print sites above, never
	// on the way into the database.
	database, err := openCanaryDB()
	if err != nil {
		t.Fatalf("openCanaryDB: %v", err)
	}
	defer closeCanaryDB(database)
	tokens, err := store.ListCanaryTokens(context.Background(), database)
	if err != nil {
		t.Fatalf("store.ListCanaryTokens: %v", err)
	}
	found := false
	for _, tok := range tokens {
		if tok.ID != tokenID {
			continue
		}
		found = true
		if tok.CanaryID != canaryID {
			t.Fatalf("stored canary_id = %q, want the original %q byte-for-byte", tok.CanaryID, canaryID)
		}
	}
	if !found {
		t.Fatalf("token %s not found via store.ListCanaryTokens", tokenID)
	}
}

// assertNoRawESC fails t if out contains a raw ESC byte (0x1b) -- the
// exact-bytes assertion issue #52 asks for, not just "the text looks
// escaped".
func assertNoRawESC(t *testing.T, label, out string) {
	t.Helper()
	for _, b := range []byte(out) {
		if b == 0x1b {
			t.Fatalf("%s output %q contains a raw ESC byte", label, out)
		}
	}
}

// TestCanaryOutputLeavesOrdinaryAndNonASCIINamesUnchanged proves the
// other half of issue #52's rule: an operator naming a canary in
// Japanese must still be able to read it back, unmangled, from list.
func TestCanaryOutputLeavesOrdinaryAndNonASCIINamesUnchanged(t *testing.T) {
	t.Setenv(envDBPath, testDBPath(t))

	const canaryID = "canary-カナリア-東京"

	if _, err := captureStdout(t, func() error { return runCanaryMint([]string{canaryID}) }); err != nil {
		t.Fatalf("runCanaryMint: %v", err)
	}

	listOut, err := captureStdout(t, func() error { return runCanaryList(nil) })
	if err != nil {
		t.Fatalf("runCanaryList: %v", err)
	}
	if !strings.Contains(listOut, canaryID) {
		t.Fatalf("list output %q does not contain the unaltered canary id %q", listOut, canaryID)
	}
}
