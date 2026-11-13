package authstore_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/tomlawesome/gauntlet/persist"
	"github.com/tomlawesome/gauntlet/persist/persisttest"

	"github.com/tomlawesome/birdcage/internal/authstore"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
)

// TestBackendKeepsGauntletsPersistContract runs gauntlet's own conformance
// suite (persisttest.Run) against NewBackend on every engine under test
// (SQLite always; Postgres when BIRDCAGE_TEST_DATABASE_URL is set).
//
// persisttest asks for empty storage for every check. One migrated database
// serves all of them, and each check gets a store name nobody has used, so
// each starts with no row. The backends a check opens share that name, as
// two processes over one store would. Closing a backend must leave the
// shared database open.
func TestBackendKeepsGauntletsPersistContract(t *testing.T) {
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			var next atomic.Int64
			persisttest.Run(t, func(t testing.TB) func() persist.Backend {
				name := fmt.Sprintf("conformance-%d", next.Add(1))
				return func() persist.Backend { return authstore.NewBackend(tgt.DB, name) }
			})
		})
	}
}

// TestBackendUsesOneRowPerNameInAuthDocuments: the document of each store
// lives in its own auth_documents row, keyed by name, and the row's version
// is what Load reports.
func TestBackendUsesOneRowPerNameInAuthDocuments(t *testing.T) {
	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			ctx := context.Background()
			accounts := authstore.NewBackend(tgt.DB, "accounts")
			tokens := authstore.NewBackend(tgt.DB, "tokens")
			t.Cleanup(func() { _ = accounts.Close(); _ = tokens.Close() })

			v1, err := accounts.Save(ctx, []byte(`{"n":1}`), 0)
			if err != nil {
				t.Fatalf("accounts first Save: %v", err)
			}
			if _, err := accounts.Save(ctx, []byte(`{"n":2}`), v1); err != nil {
				t.Fatalf("accounts second Save: %v", err)
			}
			if _, err := tokens.Save(ctx, []byte(`{"t":1}`), 0); err != nil {
				t.Fatalf("tokens first Save: %v", err)
			}

			rowCount := func(name string) int {
				var n int
				if err := tgt.DB.QueryRow(`SELECT COUNT(*) FROM auth_documents WHERE name = ?`, name).Scan(&n); err != nil {
					t.Fatalf("count rows named %s: %v", name, err)
				}
				return n
			}
			if n := rowCount("accounts"); n != 1 {
				t.Errorf("auth_documents rows named accounts = %d, want 1", n)
			}
			if n := rowCount("tokens"); n != 1 {
				t.Errorf("auth_documents rows named tokens = %d, want 1", n)
			}

			snap, err := accounts.Load(ctx)
			if err != nil {
				t.Fatalf("accounts Load: %v", err)
			}
			var stored int64
			if err := tgt.DB.QueryRow(`SELECT version FROM auth_documents WHERE name = ?`, "accounts").Scan(&stored); err != nil {
				t.Fatalf("read stored version: %v", err)
			}
			if !snap.Exists || snap.Version != stored || string(snap.Payload) != `{"n":2}` {
				t.Errorf("Load = %+v, want exists, version %d (the stored one), payload {\"n\":2}", snap, stored)
			}

			other, err := tokens.Load(ctx)
			if err != nil {
				t.Fatalf("tokens Load: %v", err)
			}
			if string(other.Payload) != `{"t":1}` {
				t.Errorf("tokens payload = %q, want {\"t\":1}: stores must not share a row", other.Payload)
			}
		})
	}
}
