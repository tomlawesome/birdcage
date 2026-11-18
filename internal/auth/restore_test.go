package auth_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #164 (note 63923): the first registration writes the one-way
// accounts_initialised marker and spends a `birdcage auth reset`
// acknowledgement; AccountCount follows the accounts store without
// announcing a code.
func TestRegistrationMarksAccountsInitialisedAndSpendsTheReset(t *testing.T) {
	ctx := context.Background()
	database := openDatabase(t)
	key := testKey('r')

	if _, err := auth.AccountCount(ctx, database, key[:8]); err == nil {
		t.Error("AccountCount with a short key: error = nil, want a refusal")
	}
	if n, err := auth.AccountCount(ctx, database, key); err != nil || n != 0 {
		t.Fatalf("AccountCount on a new database = %d, %v; want 0, nil", n, err)
	}
	if err := store.RecordAccountsReset(ctx, database, time.Now()); err != nil {
		t.Fatalf("RecordAccountsReset: %v", err)
	}

	sys := startSystem(t, database, key)
	status, body := post(t, newClient(t), sys.server.URL+"/api/auth/register", map[string]string{
		"username": testAdminName, "password": testAdminPassword, "setupCode": sys.log.setupCodes()[0],
	})
	if status != http.StatusCreated {
		t.Fatalf("register first admin: status %d, want 201; body=%s", status, body)
	}
	if acked, err := store.AccountsResetAcknowledged(ctx, database); err != nil || acked {
		t.Errorf("acknowledged after the first admin registered = %v, %v; want false (spent)", acked, err)
	}
	h, err := store.ReadAccountHistory(ctx, database)
	if err != nil || !h.Initialised || h.Registrations != 1 {
		t.Errorf("account history after registration = %+v, %v; want the marker and one user.register row", h, err)
	}
	if n, err := auth.AccountCount(ctx, database, key); err != nil || n != 1 {
		t.Errorf("AccountCount after registration = %d, %v; want 1, nil", n, err)
	}
	if _, err := auth.AccountCount(ctx, database, testKey('x')); err == nil {
		t.Error("AccountCount with the wrong key: error = nil, want a refusal")
	}
}
