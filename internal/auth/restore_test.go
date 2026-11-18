package auth_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/auth"
)

// Issue #164: the restore guard's building blocks. The reset
// acknowledgement is recorded, read back, and spent when the first admin
// registers; AccountCount follows the accounts store without announcing
// a code.
func TestAccountsResetIsSpentAtRegistration(t *testing.T) {
	ctx := context.Background()
	database := openDatabase(t)
	key := testKey('r')

	if _, err := auth.AccountCount(ctx, database, key[:8]); err == nil {
		t.Error("AccountCount with a short key: error = nil, want a refusal")
	}
	if n, err := auth.AccountCount(ctx, database, key); err != nil || n != 0 {
		t.Fatalf("AccountCount on a new database = %d, %v; want 0, nil", n, err)
	}
	if acked, err := auth.AccountsResetAcknowledged(ctx, database); err != nil || acked {
		t.Fatalf("acknowledged before any reset = %v, %v; want false, nil", acked, err)
	}
	for i := 0; i < 2; i++ { // recording twice keeps one acknowledgement
		if err := auth.RecordAccountsReset(ctx, database, time.Now()); err != nil {
			t.Fatalf("RecordAccountsReset: %v", err)
		}
	}
	if acked, err := auth.AccountsResetAcknowledged(ctx, database); err != nil || !acked {
		t.Fatalf("acknowledged after a reset = %v, %v; want true, nil", acked, err)
	}

	sys := startSystem(t, database, key)
	status, body := post(t, newClient(t), sys.server.URL+"/api/auth/register", map[string]string{
		"username": testAdminName, "password": testAdminPassword, "setupCode": sys.log.setupCodes()[0],
	})
	if status != http.StatusCreated {
		t.Fatalf("register first admin: status %d, want 201; body=%s", status, body)
	}
	if acked, err := auth.AccountsResetAcknowledged(ctx, database); err != nil || acked {
		t.Errorf("acknowledged after the first admin registered = %v, %v; want false (spent)", acked, err)
	}
	if n, err := auth.AccountCount(ctx, database, key); err != nil || n != 1 {
		t.Errorf("AccountCount after registration = %d, %v; want 1, nil", n, err)
	}
	if _, err := auth.AccountCount(ctx, database, testKey('x')); err == nil {
		t.Error("AccountCount with the wrong key: error = nil, want a refusal")
	}
}
