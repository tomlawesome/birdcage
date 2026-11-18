package auth

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// auditTimeout bounds each audit write, so a stuck database cannot hold a
// sign-in request open.
const auditTimeout = 5 * time.Second

// auditor writes gauntlet's account and token events (user.login,
// user.login_failed, token.create, ...) to birdcage's audit log. The audit
// trail is required (ASVS 5.0 V16, ADR-0001), but gauntlet's Record has no error
// return and cannot fail the request, so a write that fails is logged and
// the request carries on.
type auditor struct {
	db  *db.DB
	log *slog.Logger
}

// Record maps actor to triggered_by, action to action, target to target and
// detail to reason. Append refuses blank fields and losing the record is
// worse, so a blank field is stored as "-".
func (a auditor) Record(actor, action, target, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), auditTimeout)
	defer cancel()
	now := time.Now().UTC()
	entry := audit.Entry{
		Action:      nonBlank(action),
		Target:      nonBlank(target),
		Reason:      nonBlank(detail),
		TriggeredBy: nonBlank(actor),
		CreatedAt:   now,
	}
	var err error
	if action == "user.register" {
		err = a.recordRegistration(ctx, entry)
	} else {
		_, err = audit.Append(ctx, a.db, entry)
	}
	if err != nil {
		a.log.Error("auth: audit write failed", "action", action, "err", err)
	}
}

// recordRegistration writes the user.register row together with the
// restore guard's one-way accounts_initialised marker, and spends any
// `birdcage auth reset` acknowledgement, in one transaction (issue #164,
// note 63923). Gauntlet calls Record after its own account save, outside
// that transaction, so a crash between the two can leave an account with
// no marker; start-up writes the marker whenever it sees an account, which
// closes that gap. A gauntlet hook inside its account transaction would be
// the ideal place for this; it does not exist yet.
func (a auditor) recordRegistration(ctx context.Context, entry audit.Entry) error {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, entry); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := store.MarkAccountsInitialised(ctx, tx, entry.CreatedAt); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := store.SpendAccountsReset(ctx, tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// nonBlank returns s, or "-" when s is empty after trimming.
func nonBlank(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
