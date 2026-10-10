package auth

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
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
	_, err := audit.Append(ctx, a.db, audit.Entry{
		Action:      nonBlank(action),
		Target:      nonBlank(target),
		Reason:      nonBlank(detail),
		TriggeredBy: nonBlank(actor),
		CreatedAt:   time.Now().UTC(),
	})
	if err != nil {
		a.log.Error("auth: audit write failed", "action", action, "err", err)
	}
}

// nonBlank returns s, or "-" when s is empty after trimming.
func nonBlank(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
