// Package store: this file is issue #54's read path for the canary
// page's "upgrade this canary" command -- the copy-and-paste script that
// pulls birdcage's current images and recreates a canary's containers
// when its agent is running an older build than birdcage itself. The
// script is built by internal/runcmd.Upgrade, which needs three things
// no existing read path hands back together: the canary's own kind, and
// its enrolment-time SMB lure identity (on/off, workgroup, share names)
// -- everything else Upgrade needs (bait names, segment profile) is
// already ListCanarySettings' job, and the rest (birdcage's own
// advertise host, CA pin, image refs) is runtime configuration the
// caller already holds, not a per-canary fact at all.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// CanaryUpgradeFacts is GetCanaryUpgradeFacts' return value.
type CanaryUpgradeFacts struct {
	Kind agentkind.Kind

	// SMBLure is nil when this canary's SMB lure identity is unknown --
	// either it predates issue #54 (enrolled_at earlier than the
	// migration that added smb_lure, so nothing was ever recorded) or its
	// kind has no lure at all (a scanner). A caller must treat nil as
	// "check, don't guess" (owner, 2026-09-27), never silently as false.
	SMBLure *bool

	// SMBWorkgroup and SMBShares (comma-joined) are set only when SMBLure
	// is non-nil and true; empty in every other case.
	SMBWorkgroup string
	SMBShares    string
}

// GetCanaryUpgradeFacts reads canaryID's own kind and SMB lure identity
// back from the agents row store.Provision wrote at enrolment (or, for a
// canary added before issue #54, the NULLs that migration left behind).
// Returns ErrCanaryNotFound for an unknown id, matching GetCanaryKind's
// and GetCanarySettingsHash's own stance.
func GetCanaryUpgradeFacts(ctx context.Context, database *db.DB, canaryID string) (CanaryUpgradeFacts, error) {
	var (
		kind         string
		smbLure      *int
		smbWorkgroup *string
		smbShares    *string
	)
	row := database.QueryRowContext(ctx, `SELECT kind, smb_lure, smb_workgroup, smb_shares FROM agents WHERE id = ?`, canaryID)
	if err := row.Scan(&kind, &smbLure, &smbWorkgroup, &smbShares); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CanaryUpgradeFacts{}, ErrCanaryNotFound
		}
		return CanaryUpgradeFacts{}, fmt.Errorf("scan canary upgrade facts: %w", err)
	}
	facts := CanaryUpgradeFacts{Kind: agentkind.Kind(kind)}
	if smbLure != nil {
		enabled := *smbLure != 0
		facts.SMBLure = &enabled
	}
	if smbWorkgroup != nil {
		facts.SMBWorkgroup = *smbWorkgroup
	}
	if smbShares != nil {
		facts.SMBShares = *smbShares
	}
	return facts, nil
}
