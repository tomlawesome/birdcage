package crowdsec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/neverblock"
)

// The audit_log actions this package writes (ADR-0014, decision 8).
// internal/neverblock writes its own "refused: never-block floor" row
// before any of these can happen.
const (
	// ActionAdded: a permanent ban was created on the LAPI. Reason
	// carries the operator's text, the LAPI alert id and the duration.
	ActionAdded = "crowdsec.block_added"
	// ActionExists: birdcage already has a live ban on the address;
	// nothing was posted.
	ActionExists = "crowdsec.block_exists"
	// ActionRefused: CrowdSec's own allowlist covers the address;
	// nothing was posted.
	ActionRefused = "crowdsec.block_refused"
	// ActionFailed: a step after the floor check failed; nothing is
	// known to have been posted. Reason names the stage.
	ActionFailed = "crowdsec.block_failed"
)

// maxReasonLen bounds the operator's reason: it is sent to CrowdSec as
// the scenario text and written to audit_log, so it is a short line,
// not a report.
const maxReasonLen = 200

// Status is what Block did.
type Status string

const (
	// StatusAdded: a new permanent ban was posted.
	StatusAdded Status = "added"
	// StatusExists: a live birdcage ban was already there.
	StatusExists Status = "exists"
)

// Outcome is Block's successful result.
type Outcome struct {
	Status Status
	// Target is the canonical address the decision names.
	Target string
	// AlertID is the LAPI's id for the alert that carries the decision
	// ("" if the LAPI did not return one on a 201), or the existing
	// alert's id when Status is StatusExists.
	AlertID string
	// Duration is PermanentDuration for a new ban, or the LAPI's
	// remaining-time string for an existing one.
	Duration string
}

// ErrRefused wraps every refusal Block makes itself (an allowlisted
// address). A never-block refusal is neverblock.ErrRefused, unchanged.
var ErrRefused = errors.New("crowdsec: refused")

// Blocker is the one entry point that creates a ban. Build with New.
type Blocker struct {
	client *Client
	floor  *neverblock.Floor
	now    func() time.Time
}

// New builds a Blocker over client and floor. now is the clock used for
// timestamps on the wire and in audit rows (time.Now in production).
func New(client *Client, floor *neverblock.Floor, now func() time.Time) *Blocker {
	if now == nil {
		now = time.Now
	}
	return &Blocker{client: client, floor: floor, now: now}
}

// Block places a permanent ban on target, in ADR-0014 decision 6's
// order, every step fail-closed:
//
//  1. target must parse as a bare IPv4 or IPv6 address (no range, no
//     zone); it is canonicalised with net/netip, so an IPv4-mapped
//     IPv6 literal is handled as the IPv4 address it is. A target that
//     fails here was never a mitigation, so no audit row is written.
//  2. reason must be a non-empty single line of at most maxReasonLen
//     characters.
//  3. neverblock.Floor.Check, which writes its own refusal row.
//  4. Log in to the LAPI.
//  5. Ask CrowdSec's allowlist; refuse if it covers target.
//  6. Look for a live birdcage ban on target; if there is one, record
//     ActionExists and return StatusExists without posting.
//  7. Post the decision and record ActionAdded.
//
// Any failure at steps 4-7 is recorded as ActionFailed with the stage
// and a scrubbed reason, and returned. in supplies the dynamic floor
// categories (see neverblock.Inputs); triggeredBy names the caller for
// every audit row ("cli" for the operator command).
func (b *Blocker) Block(ctx context.Context, database db.Conn, target, reason, triggeredBy string, in neverblock.Inputs) (Outcome, error) {
	ip, err := canonicalAddress(target)
	if err != nil {
		return Outcome{}, err
	}
	reason = strings.TrimSpace(reason)
	switch {
	case reason == "":
		return Outcome{}, errors.New("crowdsec: a reason is required")
	case len(reason) > maxReasonLen:
		return Outcome{}, fmt.Errorf("crowdsec: the reason is longer than %d characters", maxReasonLen)
	case !safeValue(reason):
		return Outcome{}, errors.New("crowdsec: the reason contains a control character or a line break")
	}
	if strings.TrimSpace(triggeredBy) == "" {
		return Outcome{}, errors.New("crowdsec: triggeredBy is required")
	}

	if err := b.floor.Check(ctx, database, ip, in, triggeredBy); err != nil {
		return Outcome{}, err
	}

	token, err := b.client.login(ctx)
	if err != nil {
		return Outcome{}, b.fail(ctx, database, ip, triggeredBy, err)
	}

	allowlisted, why, err := b.client.allowlisted(ctx, token, ip)
	if err != nil {
		return Outcome{}, b.fail(ctx, database, ip, triggeredBy, err)
	}
	if allowlisted {
		if why == "" {
			why = "(no reason given)"
		}
		refusal := fmt.Errorf("%w: %s is on CrowdSec's own allowlist: %s", ErrRefused, ip, why)
		if _, aerr := b.append(ctx, database, ActionRefused, ip, "allowlisted in CrowdSec: "+why, triggeredBy); aerr != nil {
			return Outcome{}, fmt.Errorf("%w (additionally, writing the audit_log row failed: %v)", refusal, aerr)
		}
		return Outcome{}, refusal
	}

	existing, err := b.client.activeBirdcageBan(ctx, token, ip)
	if err != nil {
		return Outcome{}, b.fail(ctx, database, ip, triggeredBy, err)
	}
	if existing != nil {
		out := Outcome{Status: StatusExists, Target: ip, AlertID: fmt.Sprint(existing.AlertID), Duration: existing.Remaining}
		auditReason := fmt.Sprintf("already banned by birdcage (LAPI alert %d, decision %d, %s remaining); nothing posted", existing.AlertID, existing.DecisionID, existing.Remaining)
		if _, aerr := b.append(ctx, database, ActionExists, ip, auditReason, triggeredBy); aerr != nil {
			return out, fmt.Errorf("crowdsec: %s is already banned, but writing the audit_log row failed: %w", ip, aerr)
		}
		return out, nil
	}

	alertID, err := b.client.addBan(ctx, token, ip, ScenarioPrefix+reason, b.now())
	if err != nil {
		return Outcome{}, b.fail(ctx, database, ip, triggeredBy, err)
	}
	out := Outcome{Status: StatusAdded, Target: ip, AlertID: alertID, Duration: PermanentDuration}
	idText := "LAPI alert " + alertID
	if alertID == "" {
		idText = "LAPI returned 201 without an alert id"
	}
	auditReason := fmt.Sprintf("%s; %s; duration %s; machine %s", reason, idText, PermanentDuration, b.client.cfg.MachineID)
	if _, aerr := b.append(ctx, database, ActionAdded, ip, auditReason, triggeredBy); aerr != nil {
		// The ban landed. Say so, and say the record of it did not --
		// never report a landed block as a failure to block, and never
		// hide a failed audit write.
		return out, fmt.Errorf("crowdsec: the ban on %s was posted (%s), but writing the audit_log row failed: %w", ip, idText, aerr)
	}
	return out, nil
}

// fail records ActionFailed for cause and returns cause, with the
// audit failure appended if that write failed too.
func (b *Blocker) fail(ctx context.Context, database db.Conn, ip, triggeredBy string, cause error) error {
	if _, aerr := b.append(ctx, database, ActionFailed, ip, scrub(cause.Error()), triggeredBy); aerr != nil {
		return fmt.Errorf("%w (additionally, writing the audit_log row failed: %v)", cause, aerr)
	}
	return cause
}

func (b *Blocker) append(ctx context.Context, database db.Conn, action, target, reason, triggeredBy string) (int64, error) {
	return audit.Append(ctx, database, audit.Entry{
		Action:      action,
		Target:      target,
		Reason:      reason,
		TriggeredBy: triggeredBy,
		CreatedAt:   b.now().UTC(),
	})
}

// canonicalAddress parses raw as a bare address and returns its
// canonical text: unmapped (::ffff:203.0.113.9 becomes 203.0.113.9),
// no zone, lower-case IPv6. A range is refused here rather than passed
// to the floor: a range is a different blast radius and a different
// decision (ADR-0014, out of scope).
func canonicalAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("crowdsec: an address is required")
	}
	if strings.Contains(raw, "/") {
		return "", fmt.Errorf("crowdsec: %q is a range; only a single address can be blocked", raw)
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return "", fmt.Errorf("crowdsec: %q is not an IP address: %w", raw, err)
	}
	if a.Zone() != "" {
		return "", fmt.Errorf("crowdsec: %q carries an interface zone; a decision names a bare address", raw)
	}
	return a.Unmap().String(), nil
}
