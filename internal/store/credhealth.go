// Package store: this file is issue #130's health signals (ADR-0012 B2
// and B4) -- renewal_stalled and certificate expiry from client_certs,
// and credential_conflict from the dual-use pairs internal/ingest
// records on the canary row. Layered onto applyHealthState's result by
// applyCredentialHealth so #45's precedence stays in one table
// (healthStateRank) and #56's recorder sees the new states through
// ActiveStates like every other.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

const (
	// credentialConflictWindow is how long credential_conflict holds
	// after the newest dual-use observation. The detection window itself
	// is 60 seconds (ADR-0012 B4); internal/ingest records a continuing
	// dual use at most once per audit-coalescer interval (1 minute), so
	// two minutes keeps the state on for as long as the dual use goes on
	// and lets it clear within two minutes of stopping -- "flaps this once
	// and clears in a minute", with a minute of slack for the coalescer.
	credentialConflictWindow = 2 * time.Minute

	// renewalStalledMargin is how far past half-life a certificate may
	// go unrenewed before renewal_stalled: the agent retries on every
	// heartbeat tick from half-life, so fifteen minutes is fifteen failed
	// attempts -- rotationStalledThreshold's own number, for the same
	// failure on the other credential. For a certificate whose lifetime
	// is short (an e2e fixture overriding the TTL to minutes) the margin
	// is a tenth of the lifetime instead, so the state can still show
	// before expiry.
	renewalStalledMargin = 15 * time.Minute
)

// CredentialConflict is the dashboard-facing detail of
// credential_conflict: the two source addresses and/or the two agent
// builds seen presenting one certificate within the detection window.
// Each list holds exactly two values or is omitted.
type CredentialConflict struct {
	Addresses []string `json:"addresses,omitempty"`
	Versions  []string `json:"versions,omitempty"`
}

// DualUseKind names which of B4's two dual-use observations a pair is.
type DualUseKind int

const (
	// DualUseAddresses: one certificate from two source addresses.
	DualUseAddresses DualUseKind = iota
	// DualUseVersions: one certificate with two agent build versions.
	DualUseVersions
)

// dualUseColumns is canaries.credential_dual_use_*, raw.
type dualUseColumns struct {
	addrs, addrsAt, versions, versionsAt *string
}

// maxDualUseValueLen bounds each stored value. Addresses come from the
// connection and are short; a version is the agent's own word, so it is
// cut rather than stored at whatever length a copied credential sends.
const maxDualUseValueLen = 128

// RecordCredentialDualUse stores the newest dual-use pair of kind for
// canaryID (ADR-0012 B4), replacing the previous pair of that kind.
// internal/ingest calls it only when its audit coalescer admits a write,
// so its rate is the audit entry's rate, not the request rate.
func RecordCredentialDualUse(ctx context.Context, database db.Conn, canaryID string, kind DualUseKind, a, b string, at time.Time) error {
	if at.IsZero() {
		return fmt.Errorf("store: RecordCredentialDualUse: at is zero; callers must set it")
	}
	pair, err := json.Marshal([]string{truncate(a, maxDualUseValueLen), truncate(b, maxDualUseValueLen)})
	if err != nil {
		return fmt.Errorf("encode dual-use pair: %w", err)
	}
	query := `UPDATE canaries SET credential_dual_use_addrs = ?, credential_dual_use_addrs_at = ? WHERE id = ?`
	if kind == DualUseVersions {
		query = `UPDATE canaries SET credential_dual_use_versions = ?, credential_dual_use_versions_at = ? WHERE id = ?`
	}
	res, err := database.ExecContext(ctx, query, string(pair), at.UTC().Format(receivedAtLayout), canaryID)
	if err != nil {
		return fmt.Errorf("record credential dual use: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return ErrCanaryNotFound
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// certSignal is certificateSignal's result.
type certSignal struct {
	renewalStalled     bool
	renewalStalledForS int64
	expired            bool
}

// certificateSignal derives renewal_stalled and certificate expiry for
// canaryID as of now. The certificate judged is the one the agent is
// using: its newest live certificate that has been used, or, before any
// has been, its newest live one. A renewal that minted a successor the
// agent never used has not completed, so it does not stop the clock.
// A canary with no live certificate (never had one, or revoked by the
// operator) has no signal here; silence covers it.
func certificateSignal(ctx context.Context, database *db.DB, canaryID string, now time.Time) (certSignal, error) {
	certs, err := ListClientCertsForCanary(ctx, database, canaryID)
	if err != nil {
		return certSignal{}, err
	}
	var cur *ClientCert
	for i := len(certs) - 1; i >= 0 && cur == nil; i-- {
		if certs[i].Live() && certs[i].FirstUsedAt != nil {
			cur = &certs[i]
		}
	}
	for i := len(certs) - 1; i >= 0 && cur == nil; i-- {
		if certs[i].Live() {
			cur = &certs[i]
		}
	}
	if cur == nil {
		return certSignal{}, nil
	}
	if !now.Before(cur.NotAfter) {
		return certSignal{expired: true}, nil
	}
	lifetime := cur.NotAfter.Sub(cur.NotBefore)
	halfLife := cur.NotBefore.Add(lifetime / 2)
	margin := renewalStalledMargin
	if lifetime/10 < margin {
		margin = lifetime / 10
	}
	if now.Before(halfLife.Add(margin)) {
		return certSignal{}, nil
	}
	return certSignal{renewalStalled: true, renewalStalledForS: int64(now.Sub(halfLife).Seconds())}, nil
}

// recentPair decodes one stored dual-use pair if its time is within
// credentialConflictWindow of now. A time in the future (clock moved
// back) still counts; a pair that does not decode to exactly two values
// is an error, not silently dropped.
func recentPair(raw, rawAt *string, now time.Time) ([]string, error) {
	if raw == nil || rawAt == nil {
		return nil, nil
	}
	at, err := time.Parse(receivedAtLayout, *rawAt)
	if err != nil {
		return nil, fmt.Errorf("parse dual-use time %q: %w", *rawAt, err)
	}
	if now.Sub(at) >= credentialConflictWindow {
		return nil, nil
	}
	var pair []string
	if err := json.Unmarshal([]byte(*raw), &pair); err != nil {
		return nil, fmt.Errorf("decode dual-use pair: %w", err)
	}
	if len(pair) != 2 {
		return nil, fmt.Errorf("dual-use pair has %d values, want 2", len(pair))
	}
	return pair, nil
}

// applyCredentialHealth adds issue #130's states to what
// applyHealthState already derived: credential_conflict, renewal_stalled,
// and not_delivering when the certificate in use has expired. It
// re-sorts ActiveStates by healthStateRank and re-derives Status as its
// head, so the precedence lives in that one table.
func applyCredentialHealth(c *Canary, cert certSignal, now time.Time) error {
	addrs, err := recentPair(c.dualUse.addrs, c.dualUse.addrsAt, now)
	if err != nil {
		return err
	}
	versions, err := recentPair(c.dualUse.versions, c.dualUse.versionsAt, now)
	if err != nil {
		return err
	}

	var add []HealthState
	if addrs != nil || versions != nil {
		c.CredentialConflict = &CredentialConflict{Addresses: addrs, Versions: versions}
		add = append(add, StateCredentialConflict)
	}
	if cert.renewalStalled {
		c.RenewalStalled = true
		s := cert.renewalStalledForS
		c.RenewalStalledForS = &s
		add = append(add, StateRenewalStalled)
	}
	if cert.expired {
		c.CertificateExpired = true
		if !c.NotDelivering {
			c.NotDelivering = true
			add = append(add, StateNotDelivering)
		}
	}
	if len(add) == 0 {
		return nil
	}

	active := make([]HealthState, 0, len(c.ActiveStates)+len(add))
	for _, s := range c.ActiveStates {
		active = append(active, HealthState(s))
	}
	active = append(active, add...)
	sort.SliceStable(active, func(i, j int) bool {
		return healthStateRank[active[i]] < healthStateRank[active[j]]
	})
	c.ActiveStates = make([]string, len(active))
	for i, s := range active {
		c.ActiveStates[i] = string(s)
	}
	c.Status = c.ActiveStates[0]
	return nil
}
