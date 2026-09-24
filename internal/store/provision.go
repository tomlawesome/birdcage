// Package store: this file is issue #47 slice 3's provisioning step --
// POST /enrol/provision (internal/enrol), the exchange of a contacted
// session's enrolment secret for a live canary identity: a canary_tokens
// bearer token (for the ingest listener) and a client certificate (for
// the ingest listener's mutual TLS, internal/ingest's requireBearerToken).
package store

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
)

// provisionCanaryIDBytes is the random byte length behind a provisioned
// canary's id -- matching enrolmentSessionIDBytes' and tokenIDBytes' own
// choice of 16.
const provisionCanaryIDBytes = 16

// ProvisionOutcome is what Provision found the presented enrolment
// secret to be -- mirroring FirstContactOutcome's uniform-refusal shape
// (design note decision 1).
type ProvisionOutcome int

const (
	// Provisioned is success: a contacted session, still within its
	// window, was turned into a live canary.
	Provisioned ProvisionOutcome = iota
	// UnknownSecret means the hash matched no session in state
	// "contacted" -- an unminted secret, a session in any other state,
	// or a replay of one already provisioned (design note decision 2:
	// provisioning shreds enrolment_secret_hash back to NULL, so a
	// replay looks exactly like an unknown secret).
	UnknownSecret
	// WindowExpired means the session was found, still in state
	// "contacted", but now is at or past its window_deadline. Provision
	// moves it to state "expired" as a side effect, the same way
	// FirstContact moves an unpresented session to "expired" on its own
	// deadline.
	WindowExpired
)

// String renders o for logging; never for a caller-visible response,
// which must stay the fixed {"error":"refused"} body regardless of
// which of UnknownSecret/WindowExpired this is (both refuse identically
// -- see internal/enrol's handleProvision).
func (o ProvisionOutcome) String() string {
	switch o {
	case Provisioned:
		return "provisioned"
	case UnknownSecret:
		return "unknown_secret"
	case WindowExpired:
		return "window_expired"
	default:
		return "invalid"
	}
}

// ProvisionResult is POST /enrol/provision's success payload: everything
// Provision minted inside its one transaction, for internal/enrol to
// encode. CanaryToken is shown to the caller exactly once here -- no
// store function can recover it afterwards, matching MintCanaryToken's
// and MintEnrolmentSession's own stance on their raw values. There is no
// private key: the agent generated its own and sent only a CSR (issue
// #130, ADR-0012 B1), so birdcage never holds one to hand back.
type ProvisionResult struct {
	CanaryID           string
	CanaryToken        string
	ClientCertPEM      string
	HeartbeatIntervalS int
}

// ProvisionSigner signs the new canary's client certificate over the
// public key the agent sent (in practice a closure over
// (*ca.CA).SignClient and the parsed CSR). kind is the session's own
// registered kind, which the signer writes into the subject's OU.
type ProvisionSigner func(canaryID string, kind agentkind.Kind) (certPEM []byte, cert *x509.Certificate, err error)

// Provision resolves secretHash (as produced by HashToken) against
// enrolment_sessions in state "contacted" and, on success, creates the
// canary row, mints its bearer token, issues its client certificate, and
// shreds the enrolment secret -- all in one transaction (design note
// decision 2: "the secret is shredded at provisioning; a replay then
// looks like an unknown secret, which is the point").
//
// sign signs the canary's client certificate and is called inside the
// transaction, so a CA failure rolls back the canary row with it -- a
// caller never sees a canary row with no client certificate to match,
// and the enrolment secret is spent only when everything committed.
// The certificate is recorded in client_certs (issue #130, B2) and the
// first token is bound to it (B3) in the same transaction.
//
// A second enrolment under a name an existing canary already has is a
// new canary with a new, server-minted id and its own credential; it
// never touches the existing node's row, tokens or certificates
// (ADR-0012 B5, the Keylime CVE-2025-13609 lesson).
func Provision(ctx context.Context, database *db.DB, secretHash string, now time.Time, sign ProvisionSigner) (ProvisionResult, ProvisionOutcome, error) {
	if now.IsZero() {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("store: Provision: now is zero; callers must set it")
	}
	now = now.UTC()

	tx, err := database.Begin(ctx)
	if err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("begin provision transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = tx.Rollback() // best-effort; the error already returned above stands regardless
	}()

	found, err := scanEnrolmentSessionBySecretHash(ctx, tx, secretHash)
	if err != nil {
		if errors.Is(err, ErrEnrolmentSessionNotFound) {
			// Unknown secret, or a session found but not in state
			// "contacted" -- scanEnrolmentSessionBySecretHash's WHERE
			// clause already folds both into the same "not found".
			if cerr := tx.Commit(); cerr != nil {
				return ProvisionResult{}, UnknownSecret, fmt.Errorf("commit provision transaction: %w", cerr)
			}
			committed = true
			return ProvisionResult{}, UnknownSecret, nil
		}
		return ProvisionResult{}, UnknownSecret, err
	}

	if found.WindowDeadline == nil {
		// FirstContact always sets window_deadline alongside state
		// "contacted" -- reaching here with neither is a data invariant
		// violation, not a client error; fail the request rather than
		// guess at a deadline.
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("store: Provision: session %s is state contacted but has no window_deadline", found.ID)
	}

	if !now.Before(*found.WindowDeadline) {
		if _, err := tx.ExecContext(ctx, `
			UPDATE enrolment_sessions SET state = ? WHERE id = ?`,
			string(EnrolmentStateExpired), found.ID); err != nil {
			return ProvisionResult{}, WindowExpired, fmt.Errorf("mark enrolment session expired: %w", err)
		}
		if cerr := tx.Commit(); cerr != nil {
			return ProvisionResult{}, WindowExpired, fmt.Errorf("commit provision transaction: %w", cerr)
		}
		committed = true
		return ProvisionResult{}, WindowExpired, nil
	}

	// found.Kind names a registered profile or this is an invariant
	// violation, not a client error (issue #105 delivery plan section
	// 7): a session's kind is validated at mint (MintEnrolmentSession
	// above) and never rewritten afterwards, so a session in state
	// "contacted" carrying an unregistered kind means either a data
	// invariant was broken directly against the database, or a
	// rolled-back binary no longer registers a kind a newer one minted.
	// Fail loudly rather than silently falling back to any one kind's
	// profile -- the same stance the nil window_deadline check above
	// takes.
	profile, ok := agentkind.Lookup(found.Kind)
	if !ok {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("store: Provision: session %s carries unregistered kind %q", found.ID, found.Kind)
	}

	canaryID, err := randomHex(provisionCanaryIDBytes)
	if err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("generate canary id: %w", err)
	}

	if err := InsertCanary(ctx, tx, Canary{
		ID:                 canaryID,
		Name:               found.Name,
		Lane:               found.Lane,
		Kind:               found.Kind,
		Ports:              profile.Ports,
		HeartbeatIntervalS: DefaultHeartbeatIntervalS,
		EnrolledAt:         now,
		// Issue #47 steps 7-9: a honeypot provisioned through this path
		// is pending (#45 state 5) until its first self-test round trip
		// passes -- store.SettlePending, fired from recordSelfTestMatch
		// the moment that happens. A scanner has no self-test yet (#46
		// is honeypot-only), so nothing could ever settle it: it
		// registers on provisioning, as every canary did before this
		// column existed, until issue #116 gives it a proof of its own.
		// Every other InsertCanary caller (`birdcage canary add`,
		// cmd/seed-story) leaves Pending false and keeps registering
		// immediately.
		Pending: found.Kind == agentkind.Honeypot,
	}); err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("insert canary: %w", err)
	}

	certPEM, cert, err := sign(canaryID, found.Kind)
	if err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("sign client certificate: %w", err)
	}
	recorded, err := RecordClientCert(ctx, tx, canaryID, cert)
	if err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("record client certificate: %w", err)
	}

	rawToken, _, err := MintCanaryTokenForCert(ctx, tx, canaryID, recorded.Fingerprint, now)
	if err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("mint canary token: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE enrolment_sessions SET canary_id = ?, state = ?, enrolment_secret_hash = NULL WHERE id = ?`,
		canaryID, string(EnrolmentStateProvisioned), found.ID); err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("mark enrolment session provisioned: %w", err)
	}

	// TriggeredBy is a fixed "enrolment" rather than an actor identity:
	// unlike internal/enrol's own enrolment.deploy_token_reuse entry
	// (written at the handler layer, where r.RemoteAddr is available),
	// this entry is written inside Provision itself, which has no
	// request to attribute it to.
	if _, err := audit.Append(ctx, tx, audit.Entry{
		Action:      "enrolment.provisioned",
		Target:      canaryID,
		Reason:      fmt.Sprintf("provisioned from enrolment session %s", found.ID),
		TriggeredBy: "enrolment",
		CreatedAt:   now,
	}); err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("record provision audit entry: %w", err)
	}

	if cerr := tx.Commit(); cerr != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("commit provision transaction: %w", cerr)
	}
	committed = true

	return ProvisionResult{
		CanaryID:           canaryID,
		CanaryToken:        rawToken,
		ClientCertPEM:      string(certPEM),
		HeartbeatIntervalS: DefaultHeartbeatIntervalS,
	}, Provisioned, nil
}
