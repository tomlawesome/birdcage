// Package store: this file is issue #47 slice 3's provisioning step --
// POST /enrol/provision (internal/enrol), the exchange of a contacted
// session's enrolment secret for a live canary identity: a canary_tokens
// bearer token (for the ingest listener) and a client certificate (for
// the ingest listener's mutual TLS, internal/ingest's requireBearerToken).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
)

// provisionCanaryIDBytes is the random byte length behind a provisioned
// canary's id -- matching enrolmentSessionIDBytes' and tokenIDBytes' own
// choice of 16.
const provisionCanaryIDBytes = 16

// mockingbirdPorts is the Mockingbird image's fixed port set, stored on
// every canary row Provision creates -- issue #47 slice 3: a provisioned
// canary was never told its own ports (there is no `birdcage canary add
// --ports` step in this flow), so Provision supplies the one set every
// Mockingbird image actually serves.
//
// This must equal internal/enrol.MockingbirdPorts exactly. It is
// declared separately here, rather than imported, because internal/enrol
// already imports internal/store (FirstContact, HashToken, Provision
// itself, ...); the reverse import would be a cycle. Both were verified
// against build/mockingbird/opencanary.conf's `"*.enabled": true`
// entries when this slice was written -- ftp(21), ssh(22), telnet(23),
// tftp(69), http(80), mssql(1433), mysql(3306), rdp(3389), sip(5060),
// redis(6379) -- and a change to that file must update both constants.
const mockingbirdPorts = "21,22,23,69,80,1433,3306,3389,5060,6379"

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
// encode. CanaryToken and the two PEM fields are each shown to the
// caller exactly once here -- no store function can recover any of them
// afterwards, matching MintCanaryToken's and MintEnrolmentSession's own
// stance on their raw values.
type ProvisionResult struct {
	CanaryID           string
	CanaryToken        string
	ClientCertPEM      string
	ClientKeyPEM       string
	HeartbeatIntervalS int
}

// Provision resolves secretHash (as produced by HashToken) against
// enrolment_sessions in state "contacted" and, on success, creates the
// canary row, mints its bearer token, issues its client certificate, and
// shreds the enrolment secret -- all in one transaction (design note
// decision 2: "the secret is shredded at provisioning; a replay then
// looks like an unknown secret, which is the point").
//
// issue mints the canary's client certificate (in practice,
// (*ca.CA).IssueClient) and is called inside the transaction, so a CA
// failure rolls back the canary row and token mint with it -- a caller
// never sees a canary row with no client certificate to match.
func Provision(ctx context.Context, database *db.DB, secretHash string, now time.Time, issue func(canaryID string) (certPEM, keyPEM []byte, err error)) (ProvisionResult, ProvisionOutcome, error) {
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

	canaryID, err := randomHex(provisionCanaryIDBytes)
	if err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("generate canary id: %w", err)
	}

	if err := InsertCanary(ctx, tx, Canary{
		ID:                 canaryID,
		Name:               found.Name,
		Lane:               found.Lane,
		Ports:              mockingbirdPorts,
		HeartbeatIntervalS: DefaultHeartbeatIntervalS,
		EnrolledAt:         now,
	}); err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("insert canary: %w", err)
	}

	rawToken, _, err := MintCanaryToken(ctx, tx, canaryID, now)
	if err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("mint canary token: %w", err)
	}

	certPEM, keyPEM, err := issue(canaryID)
	if err != nil {
		return ProvisionResult{}, UnknownSecret, fmt.Errorf("issue client certificate: %w", err)
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
		ClientKeyPEM:       string(keyPEM),
		HeartbeatIntervalS: DefaultHeartbeatIntervalS,
	}, Provisioned, nil
}
