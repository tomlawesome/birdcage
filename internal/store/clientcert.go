// Package store: this file is the record of every client certificate
// birdcage signs for an agent (issue #130, ADR-0012 Part B): the
// client_certs table (migration 0021), the token-to-certificate binding
// (canary_tokens.cert_fingerprint, B3), the one-way certificate renewal
// rule (B2), and the one-action revocation of a node's whole credential
// (B5).
package store

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// certConn is db.Conn plus QueryContext, like historyConn: both *db.DB
// and *db.Tx satisfy it, so the renewal path can list and bind inside
// its own transaction.
type certConn interface {
	db.Conn
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ClientCert is one client_certs row. ID is issuance order (see
// migration 0021's comment) and is the only thing "older" is ever
// decided on.
type ClientCert struct {
	ID          int64
	CanaryID    string
	Serial      string
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
	FirstUsedAt *time.Time
	RevokedAt   *time.Time
}

// Live reports whether c has not been revoked. Expiry is not checked
// here: the TLS handshake refuses an expired certificate before any
// request reaches the auth path, and the health signal reads NotAfter
// itself.
func (c ClientCert) Live() bool { return c.RevokedAt == nil }

// ErrClientCertNotFound is returned when a fingerprint or canary names
// no client_certs row.
var ErrClientCertNotFound = errors.New("store: client certificate not found")

// CertFingerprint is the SHA-256 of a certificate's DER encoding,
// lower-case hex -- the form client_certs.fingerprint_sha256 and
// canary_tokens.cert_fingerprint store (RFC 8705's x5t#S256 thumbprint,
// hex rather than base64url because nothing outside birdcage reads it).
func CertFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// RecordClientCert writes cert's row for canaryID. database is db.Conn
// so the caller records it in the same transaction that signed it
// (provisioning, renewal): a certificate that exists without a row can
// never authenticate, so a rolled-back row must mean a certificate the
// caller never hands out.
//
// cert's CommonName must be canaryID -- the CA wrote it from the same
// registry value, so a mismatch is a wiring bug, refused rather than
// recorded against the wrong node.
func RecordClientCert(ctx context.Context, database db.Conn, canaryID string, cert *x509.Certificate) (ClientCert, error) {
	if cert == nil {
		return ClientCert{}, fmt.Errorf("store: RecordClientCert: nil certificate")
	}
	if cert.Subject.CommonName != canaryID {
		return ClientCert{}, fmt.Errorf("store: RecordClientCert: certificate CN %q is not canary %q", cert.Subject.CommonName, canaryID)
	}
	row := ClientCert{
		CanaryID:    canaryID,
		Serial:      cert.SerialNumber.Text(16),
		Fingerprint: CertFingerprint(cert.Raw),
		NotBefore:   cert.NotBefore.UTC(),
		NotAfter:    cert.NotAfter.UTC(),
	}
	if _, err := database.ExecContext(ctx, `
		INSERT INTO client_certs (canary_id, serial, fingerprint_sha256, not_before, not_after)
		VALUES (?, ?, ?, ?, ?)`,
		row.CanaryID, row.Serial, row.Fingerprint,
		row.NotBefore.Format(receivedAtLayout), row.NotAfter.Format(receivedAtLayout)); err != nil {
		return ClientCert{}, fmt.Errorf("insert client certificate: %w", err)
	}
	// Read back for the id, rather than LastInsertId (which pgx does not
	// support) or RETURNING (which would need a per-engine query).
	return LookupClientCertByFingerprint(ctx, database, row.Fingerprint)
}

const clientCertColumns = `id, canary_id, serial, fingerprint_sha256, not_before, not_after, first_used_at, revoked_at`

func scanClientCert(row rowScanner) (ClientCert, error) {
	var (
		c                   ClientCert
		notBefore, notAfter string
		firstUsed, revoked  *string
	)
	if err := row.Scan(&c.ID, &c.CanaryID, &c.Serial, &c.Fingerprint, &notBefore, &notAfter, &firstUsed, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ClientCert{}, ErrClientCertNotFound
		}
		return ClientCert{}, fmt.Errorf("scan client certificate: %w", err)
	}
	var err error
	if c.NotBefore, err = time.Parse(receivedAtLayout, notBefore); err != nil {
		return ClientCert{}, fmt.Errorf("parse not_before %q: %w", notBefore, err)
	}
	if c.NotAfter, err = time.Parse(receivedAtLayout, notAfter); err != nil {
		return ClientCert{}, fmt.Errorf("parse not_after %q: %w", notAfter, err)
	}
	if firstUsed != nil {
		t, err := time.Parse(receivedAtLayout, *firstUsed)
		if err != nil {
			return ClientCert{}, fmt.Errorf("parse first_used_at %q: %w", *firstUsed, err)
		}
		c.FirstUsedAt = &t
	}
	if revoked != nil {
		t, err := time.Parse(receivedAtLayout, *revoked)
		if err != nil {
			return ClientCert{}, fmt.Errorf("parse revoked_at %q: %w", *revoked, err)
		}
		c.RevokedAt = &t
	}
	return c, nil
}

// LookupClientCertByFingerprint returns fingerprint's row whatever its
// status -- the auth path needs to tell a revoked certificate (a
// possible cert_conflict) from one birdcage never issued, and decides
// liveness itself.
func LookupClientCertByFingerprint(ctx context.Context, database db.Conn, fingerprint string) (ClientCert, error) {
	return scanClientCert(database.QueryRowContext(ctx,
		`SELECT `+clientCertColumns+` FROM client_certs WHERE fingerprint_sha256 = ?`, fingerprint))
}

// ListClientCertsForCanary returns every certificate issued to canaryID,
// oldest first by issuance order (id: an integer, which both engines
// order identically).
func ListClientCertsForCanary(ctx context.Context, database certConn, canaryID string) ([]ClientCert, error) {
	rows, err := database.QueryContext(ctx,
		`SELECT `+clientCertColumns+` FROM client_certs WHERE canary_id = ? ORDER BY id`, canaryID)
	if err != nil {
		return nil, fmt.Errorf("list client certificates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ClientCert
	for rows.Next() {
		c, err := scanClientCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate client certificates: %w", err)
	}
	return out, nil
}

// CurrentClientCert returns canaryID's newest live certificate: the one
// a token rotation binds its new token to (B3: "token rotation mints
// the new token under the current certificate"). Newest, not the one
// the rotating request presented, so a rotation that lands while a
// renewal is in flight binds to the certificate the agent is about to
// switch to -- binding it to the outgoing one would make the pair
// useless the moment the agent switches.
func CurrentClientCert(ctx context.Context, database certConn, canaryID string) (ClientCert, error) {
	certs, err := ListClientCertsForCanary(ctx, database, canaryID)
	if err != nil {
		return ClientCert{}, err
	}
	for i := len(certs) - 1; i >= 0; i-- {
		if certs[i].Live() {
			return certs[i], nil
		}
	}
	return ClientCert{}, ErrClientCertNotFound
}

// CanaryHasLiveClientCert reports whether canaryID has at least one
// unrevoked certificate -- the "successor is live" half of
// ingest.cert_conflict, mirroring CanaryHasActiveToken.
func CanaryHasLiveClientCert(ctx context.Context, database *db.DB, canaryID string) (bool, error) {
	var n int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM client_certs WHERE canary_id = ? AND revoked_at IS NULL`, canaryID).Scan(&n); err != nil {
		return false, fmt.Errorf("count live client certificates: %w", err)
	}
	return n > 0, nil
}

// RecordClientCertFirstUse applies B2's one-way rule, the certificate
// twin of RevokeCanaryTokensSupersededBy: the first authenticated use of
// cert marks it used and revokes every older live certificate for the
// same canary, in one transaction. first is true only for the call that
// actually set first_used_at (a concurrent second first-use loses the
// conditional UPDATE and changes nothing). Older is decided on id, never
// on a timestamp.
//
// Only older certificates are revoked, never newer ones: an agent that
// presents its outgoing certificate once more (a request already in
// flight when it renewed) must not kill the certificate it just
// received.
func RecordClientCertFirstUse(ctx context.Context, database *db.DB, cert ClientCert, at time.Time) (first bool, revokedOlder int64, err error) {
	tx, err := database.Begin(ctx)
	if err != nil {
		return false, 0, fmt.Errorf("begin certificate first-use transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback() // the error being returned already says what failed
		}
	}()
	// Serialised with renewal and rotation (LockCanaryCredentials), so a
	// renewal deciding which certificates are still unused
	// (SupersedePendingClientCerts) never races this marking one used.
	// No canaries row means no rotation or renewal can run for this
	// canary either (both refuse on it), so there is nothing to race.
	if err = LockCanaryCredentials(ctx, tx, cert.CanaryID); err != nil && !errors.Is(err, ErrCanaryNotFound) {
		return false, 0, err
	}
	err = nil
	stamp := at.UTC().Format(receivedAtLayout)
	res, err := tx.ExecContext(ctx,
		`UPDATE client_certs SET first_used_at = ? WHERE id = ? AND first_used_at IS NULL AND revoked_at IS NULL`,
		stamp, cert.ID)
	if err != nil {
		return false, 0, fmt.Errorf("record certificate first use: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, 0, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		if err = tx.Commit(); err != nil {
			return false, 0, fmt.Errorf("commit certificate first use: %w", err)
		}
		return false, 0, nil
	}
	res, err = tx.ExecContext(ctx,
		`UPDATE client_certs SET revoked_at = ? WHERE canary_id = ? AND id < ? AND revoked_at IS NULL`,
		stamp, cert.CanaryID, cert.ID)
	if err != nil {
		return false, 0, fmt.Errorf("revoke superseded certificates: %w", err)
	}
	if revokedOlder, err = res.RowsAffected(); err != nil {
		return false, 0, fmt.Errorf("rows affected: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return false, 0, fmt.Errorf("commit certificate first use: %w", err)
	}
	return true, revokedOlder, nil
}

// LockCanaryCredentials serialises every transaction that reads a
// canary's certificates and then writes a binding or a revocation
// decided on that read: token rotation (read the newest certificate,
// bind the new token to it), renewal (record a certificate, supersede
// unused ones, carry every live token across) and a certificate's first
// use. Call it first in the transaction; the lock lasts until commit or
// rollback.
//
// Why it is needed (issue #130 review): without it, on Postgres, a
// renewal could commit between a rotation's "newest certificate" read
// and its commit. The renewal's carry-across cannot see the rotation's
// uncommitted token, and the rotation binds that token to what is by
// then the older certificate -- so once the agent switches to its
// renewed certificate, TokenBoundToCert refuses the pair and an honest
// node is locked out.
//
// How: a no-op UPDATE of the canary's own registry row, the same
// statement on both engines. On Postgres it takes that row's lock, so a
// second such transaction for the same canary waits at this statement
// until the first ends; under READ COMMITTED every later statement of
// the waiter takes a fresh snapshot, so its reads see everything the
// first committed. On SQLite every transaction is already serial
// (internal/db opens it with one connection), and the UPDATE merely
// takes the write lock early. Other canaries are never blocked.
//
// Returns ErrCanaryNotFound when there is no row to lock: nothing is
// serialised then, so the caller must not go on as if it were.
func LockCanaryCredentials(ctx context.Context, tx *db.Tx, canaryID string) error {
	res, err := tx.ExecContext(ctx, `UPDATE canaries SET kind = kind WHERE id = ?`, canaryID)
	if err != nil {
		return fmt.Errorf("lock canary credentials: %w", err)
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

// SupersedePendingClientCerts revokes every certificate of canaryID
// issued after the in-use certificate inUseID that is still live and
// has never been used -- a pending renewal nobody has switched to --
// and returns the rows it revoked (as they were before revocation).
//
// Renewal calls it, under LockCanaryCredentials, in the transaction
// that records the new certificate (ADR-0012 B2, issue #130 review): a
// holder of a copied certificate and token could otherwise renew and
// never present the result, keeping a hidden seven-day credential that
// no first use ever revokes and no alarm ever names. The renewal itself
// is never refused over this: an honest agent whose renewal response was
// lost retries with a fresh key and must succeed, and it is exactly its
// lost certificate that is revoked here.
func SupersedePendingClientCerts(ctx context.Context, tx *db.Tx, canaryID string, inUseID int64, at time.Time) ([]ClientCert, error) {
	certs, err := ListClientCertsForCanary(ctx, tx, canaryID)
	if err != nil {
		return nil, err
	}
	stamp := at.UTC().Format(receivedAtLayout)
	var out []ClientCert
	for _, c := range certs {
		if c.ID <= inUseID || !c.Live() || c.FirstUsedAt != nil {
			continue
		}
		// The conditions are repeated in the WHERE so the write can
		// never act on anything but what was read, lock or no lock.
		res, err := tx.ExecContext(ctx,
			`UPDATE client_certs SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL AND first_used_at IS NULL`,
			stamp, c.ID)
		if err != nil {
			return nil, fmt.Errorf("revoke pending client certificate: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("rows affected: %w", err)
		}
		if n == 1 {
			out = append(out, c)
		}
	}
	return out, nil
}

// MintCanaryTokenForCert is MintCanaryToken with the new token bound to
// the certificate whose fingerprint is certFingerprint (B3). Every token
// minted on the enrolment and rotation paths goes through here; an
// unbound token (MintCanaryToken) never authenticates over mutual TLS.
func MintCanaryTokenForCert(ctx context.Context, database db.Conn, canaryID, certFingerprint string, createdAt time.Time) (string, CanaryToken, error) {
	if certFingerprint == "" {
		return "", CanaryToken{}, fmt.Errorf("store: MintCanaryTokenForCert: empty certificate fingerprint")
	}
	raw, tok, err := MintCanaryToken(ctx, database, canaryID, createdAt)
	if err != nil {
		return "", CanaryToken{}, err
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE canary_tokens SET cert_fingerprint = ? WHERE id = ?`, certFingerprint, tok.ID); err != nil {
		return "", CanaryToken{}, fmt.Errorf("bind canary token to certificate: %w", err)
	}
	tok.CertFingerprint = certFingerprint
	return raw, tok, nil
}

// BindCanaryTokensToCert re-binds every live token of canaryID to
// certFingerprint -- B3's "certificate renewal carries the live token
// across to the new fingerprint in the same transaction that records
// the certificate". Every live token, not only the one presented: a
// rotated token not yet first used is just as much the agent's, and
// leaving it on the outgoing certificate would strand it.
func BindCanaryTokensToCert(ctx context.Context, database db.Conn, canaryID, certFingerprint string) (int64, error) {
	res, err := database.ExecContext(ctx,
		`UPDATE canary_tokens SET cert_fingerprint = ? WHERE canary_id = ? AND revoked_at IS NULL`,
		certFingerprint, canaryID)
	if err != nil {
		return 0, fmt.Errorf("rebind canary tokens: %w", err)
	}
	return res.RowsAffected()
}

// TokenBoundToCert reports whether tok may be used over a connection
// presenting cert (B3). cert must already be known live and tok's own
// canary's; this decides only the binding.
//
// Accepted: cert is exactly the certificate tok is bound to. Also
// accepted, and only this: tok is bound to a newer certificate of the
// same canary that has not been used yet and is not revoked, and cert
// is older -- a renewal still in flight. Renewal moves the token to the
// new certificate at once, but ADR-0012 B2 keeps the old certificate
// valid until the new one's first use; without this case the agent's
// own in-flight requests on the old certificate, or a renewal response
// lost on the wire, would leave it holding no working pair. The window
// closes by itself: the new certificate's first use revokes the old one
// (RecordClientCertFirstUse), after which the old one fails the
// liveness check before binding is ever asked.
//
// A NULL binding (tokens minted before migration 0021, or by
// `birdcage canary add`) is never accepted.
//
// The binding is re-read here, token row and bound certificate in one
// statement, rather than taken from tok.CertFingerprint: a renewal
// moves the binding and revokes the certificate it moved it from
// (SupersedePendingClientCerts) in one transaction, and reading the two
// halves at different moments could pair the old binding with the new
// revocation and refuse an honest request made during a renewal. One
// statement sees one consistent state on both engines.
func TokenBoundToCert(ctx context.Context, database db.Conn, tok CanaryToken, cert ClientCert) (bool, error) {
	bound, err := scanClientCert(database.QueryRowContext(ctx, `
		SELECT c.id, c.canary_id, c.serial, c.fingerprint_sha256, c.not_before, c.not_after, c.first_used_at, c.revoked_at
		FROM canary_tokens t JOIN client_certs c ON c.fingerprint_sha256 = t.cert_fingerprint
		WHERE t.id = ?`, tok.ID))
	if errors.Is(err, ErrClientCertNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if bound.Fingerprint == cert.Fingerprint {
		return bound.CanaryID == tok.CanaryID, nil
	}
	return bound.CanaryID == cert.CanaryID &&
		bound.CanaryID == tok.CanaryID &&
		bound.ID > cert.ID &&
		bound.Live() &&
		bound.FirstUsedAt == nil, nil
}

// RevokedCredentials is what RevokeCanaryCredentials changed.
type RevokedCredentials struct {
	Tokens       int64
	Certificates int64
}

// RevokeCanaryCredentials revokes every live token and every live
// certificate for canaryID (ADR-0012 B5: "one operator action ends both
// holders"). From the moment tx commits, every request from any holder
// of any of them is a 401.
//
// It takes a *db.Tx, not a db.Conn, so the two revocations cannot be
// run outside one transaction; the caller writes its audit entry
// (`canary.revoked`, naming who asked) on the same tx, so the
// revocation and its record commit together or not at all. Returns
// ErrCanaryNotFound when no canaries row exists for canaryID, so a
// mistyped id is an error rather than a silent zero. Revoking an
// already-revoked node succeeds with zero counts and keeps the earlier
// revocation times.
func RevokeCanaryCredentials(ctx context.Context, tx *db.Tx, canaryID string, at time.Time) (RevokedCredentials, error) {
	if at.IsZero() {
		return RevokedCredentials{}, fmt.Errorf("store: RevokeCanaryCredentials: at is zero; callers must set it")
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM canaries WHERE id = ?`, canaryID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RevokedCredentials{}, ErrCanaryNotFound
		}
		return RevokedCredentials{}, fmt.Errorf("look up canary: %w", err)
	}
	stamp := at.UTC().Format(receivedAtLayout)
	var out RevokedCredentials
	res, err := tx.ExecContext(ctx,
		`UPDATE canary_tokens SET revoked_at = ? WHERE canary_id = ? AND revoked_at IS NULL`, stamp, canaryID)
	if err != nil {
		return RevokedCredentials{}, fmt.Errorf("revoke canary tokens: %w", err)
	}
	if out.Tokens, err = res.RowsAffected(); err != nil {
		return RevokedCredentials{}, fmt.Errorf("rows affected: %w", err)
	}
	res, err = tx.ExecContext(ctx,
		`UPDATE client_certs SET revoked_at = ? WHERE canary_id = ? AND revoked_at IS NULL`, stamp, canaryID)
	if err != nil {
		return RevokedCredentials{}, fmt.Errorf("revoke client certificates: %w", err)
	}
	if out.Certificates, err = res.RowsAffected(); err != nil {
		return RevokedCredentials{}, fmt.Errorf("rows affected: %w", err)
	}
	return out, nil
}
