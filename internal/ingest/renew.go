package ingest

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/store"
)

// DefaultClientCertTTL is how long a renewed certificate lasts: seven
// days, the same as internal/enrol's ClientCertTTL for the first one
// (ADR-0012 B2). Kept as its own constant rather than imported, since
// internal/ingest does not depend on internal/enrol.
const DefaultClientCertTTL = 7 * 24 * time.Hour

// maxRenewBodyBytes caps POST /ingest/renew's body: one CSR, which
// ca.ParseClientCSR itself caps at 4 KiB, plus JSON structure.
const maxRenewBodyBytes = 6 * 1024

// Option adjusts NewHandler's handler.
type Option func(*ingestHandler)

// WithClientCertSigner gives POST /ingest/renew the CA to sign with.
// Without it every renewal is a 503: the route exists, fails closed, and
// says why in the log.
func WithClientCertSigner(signer *ca.CA) Option {
	return func(h *ingestHandler) { h.signer = signer }
}

// WithClientCertTTL overrides DefaultClientCertTTL for renewed
// certificates -- for a live-test fixture that needs a certificate to
// reach half-life and expiry in minutes. ttl <= 0 is ignored.
func WithClientCertTTL(ttl time.Duration) Option {
	return func(h *ingestHandler) {
		if ttl > 0 {
			h.certTTL = ttl
		}
	}
}

// renewRequest is POST /ingest/renew's body: a CSR over a fresh key the
// agent generated for this renewal, and nothing else.
type renewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// renewResponse is POST /ingest/renew's success body.
type renewResponse struct {
	ClientCertPEM string `json:"client_cert_pem"`
	NotAfter      string `json:"not_after"`
}

// handleRenew serves POST /ingest/renew (issue #130, ADR-0012 B2),
// reached only through requireBearerToken -- so over mutual TLS with a
// live, recorded certificate and a token bound to it. It signs a new
// certificate over the CSR's key with the subject re-read from the
// registry (the token's canary id and its registered kind), records it,
// and carries every live token of the canary across to it, all in one
// transaction.
//
// The presented certificate is not touched here. Like handleRotate, a
// failure at any point leaves the agent's working pair working; the old
// certificate is revoked only by the new one's first use
// (store.RecordClientCertFirstUse, from requireBearerToken), and until
// then store.TokenBoundToCert still pairs it with the carried token.
func (h *ingestHandler) handleRenew(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		slog.Error("ingest: handleRenew reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}
	presented, ok := clientCertFromContext(r.Context())
	if !ok || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		// Renewal replaces a certificate; with none presented there is
		// nothing to renew and nothing to have checked the token
		// against. Only reachable without TLS (handler tests).
		writeIngestError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if h.signer == nil {
		slog.Error("ingest: POST /ingest/renew has no certificate signer wired; refusing", "canary", tok.CanaryID)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRenewBodyBytes)
	var req renewRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeIngestError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if dec.More() {
		writeIngestError(w, http.StatusBadRequest, "malformed request: trailing data")
		return
	}
	csr, err := ca.ParseClientCSR([]byte(req.CSRPEM))
	if err != nil {
		writeIngestError(w, http.StatusBadRequest, "invalid csr: need one PEM CERTIFICATE REQUEST over an ECDSA P-256 key, correctly self-signed")
		return
	}
	// ADR-0012 B2: "a new key pair ... with a fresh key each time". A
	// renewal over the key already in use would extend a copied key's
	// life instead of ending it.
	if bytes.Equal(csr.RawSubjectPublicKeyInfo, r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo) {
		writeIngestError(w, http.StatusBadRequest, "invalid csr: renewal needs a fresh key, not the one in use")
		return
	}

	certPEM, leaf, err := h.signer.SignClient(csr, tok.CanaryID, tok.Kind, h.certTTL)
	if err != nil {
		slog.Error("ingest: sign renewed certificate failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	tx, err := h.db.Begin(r.Context())
	if err != nil {
		slog.Error("ingest: begin renew transaction failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			slog.Error("ingest: rollback renew transaction failed", "canary", tok.CanaryID, "err", rerr)
		}
	}()

	rec, err := store.RecordClientCert(r.Context(), tx, tok.CanaryID, leaf)
	if err != nil {
		slog.Error("ingest: record renewed certificate failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	if _, err := store.BindCanaryTokensToCert(r.Context(), tx, tok.CanaryID, rec.Fingerprint); err != nil {
		slog.Error("ingest: carry tokens to renewed certificate failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	if _, err := audit.Append(r.Context(), tx, audit.Entry{
		Action:      "ingest.cert_issued",
		Target:      tok.CanaryID,
		Reason:      "renewal signed a new client certificate (serial " + rec.Serial + ") to replace serial " + presented.Serial,
		TriggeredBy: tok.CanaryID,
		CreatedAt:   h.now().UTC(),
	}); err != nil {
		// Fail closed with the audit write, as a token mint does: the
		// rollback means the certificate was never recorded, so it can
		// never authenticate even though it was signed.
		slog.Error("ingest: record certificate issue failed; renewal aborted", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	if err := tx.Commit(); err != nil {
		slog.Error("ingest: commit renew transaction failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	committed = true

	writeJSON(w, http.StatusOK, renewResponse{
		ClientCertPEM: string(certPEM),
		NotAfter:      rec.NotAfter.UTC().Format(time.RFC3339),
	})
}
