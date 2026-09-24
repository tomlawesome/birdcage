// provision.go adds POST /enrol/provision to this package's submux
// (issue #47 slice 3): the second and last step of enrolment, where a
// contacted session's enrolment secret (POST /enrol/hello's own success
// response) is exchanged for a live canary identity.
package enrol

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/store"
)

// maxProvisionBodyBytes caps the body: a hex secret and one ECDSA
// P-256 CSR in PEM (about 400 bytes; ca.ParseClientCSR itself refuses
// more than 4 KiB), plus JSON structure.
const maxProvisionBodyBytes = 6 * 1024

// ClientCertTTL is how long an agent's client certificate is valid for
// (issue #130, ADR-0012 B2): seven days, renewed by the agent from
// half-life over POST /ingest/renew with a fresh key each time, so a
// copied key stops working by itself within a week. internal/ingest's
// renewal signs for the same period.
const ClientCertTTL = 7 * 24 * time.Hour

// provisionRequest is POST /enrol/provision's request body: the
// enrolment secret POST /enrol/hello handed back and a CSR over the key
// the agent generated for itself (ADR-0012 B1), and nothing else --
// DisallowUnknownFields below rejects anything more.
type provisionRequest struct {
	EnrolmentSecret string `json:"enrolment_secret"`
	CSRPEM          string `json:"csr_pem"`
}

// provisionResponse is POST /enrol/provision's success body: everything
// a canary's agent needs to start posting to the ingest listener -- its
// bearer token, its client certificate for mutual TLS, and the
// heartbeat interval it should use. There is no private key in it: the
// agent's key never left the agent (ADR-0012 B1). The token is shown
// exactly once; no later request can recover it.
type provisionResponse struct {
	CanaryID           string `json:"canary_id"`
	CanaryToken        string `json:"canary_token"`
	ClientCertPEM      string `json:"client_cert_pem"`
	HeartbeatIntervalS int    `json:"heartbeat_interval_s"`
}

// handleProvision serves POST /enrol/provision.
func (h *handler) handleProvision(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxProvisionBodyBytes)
	var req provisionRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusBadRequest, "body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "malformed request: trailing data")
		return
	}

	// The CSR is checked before the secret is even looked up, so a bad
	// CSR is a 400 that spends nothing: the one-shot secret is shredded
	// only inside store.Provision's transaction, which this path never
	// reaches, and the agent can retry with a good CSR inside its
	// window. The error says what is wrong with the CSR and nothing
	// about the secret.
	csr, err := ca.ParseClientCSR([]byte(req.CSRPEM))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid csr: need one PEM CERTIFICATE REQUEST over an ECDSA P-256 key, correctly self-signed")
		return
	}

	ctx := r.Context()
	hash := store.HashToken(req.EnrolmentSecret)
	// kind is the session's own kind (#105): SignClient writes it into
	// the subject's OU, and the canary id into the CN, so nothing the
	// CSR asked for survives but its public key (ADR-0012 B1).
	result, outcome, err := store.Provision(ctx, h.db, hash, h.now(), func(canaryID string, kind agentkind.Kind) ([]byte, *x509.Certificate, error) {
		return h.ca.SignClient(csr, canaryID, kind, h.certTTL)
	})
	if err != nil {
		// birdcage's own storage or CA trouble, not the secret's fault --
		// 503 rather than folding this into the uniform 401 refusal,
		// the same distinction handleHello draws for store.FirstContact.
		h.logger.Error("enrol: provision failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	switch outcome {
	case store.Provisioned:
		writeJSON(w, http.StatusOK, provisionResponse{
			CanaryID:           result.CanaryID,
			CanaryToken:        result.CanaryToken,
			ClientCertPEM:      result.ClientCertPEM,
			HeartbeatIntervalS: result.HeartbeatIntervalS,
		})
	default: // store.UnknownSecret, store.WindowExpired
		writeRefused(w)
	}
}
