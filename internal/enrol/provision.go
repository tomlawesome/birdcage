// provision.go adds POST /enrol/provision to this package's submux
// (issue #47 slice 3): the second and last step of enrolment, where a
// contacted session's enrolment secret (POST /enrol/hello's own success
// response) is exchanged for a live canary identity.
package enrol

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

// maxProvisionBodyBytes mirrors maxHelloBodyBytes: the body is one
// field, a hex secret well under 1 KiB.
const maxProvisionBodyBytes = 1024

// clientCertTTL is how long a provisioned canary's client certificate
// (IssueClient below) is valid for.
//
// Refs #47: renewal of client certificates is not designed yet.
const clientCertTTL = 365 * 24 * time.Hour

// MockingbirdPorts is the fixed set of ports the Mockingbird image
// serves, comma-separated in ascending order -- a provisioned canary is
// never asked for its own ports, so this is what store.Provision writes
// into the canaries row. It must match every `"*.enabled": true`
// module's `.port` entry in build/mockingbird/opencanary.conf exactly;
// verified against that file when this slice was written: ftp(21),
// ssh(22), telnet(23), tftp(69), http(80), mssql(1433), mysql(3306),
// rdp(3389), sip(5060), redis(6379). A change to that file must update
// this constant, and its mirror in internal/store (which cannot import
// this package -- see that constant's own doc comment for why).
const MockingbirdPorts = "21,22,23,69,80,1433,3306,3389,5060,6379"

// provisionRequest is POST /enrol/provision's request body: the
// enrolment secret POST /enrol/hello handed back, and nothing else --
// DisallowUnknownFields below rejects anything more.
type provisionRequest struct {
	EnrolmentSecret string `json:"enrolment_secret"`
}

// provisionResponse is POST /enrol/provision's success body: everything
// a canary's agent needs to start posting to the ingest listener --
// its bearer token, its client certificate/key for mutual TLS, and the
// heartbeat interval it should use. Every field here is shown exactly
// once; no later request can recover any of them.
type provisionResponse struct {
	CanaryID           string `json:"canary_id"`
	CanaryToken        string `json:"canary_token"`
	ClientCertPEM      string `json:"client_cert_pem"`
	ClientKeyPEM       string `json:"client_key_pem"`
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

	ctx := r.Context()
	hash := store.HashToken(req.EnrolmentSecret)
	result, outcome, err := store.Provision(ctx, h.db, hash, h.now(), func(canaryID string) (certPEM, keyPEM []byte, err error) {
		return h.ca.IssueClient(canaryID, clientCertTTL)
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
			ClientKeyPEM:       result.ClientKeyPEM,
			HeartbeatIntervalS: result.HeartbeatIntervalS,
		})
	default: // store.UnknownSecret, store.WindowExpired
		writeRefused(w)
	}
}
