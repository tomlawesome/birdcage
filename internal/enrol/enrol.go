// Package enrol implements issue #47's enrolment flow: POST /enrol/hello
// (slice 1b), the one and only place a freshly minted deploy token
// (internal/store's MintEnrolmentSession, `birdcage canary enrol`) is
// ever accepted, and POST /enrol/provision (slice 3), where a contacted
// session's enrolment secret becomes a live canary identity -- a bearer
// token and a client certificate for the ingest listener's mutual TLS.
// This is deliberately its own submux, on its own listener -- design
// note decision 1: "A separate enrolment_sessions table and a separate
// endpoint mux, never the canary_tokens model" -- so cmd/birdcage/main.go
// serves it from its own *http.Server, never mounted alongside, or
// reachable from, the ingest submux's bearer-token routes
// (internal/ingest) or the dashboard's requireAuth seam (internal/api),
// the same structural isolation internal/ingest's own package doc claims
// for itself.
package enrol

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// maxHelloBodyBytes caps POST /enrol/hello's request body. The body is
// one field, a hex token well under 1 KiB; 1 KiB leaves headroom for
// JSON structure without opening the door to anything resembling
// internal/ingest's batch bodies.
const maxHelloBodyBytes = 1024

// handler carries POST /enrol/hello's dependencies: db for the
// FirstContact lookup/burn and the two #54 settings, ca so a successful
// response can hand back the CA certificate PEM (design note decision
// 1's "the CA pin ... the two named volumes and the image" is step 2's
// job -- the CLI's -- step 3's job, carried here, is the CA certificate
// itself), and now so a test can drive the clock instead of depending on
// the wall clock, matching every other handler in this codebase.
//
// There is no separate "audit-writer" dependency: db is already a
// db.Conn (internal/db's minimal query surface), the same type
// audit.Append itself takes, so the one database handle this handler
// holds serves both roles -- store lookups and audit writes -- exactly
// as internal/ingest's own handlers do (see e.g. rotate.go's mint-plus-
// audit transaction).
type handler struct {
	db        *db.DB
	ca        *ca.CA
	ingestURL string
	now       func() time.Time
	logger    *slog.Logger
}

// NewHandler returns the enrolment submux: POST /enrol/hello and POST
// /enrol/provision, and nothing else. ingestURL is POST /enrol/hello's
// new "ingest_url" field (issue #47 slice 3) -- cmd/birdcage/main.go
// builds it from BIRDCAGE_ADVERTISE_HOST and BIRDCAGE_INGEST_ADDR's
// port; an empty string means BIRDCAGE_ADVERTISE_HOST was unset, and is
// passed straight through to the response the same way. now nil means
// time.Now; logger nil means slog.Default().
func NewHandler(database *db.DB, birdcageCA *ca.CA, ingestURL string, now func() time.Time, logger *slog.Logger) http.Handler {
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{db: database, ca: birdcageCA, ingestURL: ingestURL, now: now, logger: logger}

	// No rate limiting by source address yet. internal/ingest's own
	// limiterRegistry is keyed on the authenticated canary id -- an
	// identity this pre-auth endpoint has no equivalent of before
	// store.FirstContact resolves the token, so that limiter isn't
	// reusable here without inventing a new per-source-address one.
	// Refs #47 (a later slice).
	mux := http.NewServeMux()
	mux.HandleFunc("POST /enrol/hello", h.handleHello)
	mux.HandleFunc("POST /enrol/provision", h.handleProvision)
	mux.HandleFunc("/", notFoundJSON)
	return mux
}

// helloRequest is POST /enrol/hello's request body: the deploy token,
// and nothing else -- DisallowUnknownFields below rejects anything more.
type helloRequest struct {
	Token string `json:"token"`
}

// helloResponse is POST /enrol/hello's success body -- "The flow" step
// 3: the enrolment secret (design note decision 2, shown here once and
// never again), the CA certificate PEM, and issue #54's two addresses.
type helloResponse struct {
	EnrolmentSecret      string `json:"enrolment_secret"`
	CAPEM                string `json:"ca_pem"`
	WindowDeadline       string `json:"window_deadline"`
	AdminApprovalAddress string `json:"admin_approval_address"`
	ReleaseAddress       string `json:"release_address"`
	// IngestURL is issue #47 slice 3's addition: where this canary's
	// agent posts to once it holds a bearer token and client
	// certificate -- https://BIRDCAGE_ADVERTISE_HOST:<port of
	// BIRDCAGE_INGEST_ADDR>. Empty when BIRDCAGE_ADVERTISE_HOST is
	// unset (main.go logs a boot warning naming it in that case).
	IngestURL string `json:"ingest_url"`
}

// refusedBody is the fixed, byte-identical response every refusal
// (unknown token, expired token, reused/burned token) writes -- design
// note decision 1: "nothing distinguishes them to the caller." A single
// package-level value, written verbatim by every refusal path, is a
// stronger guarantee of that than re-encoding the same map three times
// and trusting encoding/json's output to stay identical.
var refusedBody = []byte(`{"error":"refused"}` + "\n")

// handleHello serves POST /enrol/hello.
func (h *handler) handleHello(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxHelloBodyBytes)
	var req helloRequest
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
	hash := store.HashToken(req.Token)
	secret, session, outcome, err := store.FirstContact(ctx, h.db, hash, h.now())
	if err != nil {
		// birdcage's own storage trouble, not the token's fault --
		// 503 rather than folding this into the uniform 401 refusal,
		// the same distinction internal/ingest's requireBearerToken
		// draws between ErrTokenNotFound and every other error.
		h.logger.Error("enrol: first contact failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	switch outcome {
	case store.Contacted:
		h.respondContacted(w, r, secret, session)
	case store.Reused:
		// Design note decision 1: "a second /enrol/hello with a burned
		// token: uniform refusal plus an audit entry
		// enrolment.deploy_token_reuse" -- naming the session id, never
		// the token itself. Logged at WARN as well as audited: #47 "The
		// flow" step 2, "refused loudly and shown to the operator as
		// hostile, not as a retry: a lost race *is* the attack
		// signature" -- an operator watching `docker logs` sees it
		// without opening the audit trail.
		h.logger.Warn("enrol: deploy token reused after it was burned; treat as hostile", "session", session.ID, "remote", r.RemoteAddr)
		if _, err := audit.Append(ctx, h.db, audit.Entry{
			Action:      "enrolment.deploy_token_reuse",
			Target:      session.ID,
			Reason:      "deploy token presented to POST /enrol/hello after it was already burned",
			TriggeredBy: r.RemoteAddr,
			CreatedAt:   h.now().UTC(),
		}); err != nil {
			h.logger.Error("enrol: record deploy token reuse", "session", session.ID, "err", err)
		}
		writeRefused(w)
	default: // store.Unknown, store.Expired
		writeRefused(w)
	}
}

// respondContacted writes POST /enrol/hello's success body once
// store.FirstContact has minted secret for session.
func (h *handler) respondContacted(w http.ResponseWriter, r *http.Request, secret string, session store.EnrolmentSession) {
	ctx := r.Context()
	adminApprovalAddress, err := store.GetSetting(ctx, h.db, store.SettingAdminApprovalAddress)
	if err != nil {
		h.logger.Error("enrol: read admin approval address", "session", session.ID, "err", err)
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	releaseAddress, err := store.GetSetting(ctx, h.db, store.SettingReleaseAddress)
	if err != nil {
		h.logger.Error("enrol: read release address", "session", session.ID, "err", err)
		writeError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}

	windowDeadline := session.CreatedAt // overwritten below; only reached if WindowDeadline is set
	if session.WindowDeadline != nil {
		windowDeadline = *session.WindowDeadline
	} else {
		// store.FirstContact always sets WindowDeadline on Contacted;
		// reaching here is a wiring bug, not a client error, but there
		// is still a response to send -- fail loudly in the log rather
		// than panic on a nil deref.
		h.logger.Error("enrol: contacted session has no window deadline", "session", session.ID)
	}

	writeJSON(w, http.StatusOK, helloResponse{
		EnrolmentSecret:      secret,
		CAPEM:                string(h.ca.CertPEM()),
		WindowDeadline:       windowDeadline.UTC().Format(time.RFC3339),
		AdminApprovalAddress: adminApprovalAddress,
		ReleaseAddress:       releaseAddress,
		IngestURL:            h.ingestURL,
	})
}

func notFoundJSON(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "not found")
}

// writeRefused writes the fixed refusal body -- see refusedBody's doc
// comment for why every refusal path shares this one function rather
// than each encoding its own copy of the same JSON.
func writeRefused(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write(refusedBody)
}

// writeJSON and writeError mirror internal/ingest's own (unexported
// there too, so not reusable directly): one place in this package that
// writes a response body, and one shape for every error response other
// than the fixed refusal above.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
