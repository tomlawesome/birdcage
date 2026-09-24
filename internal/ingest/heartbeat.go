package ingest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// heartbeatMaxBodyBytes bounds the ingest heartbeat body -- far smaller
// than a batch's, since this is a handful of scalar self-report fields,
// never a list of events.
const heartbeatMaxBodyBytes = 4 * 1024

// ingestHeartbeat is POST /ingest/heartbeat's body (issue #32 slice 5a):
// the agent's own self-report (#48), which is what #45's "not
// delivering" state stands on since birdcage never connects to the
// agent to check on it directly. CanaryID is accepted (so
// DisallowUnknownFields doesn't reject a caller that sends it) but never
// trusted as identity -- see handleHeartbeat's comparison against the
// token's own canary id, mirroring ingestBatch.NodeID in batch.go.
//
// Dropped, Rejected, EventIDCollisions and PositionFound (#48's
// process-composition note, gap 3) are pointers, not plain values, on
// purpose: an agent built before this change -- or mid-rollout -- sends
// the original four fields only, and DisallowUnknownFields below still
// accepts that body. A pointer left nil by json.Decode because the field
// was absent must never be treated the same as one explicitly set to
// zero/false -- zero dropped is good news, absent is no news. See
// handleHeartbeat's construction of store.AgentHeartbeat, which carries
// that same nil-vs-value distinction into storage.
type ingestHeartbeat struct {
	CanaryID          string `json:"canary_id,omitempty"`
	QueueDepth        int    `json:"queue_depth"`
	LogReadOK         bool   `json:"log_read_ok"`
	LastEventID       string `json:"last_event_id,omitempty"`
	AgentVersion      string `json:"agent_version,omitempty"`
	Dropped           *int64 `json:"dropped,omitempty"`
	Rejected          *int64 `json:"rejected,omitempty"`
	EventIDCollisions *int64 `json:"event_id_collisions,omitempty"`
	PositionFound     *bool  `json:"position_found,omitempty"`

	// PoisonerNames is the bait names the canary is asking for (#86 slice
	// D), comma-separated, for the canary page's facts column. Absent from
	// an agent built before the field existed, from one with the poisoner
	// road off, and from every kind but a honeypot -- all of which are
	// ordinary, and all of which are stored as NULL rather than as an empty
	// list.
	PoisonerNames string `json:"poisoner_names,omitempty"`
}

// ingestCommonHeartbeat is POST /ingest/heartbeat's body for every kind
// other than Honeypot (issue #106, ADR-0009's own promise: "the small
// common part -- agent version, last contact -- is shared; the rest
// belongs to the kind"). DisallowUnknownFields below refuses a scanner
// that sends queue_depth or log_read_ok outright -- it would be lying
// about having a log tailer at all -- with no bespoke field-by-field
// check to forget.
//
// Run and DBRefresh are the scanner's (issue #116, ADR-0012 decisions 9
// and 10), refused with 400 from any other kind.
type ingestCommonHeartbeat struct {
	CanaryID     string           `json:"canary_id,omitempty"`
	AgentVersion string           `json:"agent_version,omitempty"`
	Run          *ingestRunReport `json:"run,omitempty"`
	DBRefresh    *ingestDBRefresh `json:"db_refresh,omitempty"`
}

// ingestRunReport is where an ordered scan has got to: one of the three
// stages the scanner itself reports (store.AgentReportableStage).
type ingestRunReport struct {
	RunID string `json:"run_id"`
	Stage string `json:"stage"`
}

// ingestDBRefresh is the scanner's vulnerability database refresh
// state, present whenever a refresh has failed since the last success.
// FailingSince non-null is what "failing" means; birdcage records its
// own clock, not this value, as the start (store.SetCanaryDBRefresh).
type ingestDBRefresh struct {
	LastOKAt     *string `json:"last_ok_at"`
	FailingSince *string `json:"failing_since"`
	LastError    string  `json:"last_error"`
}

// maxRunIDLen bounds a reported run id: MintScanCommand's are 32 hex
// characters, so anything much longer is not one.
const maxRunIDLen = 128

// validateScannerHeartbeat checks the scanner-only fields' shapes,
// returning the 400 message or "".
func validateScannerHeartbeat(body ingestCommonHeartbeat) string {
	if body.Run != nil {
		if body.Run.RunID == "" || len(body.Run.RunID) > maxRunIDLen {
			return "run.run_id is required"
		}
		if !store.AgentReportableStage(body.Run.Stage) {
			return "run.stage must be one of mounts_checked, db_refreshed, scanning"
		}
	}
	if body.DBRefresh != nil {
		for name, v := range map[string]*string{"last_ok_at": body.DBRefresh.LastOKAt, "failing_since": body.DBRefresh.FailingSince} {
			if v == nil {
				continue
			}
			if _, err := time.Parse(time.RFC3339, *v); err != nil {
				return "db_refresh." + name + " must be an RFC3339 timestamp or null"
			}
		}
	}
	return ""
}

// handleHeartbeat serves POST /ingest/heartbeat, reached only through
// requireBearerToken -- which has already resolved tok.Kind to one this
// route allows (http.go's ingestRoutes: Honeypot or Scanner today). The
// body shape is per kind (issue #106): Honeypot keeps the original
// log-tailer shape, wire-unchanged; every other kind gets the common-only
// shape above. default below is unreachable in production -- defended
// the same way canaryTokenFromContext's own missing-token case is,
// against a wiring bug rather than a client error.
func (h *ingestHandler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		slog.Error("ingest: handleHeartbeat reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}

	switch tok.Kind {
	case agentkind.Honeypot:
		h.handleHoneypotHeartbeat(w, r, tok)
	case agentkind.Scanner:
		h.handleCommonHeartbeat(w, r, tok)
	default:
		slog.Error("ingest: handleHeartbeat reached with a kind this route should have refused", "kind", tok.Kind)
		writeIngestError(w, http.StatusInternalServerError, "internal error")
	}
}

// handleHoneypotHeartbeat is issue #32 slice 5a's original handler,
// unchanged in shape: Honeypot's own log-tailer self-report. Issue #106
// item 6 (owner, 2026-09-14): heartbeat moves off the dashboard's
// human-auth seam onto this submux, authenticated by the canary token,
// identity from the token. The dashboard's POST /api/heartbeat
// (internal/api/handlers.go) is left exactly as it is -- see this file's
// package doc and the commit message for what still depends on it --
// this is a second, independent write path onto the same
// canaries/heartbeats registry.
//
// Fail-closed (issue #32): an invalid body is a 4xx and the canary's
// last-seen does NOT advance -- a broken agent must look broken, never
// healthy. That falls out of the ordering below: store.RecordCanaryAgentHeartbeat
// is only ever reached after the body has decoded cleanly.
func (h *ingestHandler) handleHoneypotHeartbeat(w http.ResponseWriter, r *http.Request, tok store.CanaryToken) {
	r.Body = http.MaxBytesReader(w, r.Body, heartbeatMaxBodyBytes)
	var body ingestHeartbeat
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeIngestError(w, http.StatusBadRequest, "malformed heartbeat body")
		return
	}
	if dec.More() {
		writeIngestError(w, http.StatusBadRequest, "malformed heartbeat body: trailing data")
		return
	}

	if body.CanaryID != "" && body.CanaryID != tok.CanaryID {
		// Never trusted as identity, exactly like ingestBatch.NodeID
		// (issue #32: "the canary is the token's, whatever the body
		// says").
		slog.Warn("ingest: heartbeat payload named a different canary than its token; ignoring",
			"token_canary", tok.CanaryID, "payload_canary_id", body.CanaryID)
	}

	h.observeAgentVersion(r.Context(), tok, body.AgentVersion)

	report := store.AgentHeartbeat{
		QueueDepth:        body.QueueDepth,
		LogReadOK:         body.LogReadOK,
		LastEventID:       body.LastEventID,
		AgentVersion:      body.AgentVersion,
		Dropped:           body.Dropped,
		Rejected:          body.Rejected,
		EventIDCollisions: body.EventIDCollisions,
		PositionFound:     body.PositionFound,
		PoisonerNames:     body.PoisonerNames,
	}
	if err := store.RecordCanaryAgentHeartbeat(r.Context(), h.db, tok.CanaryID, h.now().UTC(), report); err != nil {
		if errors.Is(err, store.ErrCanaryNotFound) {
			// Mirrors internal/api's own handleHeartbeat: a live token
			// implies the canary_tokens row exists, but that table
			// carries no foreign key into canaries (0004's own comment),
			// so an unregistered canary id is a real, if unusual, state
			// -- not birdcage's own storage trouble. In practice, issue
			// #106's registry kind check already refuses a token with no
			// canaries row before this handler is ever reached; this
			// stays as the defended case for a token store bug that
			// somehow resolved one anyway.
			writeIngestError(w, http.StatusNotFound, "unknown canary")
			return
		}
		slog.Error("ingest: record agent heartbeat failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	recordLastSeenAddr(r, h.db, tok.CanaryID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// recordLastSeenAddr stores r's peer host as canaryID's
// canaries.last_seen_addr (issue #46 item 1), from r.RemoteAddr's own
// net.SplitHostPort -- never a payload value, the same "identity from
// the transport" rule the rest of this package already follows. Called
// only after the heartbeat itself has already been accepted and
// recorded, and deliberately best-effort: a failure here is logged and
// does not turn an otherwise-accepted heartbeat into a failed response,
// since this is a secondary signal (internal/selftestsched's own address
// to probe) rather than part of what "accepted" means for #45's health
// states.
func recordLastSeenAddr(r *http.Request, database *db.DB, canaryID string) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		slog.Warn("ingest: could not parse peer address for last-seen", "canary", canaryID, "remote_addr", r.RemoteAddr, "err", err)
		return
	}
	if err := store.SetCanaryLastSeenAddr(r.Context(), database, canaryID, host); err != nil {
		slog.Warn("ingest: record last-seen address failed", "canary", canaryID, "err", err)
	}
}

// handleCommonHeartbeat serves every kind other than Honeypot (Scanner
// today): the common-only shape, and a common-only store write
// (store.RecordCanaryCommonHeartbeat) that touches last-seen and
// agent_version and leaves every log-tailer column exactly as it was --
// see that function's own doc comment for why a scanner must never
// surface as a log tailer with an empty queue.
func (h *ingestHandler) handleCommonHeartbeat(w http.ResponseWriter, r *http.Request, tok store.CanaryToken) {
	r.Body = http.MaxBytesReader(w, r.Body, heartbeatMaxBodyBytes)
	var body ingestCommonHeartbeat
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeIngestError(w, http.StatusBadRequest, "malformed heartbeat body")
		return
	}
	if dec.More() {
		writeIngestError(w, http.StatusBadRequest, "malformed heartbeat body: trailing data")
		return
	}

	if tok.Kind != agentkind.Scanner && (body.Run != nil || body.DBRefresh != nil) {
		writeIngestError(w, http.StatusBadRequest, "run and db_refresh are scanner-only heartbeat fields")
		return
	}
	if msg := validateScannerHeartbeat(body); msg != "" {
		writeIngestError(w, http.StatusBadRequest, msg)
		return
	}

	if body.CanaryID != "" && body.CanaryID != tok.CanaryID {
		slog.Warn("ingest: heartbeat payload named a different canary than its token; ignoring",
			"token_canary", tok.CanaryID, "payload_canary_id", body.CanaryID)
	}

	h.observeAgentVersion(r.Context(), tok, body.AgentVersion)

	now := h.now().UTC()
	if err := store.RecordCanaryCommonHeartbeat(r.Context(), h.db, tok.CanaryID, h.now().UTC(), body.AgentVersion); err != nil {
		if errors.Is(err, store.ErrCanaryNotFound) {
			writeIngestError(w, http.StatusNotFound, "unknown canary")
			return
		}
		slog.Error("ingest: record common heartbeat failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	recordLastSeenAddr(r, h.db, tok.CanaryID)
	if tok.Kind == agentkind.Scanner {
		if err := h.recordScannerProgress(r, tok.CanaryID, body, now); err != nil {
			slog.Error("ingest: record scanner progress failed", "canary", tok.CanaryID, "err", err)
			writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// recordScannerProgress stores a scanner heartbeat's database refresh
// state -- clearing it when the field is absent -- and applies its stage
// report. A stage for a run that is not this node's, not open, or behind
// the one recorded is ignored and audited selftest.stage_stale through
// the coalescer; the response does not say which, so the route is no
// oracle for another node's run ids.
func (h *ingestHandler) recordScannerProgress(r *http.Request, canaryID string, body ingestCommonHeartbeat, now time.Time) error {
	failing := body.DBRefresh != nil && body.DBRefresh.FailingSince != nil
	lastError := ""
	if failing {
		lastError = body.DBRefresh.LastError
	}
	if err := store.SetCanaryDBRefresh(r.Context(), h.db, canaryID, failing, lastError, now); err != nil {
		return err
	}
	if body.Run == nil {
		return nil
	}
	result, err := store.AdvanceRunStage(r.Context(), h.db, canaryID, body.Run.RunID, store.ScanStage(body.Run.Stage), now)
	if err != nil {
		return err
	}
	if result == store.StageStale {
		recordSelfTestAudit(r.Context(), h.db, h.now, h.coalescer, canaryID, "selftest.stage_stale",
			"stage "+body.Run.Stage+" reported for a run that is not open, not this node's, or already further along", "reports")
	}
	return nil
}
