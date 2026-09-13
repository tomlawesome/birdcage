package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

// alertsResponse is GET /api/alerts' body. NextBefore is the id of the
// last (oldest) alert on this page, for the caller to pass back as
// ?before= to fetch the next page -- nil once a page comes back shorter
// than the effective limit, which is the only reliable "nothing more"
// signal available (a full page can occasionally also be the last one;
// the caller just tries once more and gets an empty page back).
type alertsResponse struct {
	Alerts     []store.Alert `json:"alerts"`
	NextBefore *int64        `json:"next_before"`
}

// handleAlerts serves GET /api/alerts, translating query parameters
// into a store.AlertFilter. Every parse failure is reported as the
// specific thing that was wrong, since these are caller-supplied values
// (unlike a database failure, which is never shown verbatim -- see
// writeError's doc comment).
func (h *handler) handleAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.AlertFilter{
		InstanceID: q.Get("instance"),
		SourceIP:   q.Get("source_ip"),
		Service:    q.Get("service"),
	}

	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "since must be an RFC3339 timestamp, e.g. 2026-01-02T15:04:05Z")
			return
		}
		filter.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "until must be an RFC3339 timestamp, e.g. 2026-01-02T15:04:05Z")
			return
		}
		filter.Until = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "limit must be an integer")
			return
		}
		filter.Limit = n
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be an integer alert id")
			return
		}
		filter.Before = n
	}

	alerts, err := store.ListAlerts(r.Context(), h.db, filter)
	if err != nil {
		log.Printf("api: list alerts: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	resp := alertsResponse{Alerts: alerts}
	// A short page (fewer rows than the effective limit) is the only
	// reliable "nothing more" signal SQL gives us here -- see
	// store.NormalizeLimit's doc comment for why the handler recomputes
	// the same effective limit rather than trusting filter.Limit as-is.
	if len(alerts) == store.NormalizeLimit(filter.Limit) {
		next := alerts[len(alerts)-1].ID
		resp.NextBefore = &next
	}
	writeJSON(w, http.StatusOK, resp)
}

// instancesResponse is GET /api/instances' body.
type instancesResponse struct {
	Instances []store.Instance `json:"instances"`
}

func (h *handler) handleInstances(w http.ResponseWriter, r *http.Request) {
	instances, err := store.ListInstances(r.Context(), h.db)
	if err != nil {
		log.Printf("api: list instances: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, instancesResponse{Instances: instances})
}

// handleStats serves GET /api/stats. h.now, not time.Now directly, is
// what lets TestHandleStatsUsesInjectedNow pin "now" without depending
// on wall-clock time.
func (h *handler) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := store.GetStats(r.Context(), h.db, h.now())
	if err != nil {
		log.Printf("api: get stats: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// canariesResponse is GET /api/canaries' body.
type canariesResponse struct {
	Canaries []store.Canary `json:"canaries"`
}

// handleCanaries serves GET /api/canaries?range=<Range>, defaulting to
// store.DefaultRange when range is omitted and rejecting any other
// unrecognized value with 400 (issue #34).
func (h *handler) handleCanaries(w http.ResponseWriter, r *http.Request) {
	window, err := store.ParseRange(r.URL.Query().Get("range"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "range must be one of 15m, 1h, 24h, 14d, 90d")
		return
	}

	canaries, err := store.ListCanaries(r.Context(), h.db, h.now(), window)
	if err != nil {
		log.Printf("api: list canaries: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, canariesResponse{Canaries: canaries})
}

// heartbeatRequest is POST /api/heartbeat's body.
type heartbeatRequest struct {
	Canary string `json:"canary"`
}

// handleHeartbeat serves POST /api/heartbeat, recording that the named
// canary phoned home at h.now(). A canary id that isn't registered
// (store.ErrCanaryNotFound) is reported as 404 rather than silently
// accepted, since enrollment (#1) is what's supposed to create the row.
func (h *handler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req heartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, `body must be JSON: {"canary": "<id>"}`)
		return
	}
	if strings.TrimSpace(req.Canary) == "" {
		writeError(w, http.StatusBadRequest, "canary must not be empty")
		return
	}

	err := store.RecordHeartbeat(r.Context(), h.db, req.Canary, h.now())
	switch {
	case errors.Is(err, store.ErrCanaryNotFound):
		writeError(w, http.StatusNotFound, "unknown canary")
		return
	case err != nil:
		log.Printf("api: record heartbeat: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
