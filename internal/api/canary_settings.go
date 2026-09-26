// Package api: this file is issue #124's one write path onto
// canary_settings -- POST /api/canary/settings?id=<id>, the mechanism
// that lets the canary page change a setting (segment profile, bait
// names, pace floor/ceiling, working hours) on a running agent with no
// container restart. It is the first dashboard-authored write this
// package has ever had beside POST /api/heartbeat (api.go's own package
// doc): the same requireAuth placeholder guards it (issue #8 -- there is
// no stronger admin-write precedent anywhere in this package to copy
// yet), and every write is audited the same way store.Provision and
// cmd/birdcage's CLI writes already are.
package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/store"
)

// canarySettingsWriteMaxBodyBytes bounds the request body: a handful of
// short key/value pairs, never a list, matching
// internal/ingest/heartbeat.go's own heartbeatMaxBodyBytes reasoning for
// a body this shape.
const canarySettingsWriteMaxBodyBytes = 4 * 1024

// handleSetCanarySettings serves POST /api/canary/settings?id=<id>: the
// body is a flat JSON object of setting key to new value, e.g.
// {"segment_profile":"off"}. Every key is validated against the same
// closed set and rules the environment variables and enrolment flags
// already use (store.SetCanarySettings, store/canary_settings.go) before
// anything is written, and the whole request is one transaction -- a
// batch with one bad key writes nothing, not a partial update.
//
// An unknown canary id is 404. A key outside the closed set, an invalid
// value, or a key that does not apply to this canary's kind (e.g.
// segment_profile on a scanner) is 400, naming what was wrong. Success
// writes one audit entry naming which keys changed -- never their
// values, since one of them (bait_names) must never reach a log a
// compromised box's own reader could find (see internal/agent/poisoner's
// package comment) -- and answers {"ok":true}; the caller re-reads
// GET /api/canary for the new facts column.
func (h *handler) handleSetCanarySettings(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id must name a canary")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, canarySettingsWriteMaxBodyBytes)
	var raw map[string]string
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&raw); err != nil {
		writeError(w, http.StatusBadRequest, "body must be a flat JSON object of setting key to value")
		return
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "malformed body: trailing data")
		return
	}
	if len(raw) == 0 {
		writeError(w, http.StatusBadRequest, "body must name at least one setting")
		return
	}

	kind, err := store.GetCanaryKind(r.Context(), h.db, id)
	if errors.Is(err, store.ErrCanaryNotFound) {
		writeError(w, http.StatusNotFound, "unknown canary")
		return
	}
	if err != nil {
		log.Printf("api: get canary kind for %s: %v", id, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	updates := make(map[store.CanarySettingKey]string, len(raw))
	keys := make([]string, 0, len(raw))
	for k, v := range raw {
		updates[store.CanarySettingKey(k)] = v
		keys = append(keys, k)
	}

	now := h.now().UTC()
	if err := store.SetCanarySettings(r.Context(), h.db, id, kind, updates, now); err != nil {
		switch {
		case errors.Is(err, store.ErrCanarySettingUnknown),
			errors.Is(err, store.ErrCanarySettingInvalidValue),
			errors.Is(err, store.ErrCanarySettingWrongKind):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			log.Printf("api: set canary settings for %s: %v", id, err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	if _, err := audit.Append(r.Context(), h.db, audit.Entry{
		Action:      "canary_settings.updated",
		Target:      id,
		Reason:      "updated " + joinKeys(keys) + " via dashboard",
		TriggeredBy: "dashboard",
		CreatedAt:   now,
	}); err != nil {
		// The write already committed; an audit-append failure is
		// logged, not surfaced as a failed request -- matching this
		// package's existing stance elsewhere (recordLastSeenAddr,
		// canary.go) that a secondary record never turns an accepted
		// write into an error response.
		log.Printf("api: record canary settings audit entry for %s: %v", id, err)
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// joinKeys renders keys for the audit Reason -- key names only, never a
// value, so a bait name never reaches the audit log.
func joinKeys(keys []string) string {
	out := keys[0]
	for _, k := range keys[1:] {
		out += ", " + k
	}
	return out
}
