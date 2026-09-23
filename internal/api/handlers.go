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

// canaryWithSelfTest extends store.Canary with #46 slice 2's per-service
// self-test breakdown (item 4: "the API can say, per service,
// pass-at-grade / failed / untested"). store.Canary (internal/store/
// canary.go, slice 1's file, not this slice's to change) already carries
// the run-level summary -- LastSelfTestAt, LastSelfTestPassed,
// SelfTestFailedServices; this adds the per-service grade breakdown
// alongside it without touching that type. The embedded field's own
// fields are promoted to the top level by encoding/json, so the wire
// shape is store.Canary's fields plus one more, "self_test".
type canaryWithSelfTest struct {
	store.Canary
	SelfTest []store.SelfTestServiceResult `json:"self_test,omitempty"`
}

// canariesResponse is GET /api/canaries' body.
type canariesResponse struct {
	Canaries []canaryWithSelfTest `json:"canaries"`
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

	out := make([]canaryWithSelfTest, len(canaries))
	for i, c := range canaries {
		out[i] = canaryWithSelfTest{Canary: c}
		// One lookup per canary, the same shape ListCanaries' own
		// applySelfTestState call already makes per canary for the
		// run-level summary -- fleets this build targets are small
		// enough (#46's own module survey: "~50 canaries") that this
		// costs nothing worth a join.
		results, ok, err := store.SelfTestServiceResults(r.Context(), h.db, c.ID)
		if err != nil {
			log.Printf("api: self-test service results for %s: %v", c.ID, err)
			continue // the run-level summary above still renders; per-service detail is best-effort
		}
		if ok {
			out[i].SelfTest = results
		}
	}
	writeJSON(w, http.StatusOK, canariesResponse{Canaries: out})
}

// scansResponse is GET /api/scans' body.
type scansResponse struct {
	Scans []store.ScanSnapshot `json:"scans"`
}

// handleScans serves GET /api/scans (#108 slice 1): the minimal
// read-back of every recorded Nightjar scan receipt, same auth posture
// as GET /api/alerts (issue #8's requireAuth seam, not yet filled in).
// No filtering or paging -- #109 adds those once there is a findings
// table worth either over; this slice only has to prove a snapshot
// landed.
func (h *handler) handleScans(w http.ResponseWriter, r *http.Request) {
	scans, err := store.ListScanSnapshots(r.Context(), h.db)
	if err != nil {
		log.Printf("api: list scan snapshots: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, scansResponse{Scans: scans})
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

// visitorsResponse is GET /api/visitors' body. NextBefore mirrors
// alertsResponse.NextBefore's short-page signal (see handleAlerts), just
// keyed on a visitor's last_at instead of an alert id, since visitors
// are a grouping over alerts rather than alert rows themselves.
type visitorsResponse struct {
	Visitors   []store.Visitor `json:"visitors"`
	NextBefore *string         `json:"next_before"`
}

// handleVisitors serves GET /api/visitors?range=<Range>, defaulting and
// rejecting an unrecognized range exactly like handleCanaries.
func (h *handler) handleVisitors(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	window, err := store.ParseRange(q.Get("range"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "range must be one of 15m, 1h, 24h, 14d, 90d")
		return
	}

	now := h.now().UTC()
	filter := store.VisitorFilter{Since: now.Add(-window), Until: now}

	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be an RFC3339 timestamp, e.g. 2026-01-02T15:04:05Z")
			return
		}
		filter.Before = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "limit must be an integer")
			return
		}
		filter.Limit = n
	}

	visitors, err := store.ListVisitors(r.Context(), h.db, now, filter, h.internalRanges)
	if err != nil {
		log.Printf("api: list visitors: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	resp := visitorsResponse{Visitors: visitors}
	// Same "short page" signal as handleAlerts: a page shorter than the
	// effective limit is the only reliable "nothing more" indicator
	// available without a second query.
	if len(visitors) == store.NormalizeVisitorLimit(filter.Limit) {
		next := visitors[len(visitors)-1].LastAt.Format(time.RFC3339Nano)
		resp.NextBefore = &next
	}
	writeJSON(w, http.StatusOK, resp)
}

// historyResponse is GET /api/history's body (issue #56): the window it
// was asked for, every state period overlapping that window, and the
// per-canary per-state totals over it. store.StatePeriod and
// store.StateSummary already carry their own JSON shapes, so this
// envelope adds only the window they all refer to -- without which
// "total_s: 1500" says nothing.
type historyResponse struct {
	Range   string               `json:"range"`
	Since   time.Time            `json:"since"`
	Until   time.Time            `json:"until"`
	Periods []store.StatePeriod  `json:"periods"`
	Summary []store.StateSummary `json:"summary"`
}

// handleHistory serves GET /api/history?range=<Range>&canary=<id>,
// defaulting to store.DefaultRange when range is omitted and rejecting
// any other value with 400, exactly like handleCanaries -- the same
// five ranges the dashboard's picker offers, not a separate set: the
// section used to keep its own 24h/7d/30d list, which meant it could
// show a different window than the range chip said (issue #56 follow-up).
// An unknown canary id is not an error: it matches no periods, the
// same as a canary that has nothing to report.
//
// Canary names travel through this handler as plain JSON strings. They
// are attacker-influenced text -- whoever names a canary chooses them --
// and encoding/json escapes them for transport; making them safe to
// *display* is the frontend's job at the point it renders them
// (SECURITY.md, "Output escaping"), not this handler's to pre-empt by
// stripping or rewriting what an operator typed.
func (h *handler) handleHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rangeParam := q.Get("range")
	window, err := store.ParseRange(rangeParam)
	if err != nil {
		writeError(w, http.StatusBadRequest, "range must be one of 15m, 1h, 24h, 14d, 90d")
		return
	}
	if rangeParam == "" {
		rangeParam = store.DefaultRange
	}

	until := h.now().UTC()
	since := until.Add(-window)

	periods, err := store.ListStatePeriods(r.Context(), h.db, since, until, q.Get("canary"))
	if err != nil {
		log.Printf("api: list state periods: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, historyResponse{
		Range:   rangeParam,
		Since:   since,
		Until:   until,
		Periods: periods,
		Summary: store.SummarizeStatePeriods(periods, since, until),
	})
}

// mailResponse is GET /api/mail's body (issue #55): whether outbound
// mail is configured at all, and how the sending itself is going.
// store.MailStatus already carries its own JSON shape, so this envelope
// adds only the one fact that is not in the database -- an empty outbox
// looks the same whether mail is switched off or has simply had nothing
// to say, and the dashboard needs to tell "mail off" from "mail ok".
//
// Nothing here is a credential or derived from one: no host, no
// username, no address. An operator can see that mail is configured and
// whether it is working; they read their own configuration for the
// rest.
type mailResponse struct {
	Configured bool `json:"configured"`
	store.MailStatus
}

// handleMail serves GET /api/mail. It reports the state of the outbox
// whether or not mail is currently configured: rows left behind by a
// configuration that has since been removed are still owed, and hiding
// them would make a disabled mailer look like a drained one.
//
// last_error is the stored text for the oldest failing message, which
// internal/mail has already scrubbed of the credential before writing
// it (Sender.scrub). It is the one field on this endpoint that carries
// text birdcage did not compose entirely itself -- an SMTP server's own
// rejection -- so the frontend renders it through Svelte's text
// interpolation like every other value (SECURITY.md, "Output
// escaping").
func (h *handler) handleMail(w http.ResponseWriter, r *http.Request) {
	status, err := store.GetMailStatus(r.Context(), h.db)
	if err != nil {
		log.Printf("api: get mail status: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, mailResponse{Configured: h.mailConfigured, MailStatus: status})
}

// handleTrace serves GET /api/trace?range=<Range>. store.Trace already
// carries exactly TraceResponse's shape (frontend/src/lib/types.ts), so
// there is no wrapper struct to build here, unlike handleVisitors'
// pagination envelope.
func (h *handler) handleTrace(w http.ResponseWriter, r *http.Request) {
	rangeParam := r.URL.Query().Get("range")
	window, err := store.ParseRange(rangeParam)
	if err != nil {
		writeError(w, http.StatusBadRequest, "range must be one of 15m, 1h, 24h, 14d, 90d")
		return
	}
	if rangeParam == "" {
		rangeParam = store.DefaultRange
	}

	trace, err := store.ListTrace(r.Context(), h.db, h.now(), rangeParam, window, h.internalRanges)
	if err != nil {
		log.Printf("api: list trace: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, trace)
}
