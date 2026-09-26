package api

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

// canaryFacts is the "this canary" column of issue #118's canary page:
// the standing facts about one canary that the fleet dashboard has never
// needed and so /api/canaries does not carry. Everything here is read
// back from what birdcage already records -- nothing is derived for
// display, which is the frontend's job.
//
// One fact the round-7 mockup shows is deliberately missing: who
// enrolled the canary. birdcage has no operator identity yet (issue #8's
// requireAuth is still a placeholder), and the audit log's triggered_by
// for an enrolment is "cli" or "enrolment", never a person -- so the
// field is absent rather than filled with something that only looks like
// an answer.
type canaryFacts struct {
	Kind               string  `json:"kind"`
	Lane               string  `json:"lane"`
	Ports              string  `json:"ports"`
	Address            *string `json:"address,omitempty"`
	HeartbeatIntervalS int     `json:"heartbeat_interval_s"`
	SelfTestEnabled    bool    `json:"self_test_enabled"`
	// SelfTestSchedule is the 24-hour UTC "HH:MM" the scheduled
	// self-test runs at -- the rotation schedule when the operator chose
	// "same schedule as key rotation" (store.SettingSelfTestUseRotationSchedule),
	// which is the default, so this is the time that actually applies
	// rather than whichever setting holds it.
	SelfTestSchedule string     `json:"self_test_schedule"`
	EnrolledAt       time.Time  `json:"enrolled_at"`
	RegisteredAt     *time.Time `json:"registered_at,omitempty"`
	AgentVersion     *string    `json:"agent_version,omitempty"`
	// PoisonerNames is the bait names this canary is asking for (#86 slice
	// D), comma-separated, as the agent last reported them. Absent for a
	// canary that reports none: the poisoner road off, an agent built
	// before the field existed, or any kind but a honeypot.
	//
	// These are visible here and nowhere else. The canary side keeps them
	// out of every log line on purpose (internal/agent/poisoner's package
	// comment) because the bait only works while nobody knows which names
	// it uses; this screen is the operator's own, and is where they are
	// meant to be readable.
	PoisonerNames *string `json:"poisoner_names,omitempty"`
	// TokenRotatedAt is when this canary's newest live token was minted,
	// and TokenRotatesAt the next occurrence of the rotation schedule --
	// the two halves of the facts column's "rotated <day> · next in
	// <duration>" row.
	TokenRotatedAt *time.Time `json:"token_rotated_at,omitempty"`
	TokenRotatesAt *time.Time `json:"token_rotates_at,omitempty"`

	// Settings is issue #124's own addition: every canary_settings row
	// for this canary, each with whether the agent's own last-reported
	// hash confirms it is actually running. Empty for a canary nothing
	// has ever been pushed to (no enrolment flag, no dashboard write) --
	// the ordinary state, and the same "a fact birdcage does not know is
	// left out" rule this whole struct already follows.
	Settings []canarySettingFact `json:"settings,omitempty"`
}

// canarySettingFact is one canary_settings row as the facts column draws
// it: its value and whether the agent has confirmed applying it.
// Confirmed is computed fresh on every read (store.SettingsHash of the
// current rows, compared against agents.settings_hash) rather than
// stored -- an admin write immediately makes every row's Confirmed false
// again, with no second write needed to say so.
type canarySettingFact struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Confirmed bool      `json:"confirmed"`
}

// selfTestRunSummary is one past self-test run as the page's line draws
// it: a tick under the line per run, filled with words above when the
// run failed. Only what a mark needs -- the command id and the marker
// bookkeeping stay in the store.
type selfTestRunSummary struct {
	IssuedAt       time.Time  `json:"issued_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	Passed         *bool      `json:"passed,omitempty"`
	FailedServices []string   `json:"failed_services,omitempty"`
}

// canaryPageResponse is GET /api/canary's body (issue #118): one
// canary's own view. The canary itself is exactly the shape
// /api/canaries already sends for it, so the page and the tile can never
// disagree about a status; the rest is what only this page asks for.
type canaryPageResponse struct {
	Canary       canaryWithSelfTest   `json:"canary"`
	Facts        canaryFacts          `json:"facts"`
	SelfTestRuns []selfTestRunSummary `json:"self_test_runs"`
}

// handleCanary serves GET /api/canary?id=<id>&range=<Range>: everything
// one canary's page draws that the fleet reads do not already carry.
// Deliberately a separate route rather than more fields on
// /api/canaries: the per-run self-test history and the token lookups
// below are per-canary queries, and the dashboard polls /api/canaries
// every thirty seconds for every canary.
//
// An unknown id is 404, unlike /api/history's "unknown canary matches no
// periods": a page about a canary that does not exist has nothing to
// draw, where a history section legitimately has nothing to say.
func (h *handler) handleCanary(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id must name a canary")
		return
	}
	window, err := store.ParseRange(q.Get("range"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "range must be one of 15m, 1h, 24h, 14d, 90d")
		return
	}

	now := h.now().UTC()
	canaries, err := store.ListCanaries(r.Context(), h.db, now, window)
	if err != nil {
		log.Printf("api: list canaries: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	var found *store.Canary
	for i := range canaries {
		if canaries[i].ID == id {
			found = &canaries[i]
			break
		}
	}
	if found == nil {
		writeError(w, http.StatusNotFound, "unknown canary")
		return
	}

	out := canaryWithSelfTest{Canary: *found}
	results, ok, err := store.SelfTestServiceResults(r.Context(), h.db, found.ID)
	if err != nil {
		// Best-effort, exactly as handleCanaries treats it: the
		// run-level summary on the canary still renders.
		log.Printf("api: self-test service results for %s: %v", found.ID, err)
	} else if ok {
		out.SelfTest = results
	}

	runs, err := store.ListSelfTestRuns(r.Context(), h.db, found.ID, now.Add(-window), now)
	if err != nil {
		log.Printf("api: list self-test runs for %s: %v", found.ID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	summaries := make([]selfTestRunSummary, len(runs))
	for i, run := range runs {
		summaries[i] = selfTestRunSummary{
			IssuedAt:       run.IssuedAt,
			CompletedAt:    run.CompletedAt,
			Passed:         run.Passed,
			FailedServices: run.FailedServices,
		}
	}

	facts, err := h.canaryFacts(r, *found, now)
	if err != nil {
		log.Printf("api: canary facts for %s: %v", found.ID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, canaryPageResponse{Canary: out, Facts: facts, SelfTestRuns: summaries})
}

// canaryFacts gathers the standing facts column: the canary's own
// columns, the self-test schedule settings, and the newest live token.
func (h *handler) canaryFacts(r *http.Request, c store.Canary, now time.Time) (canaryFacts, error) {
	facts := canaryFacts{
		Kind:               string(c.Kind),
		Lane:               c.Lane,
		Ports:              c.Ports,
		Address:            c.LastSeenAddr,
		HeartbeatIntervalS: c.HeartbeatIntervalS,
		EnrolledAt:         c.EnrolledAt,
		RegisteredAt:       c.RegisteredAt,
		AgentVersion:       c.AgentVersion,
		PoisonerNames:      c.PoisonerNames,
	}

	enabled, err := store.GetSetting(r.Context(), h.db, store.SettingSelfTestEnabled)
	if err != nil {
		return canaryFacts{}, err
	}
	facts.SelfTestEnabled = enabled == "true"

	useRotation, err := store.GetSetting(r.Context(), h.db, store.SettingSelfTestUseRotationSchedule)
	if err != nil {
		return canaryFacts{}, err
	}
	scheduleKey := store.SettingSelfTestSchedule
	if useRotation == "true" {
		scheduleKey = store.SettingRotationSchedule
	}
	schedule, err := store.GetSetting(r.Context(), h.db, scheduleKey)
	if err != nil {
		return canaryFacts{}, err
	}
	facts.SelfTestSchedule = schedule

	rotationSchedule, err := store.GetSetting(r.Context(), h.db, store.SettingRotationSchedule)
	if err != nil {
		return canaryFacts{}, err
	}
	if next, ok := nextScheduleTime(rotationSchedule, now); ok {
		facts.TokenRotatesAt = &next
	}

	tokens, err := store.ListCanaryTokensForCanary(r.Context(), h.db, c.ID)
	if err != nil {
		return canaryFacts{}, err
	}
	for _, tok := range tokens {
		if tok.RevokedAt != nil {
			continue
		}
		if facts.TokenRotatedAt == nil || tok.CreatedAt.After(*facts.TokenRotatedAt) {
			created := tok.CreatedAt
			facts.TokenRotatedAt = &created
		}
	}

	settings, err := store.ListCanarySettings(r.Context(), h.db, c.ID)
	if err != nil {
		return canaryFacts{}, err
	}
	if len(settings) > 0 {
		reportedHash, _, err := store.GetCanarySettingsHash(r.Context(), h.db, c.ID)
		if err != nil {
			return canaryFacts{}, err
		}
		currentHash := store.SettingsHash(settings)
		confirmed := reportedHash != "" && reportedHash == currentHash
		facts.Settings = make([]canarySettingFact, len(settings))
		for i, s := range settings {
			facts.Settings[i] = canarySettingFact{
				Key:       string(s.Key),
				Value:     s.Value,
				Version:   s.Version,
				UpdatedAt: s.UpdatedAt,
				// Confirmed is whole-canary, not per-key: issue #124's
				// wire protocol carries a single hash over every
				// setting, not a per-key acknowledgement, so "has the
				// agent confirmed" can only be answered for the settings
				// block as a whole -- true here means the agent's most
				// recent heartbeat reported effective settings that hash
				// identically to every row shown here, this one
				// included.
				Confirmed: confirmed,
			}
		}
	}
	return facts, nil
}

// nextScheduleTime is the next UTC instant matching a "HH:MM" schedule
// setting strictly after now. ok is false for a value that is not a
// schedule time, which GetSetting's own validation makes unreachable
// through SetSetting but which a hand-edited row could still hold.
func nextScheduleTime(schedule string, now time.Time) (time.Time, bool) {
	parsed, err := time.Parse("15:04", schedule)
	if err != nil {
		return time.Time{}, false
	}
	next := time.Date(now.Year(), now.Month(), now.Day(), parsed.Hour(), parsed.Minute(), 0, 0, time.UTC)
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next, true
}

// canaryRunsResponse is GET /api/canaries/{id}/runs' body.
type canaryRunsResponse struct {
	Runs []store.ScanRunSummary `json:"runs"`
}

// handleCanaryRuns serves GET /api/canaries/{id}/runs (issue #116,
// ADR-0012 decision 11): a scanner's completed ordered runs, newest
// first, at most store.DefaultScanRunsLimit -- trigger, when, verdict,
// last stage, reason and the settling snapshot's id. Never the run id.
// An unknown canary is 404, as on /api/canary; a canary with no scan
// runs (a honeypot, or a scanner registered before #116) is an empty
// list.
func (h *handler) handleCanaryRuns(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	runs, err := store.ListScannerRuns(r.Context(), h.db, id, store.DefaultScanRunsLimit)
	if errors.Is(err, store.ErrCanaryNotFound) {
		writeError(w, http.StatusNotFound, "unknown canary")
		return
	}
	if err != nil {
		log.Printf("api: list scan runs for %s: %v", id, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, canaryRunsResponse{Runs: runs})
}
