package ingest

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

// scanMaxBodyBytes bounds POST /ingest/scans' body -- a host's whole
// finding set, not a handful of scalars like heartbeatMaxBodyBytes's cap
// (heartbeat.go) or a batch of a few dozen events like maxBodyBytes'
// (batch.go). The "Scanner agent, slice 1" plan (#108, section 2) picks
// this explicitly: "300 KiB is far too small for a host's finding set."
// Over-cap is a 413, never a truncated snapshot -- a truncated finding
// set would be a false partial all-clear.
const scanMaxBodyBytes = 4 * 1024 * 1024

// ingestScanEngine identifies the scanner and vulnerability database
// that produced a snapshot -- internal/scan.Engine's wire shape,
// mirrored here deliberately rather than imported: this package must
// never depend on internal/scan, which ADR-0009 decision 6 fences to the
// scanner binary alone. Every field is optional (empty string): a run
// that failed before it ever loaded a database has nothing honest to
// report here (internal/scan.Result's own doc comment).
//
// DBRefreshedAt and DBRefreshError (issue #116, ADR-0012 decision 10)
// are the agent's last successful database refresh and, when this
// scan's own refresh failed, its error text.
type ingestScanEngine struct {
	Name           string `json:"name,omitempty"`
	Version        string `json:"version,omitempty"`
	DBBuiltAt      string `json:"db_built_at,omitempty"`
	DBRefreshedAt  string `json:"db_refreshed_at,omitempty"`
	DBRefreshError string `json:"db_refresh_error,omitempty"`
}

// dbRefreshErrorMaxLen bounds the refresh error text stored per
// snapshot.
const dbRefreshErrorMaxLen = 1024

// ingestScanFinding is one finding in a snapshot's findings array --
// internal/scan.Finding's wire shape, mirrored for the same reason
// ingestScanEngine is. Every field but fix_version is required.
type ingestScanFinding struct {
	Target        string `json:"target"`
	Package       string `json:"package"`
	Version       string `json:"version"`
	Type          string `json:"type"`
	Vulnerability string `json:"vulnerability"`
	Severity      string `json:"severity"`
	// FixVersion is empty when no fixed version is known.
	FixVersion string `json:"fix_version,omitempty"`
}

// ingestScan is POST /ingest/scans' request body -- the "Scanner agent,
// slice 1" plan (#108), section 2's wire shape, final: only server-side
// consumption of it grows later (#109, #110). There is no agent-identity
// field here at all, unlike ingestBatch.NodeID and ingestHeartbeat.CanaryID:
// the plan's payload names none, so there is nothing for a body to claim
// against the token. Identity is the token's exactly as those two
// routes' own comments describe -- it is simply never offered a
// competing value to ignore in the first place.
//
// AgentVersion is accepted (so DisallowUnknownFields doesn't reject a
// real caller) but not persisted onto scan_snapshots: the calling
// agent's own build version is already tracked against its canaries row
// by the existing heartbeat self-report (canaries.agent_version), and
// migration 0014's column list -- settled before this field was
// reconsidered -- does not repeat it.
//
// MaskedPaths is the host paths the scanner's read-only root mount
// covered over before this scan ran (design decision on #108, 2026-09-22): a
// covered path is a path the scan could not see, present on both an ok
// and a failed snapshot since the blind spot exists either way.
//
// RunID (issue #116, ADR-0012 decision 4) is present when this snapshot
// answers an ordered scan: the run id from the scan command's params.
type ingestScan struct {
	RunID        string              `json:"run_id,omitempty"`
	TakenAt      string              `json:"taken_at"`
	AgentVersion string              `json:"agent_version,omitempty"`
	Engine       ingestScanEngine    `json:"engine"`
	Status       string              `json:"status"`
	Reason       string              `json:"reason,omitempty"`
	Findings     []ingestScanFinding `json:"findings"`
	MaskedPaths  []string            `json:"masked_paths"`
}

// handleScan serves POST /ingest/scans, reached only through
// requireBearerToken -- #108 slice 1's own route, the scanner kind's
// sole write path, independent of the honeypot's alerts/heartbeats
// registry. Fail-closed the same way handleHeartbeat is: an invalid
// body is a 4xx and nothing is stored.
//
// Findings are validated and counted, never persisted -- migration
// 0014's own comment and #109, which adds the store they will hang off
// this table's id.
func (h *ingestHandler) handleScan(w http.ResponseWriter, r *http.Request) {
	tok, ok := canaryTokenFromContext(r.Context())
	if !ok {
		slog.Error("ingest: handleScan reached without a canary token in context")
		writeIngestError(w, http.StatusInternalServerError, "internal error")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, scanMaxBodyBytes)
	var body ingestScan
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeIngestError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeIngestError(w, http.StatusBadRequest, "malformed scan body")
		return
	}
	if dec.More() {
		writeIngestError(w, http.StatusBadRequest, "malformed scan body: trailing data")
		return
	}

	takenAt, err := time.Parse(time.RFC3339, body.TakenAt)
	if err != nil {
		writeIngestError(w, http.StatusBadRequest, "taken_at must be an RFC3339 timestamp")
		return
	}

	if body.Status != store.ScanStatusOK && body.Status != store.ScanStatusFailed {
		writeIngestError(w, http.StatusBadRequest, `status must be "ok" or "failed"`)
		return
	}
	if body.Status == store.ScanStatusFailed {
		if body.Reason == "" {
			writeIngestError(w, http.StatusBadRequest, "reason is required when status is failed")
			return
		}
		if len(body.Findings) > 0 {
			writeIngestError(w, http.StatusBadRequest, "findings must be empty when status is failed")
			return
		}
	} else {
		if body.Reason != "" {
			writeIngestError(w, http.StatusBadRequest, "reason must be empty when status is ok")
			return
		}
		if body.Engine.Name == "" || body.Engine.Version == "" || body.Engine.DBBuiltAt == "" {
			writeIngestError(w, http.StatusBadRequest, "engine name, version and db_built_at are required when status is ok")
			return
		}
		for i, f := range body.Findings {
			if reason, ok := validateFinding(f); !ok {
				writeIngestError(w, http.StatusBadRequest, fmt.Sprintf("finding %d: %s", i, reason))
				return
			}
		}
	}

	var dbBuiltAt *time.Time
	if body.Engine.DBBuiltAt != "" {
		t, err := time.Parse(time.RFC3339, body.Engine.DBBuiltAt)
		if err != nil {
			writeIngestError(w, http.StatusBadRequest, "engine.db_built_at must be an RFC3339 timestamp")
			return
		}
		dbBuiltAt = &t
	}

	var dbRefreshedAt *time.Time
	if body.Engine.DBRefreshedAt != "" {
		t, err := time.Parse(time.RFC3339, body.Engine.DBRefreshedAt)
		if err != nil {
			writeIngestError(w, http.StatusBadRequest, "engine.db_refreshed_at must be an RFC3339 timestamp")
			return
		}
		dbRefreshedAt = &t
	}
	if len(body.RunID) > maxRunIDLen {
		writeIngestError(w, http.StatusBadRequest, "unknown run")
		return
	}

	for i, p := range body.MaskedPaths {
		if !strings.HasPrefix(p, "/") {
			writeIngestError(w, http.StatusBadRequest, fmt.Sprintf("masked_paths[%d]: %q is not an absolute path", i, p))
			return
		}
	}

	now := h.now().UTC()
	snapshot := store.ScanSnapshot{
		CanaryID:       tok.CanaryID, // identity from the token; the body carries none to disagree with -- see ingestScan's own comment
		TakenAt:        takenAt,
		ReceivedAt:     now,
		EngineName:     body.Engine.Name,
		EngineVersion:  body.Engine.Version,
		DBBuiltAt:      dbBuiltAt,
		Status:         body.Status,
		Reason:         body.Reason,
		FindingCount:   len(body.Findings),
		MaskedPaths:    body.MaskedPaths,
		DBRefreshedAt:  dbRefreshedAt,
		DBRefreshError: truncate(body.Engine.DBRefreshError, dbRefreshErrorMaxLen),
	}
	// The server-side backstop for Grype's own five-day rule (ADR-0012
	// decisions 4 and 10), on every snapshot, at scan time
	// (store.ScanDBTooOld): a database older than that is never ok,
	// whatever the agent says. The
	// finding count goes with the status -- a failed snapshot carries
	// none (store.RecordScanSnapshot's invariant).
	if snapshot.Status == store.ScanStatusOK && store.ScanDBTooOld(dbBuiltAt, takenAt) {
		snapshot.Status = store.ScanStatusFailed
		snapshot.Reason = fmt.Sprintf("%s: vulnerability database built %s is more than five days old",
			store.ReasonDBTooOld, dbBuiltAt.UTC().Format(time.RFC3339))
		snapshot.FindingCount = 0
	}

	outcome, err := h.storeScan(r, snapshot, body.RunID, now)
	if err != nil {
		slog.Error("ingest: record scan snapshot failed", "canary", tok.CanaryID, "err", err)
		writeIngestError(w, http.StatusServiceUnavailable, "service unavailable")
		return
	}
	switch outcome {
	case store.ScanRunUnknown:
		recordSelfTestAudit(r.Context(), h.db, h.now, h.coalescer, tok.CanaryID, "selftest.run_unknown",
			"scan snapshot named a run that does not exist for this node; refused, nothing stored", "refusals")
		writeIngestError(w, http.StatusBadRequest, "unknown run")
		return
	case store.ScanRunStale:
		recordSelfTestAudit(r.Context(), h.db, h.now, h.coalescer, tok.CanaryID, "selftest.run_stale",
			"scan snapshot answered a run already completed or past its deadline; stored, settles nothing", "answers")
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// noRunAudit is storeScan's "nothing to audit" result: a timer scan, or
// a run that passed or failed.
const noRunAudit store.ScanRunOutcome = -1

// storeScan stores snapshot and, when runID is set, settles the run it
// answers -- all in one transaction (ADR-0012 decision 4). It also
// records the node's database refresh state from the snapshot. It
// returns store.ScanRunUnknown (nothing stored; the caller refuses the
// request) or store.ScanRunStale (stored, settles nothing) for the
// caller to audit after the transaction is over, and noRunAudit
// otherwise. Audits are written after commit: SQLite serves one
// connection, which the open transaction holds.
func (h *ingestHandler) storeScan(r *http.Request, snapshot store.ScanSnapshot, runID string, now time.Time) (store.ScanRunOutcome, error) {
	ctx := r.Context()
	tx, err := h.db.Begin(ctx)
	if err != nil {
		return noRunAudit, fmt.Errorf("begin scan transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	result := noRunAudit
	if runID != "" {
		match, err := store.MatchScanRun(ctx, tx, snapshot.CanaryID, runID, snapshot, now)
		if err != nil {
			return noRunAudit, err
		}
		switch match.Outcome {
		case store.ScanRunUnknown:
			return store.ScanRunUnknown, nil // deferred rollback: nothing stored
		case store.ScanRunStale:
			result = store.ScanRunStale
		default:
			snapshot.SelfTestRunID = match.CommandID
		}
	}

	if err := store.RecordScanSnapshot(ctx, tx, snapshot); err != nil {
		return noRunAudit, err
	}
	// Decision 10: a snapshot whose refresh failed marks the node
	// failing (from birdcage's clock, if not already); an ok snapshot
	// with a fresh refresh and no error clears it. A snapshot that says
	// neither (a failed scan, or an agent predating the fields) leaves
	// the state as it was.
	switch {
	case snapshot.DBRefreshError != "":
		err = store.SetCanaryDBRefresh(ctx, tx, snapshot.CanaryID, true, snapshot.DBRefreshError, now)
	case snapshot.Status == store.ScanStatusOK && snapshot.DBRefreshedAt != nil:
		err = store.SetCanaryDBRefresh(ctx, tx, snapshot.CanaryID, false, "", now)
	}
	if err != nil {
		return noRunAudit, err
	}
	if err := tx.Commit(); err != nil {
		return noRunAudit, fmt.Errorf("commit scan transaction: %w", err)
	}
	committed = true
	return result, nil
}

// truncate cuts s to at most n bytes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// validateFinding applies section 2's per-field requirement: every
// finding field except fix_version is required. Unlike batch.go's
// validateEvent, one bad finding fails the whole body rather than being
// rejected individually -- a scan snapshot is not acked per-finding
// (nothing about a finding is ever returned to the agent), so there is
// no shape for a partial rejection to take.
func validateFinding(f ingestScanFinding) (reason string, ok bool) {
	switch {
	case f.Target == "":
		return "target is required", false
	case f.Package == "":
		return "package is required", false
	case f.Version == "":
		return "version is required", false
	case f.Type == "":
		return "type is required", false
	case f.Vulnerability == "":
		return "vulnerability is required", false
	case f.Severity == "":
		return "severity is required", false
	}
	return "", true
}
