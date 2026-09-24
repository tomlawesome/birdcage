package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Finding is one vulnerability finding in a Snapshot -- the caller-facing
// shape SendScan carries onto the wire. A peer package (internal/scan,
// fenced to the scanner binary, never imported here -- see this file's
// own comment on wireScan below) builds these; this package only carries
// them.
type Finding struct {
	Target        string
	Package       string
	Version       string
	Type          string
	Vulnerability string
	Severity      string
	// FixVersion is empty when no fixed version is known.
	FixVersion string
}

// Engine identifies the scanner and vulnerability database that
// produced a Snapshot. Name, Version and DBBuiltAt are all zero-valued
// ("", "", the zero time.Time) when a run failed before it ever loaded a
// database -- there is nothing honest to report then, mirroring
// internal/scan.Engine's own doc comment.
type Engine struct {
	Name      string
	Version   string
	DBBuiltAt time.Time

	// DBRefreshedAt is ADR-0012 decision 10: the time of the last
	// successful `grype db update`, persisted across restarts by
	// cmd/nightjar's own state directory. Zero when no refresh has ever
	// succeeded.
	DBRefreshedAt time.Time
	// DBRefreshError is the refresh's error text when this scan's own
	// `grype db update` step failed -- empty when it succeeded. The scan
	// still ran on the last good database (Grype's own five-day cap
	// permitting), so a non-empty value here never implies Status ==
	// "failed".
	DBRefreshError string
}

// Snapshot is one scan's outcome, the shape SendScan posts to POST
// /ingest/scans (#108 slice 1, "Scanner agent, slice 1" plan section 2).
//
// Status is "ok" or "failed"; Reason is set exactly when Status is
// "failed", and Findings is empty exactly then too -- birdcage's own
// handler (internal/ingest/scans.go) enforces both, this package does
// not re-validate before sending.
//
// MaskedPaths is the host paths the scanner's read-only root mount
// covered over before this scan ran (design decision on #108, 2026-09-22):
// present on both an ok and a failed Snapshot, since the blind spot
// exists either way.
type Snapshot struct {
	TakenAt      time.Time
	AgentVersion string
	Engine       Engine
	Status       string
	Reason       string
	Findings     []Finding
	MaskedPaths  []string

	// RunID is ADR-0012 decision 1: present when this snapshot answers a
	// birdcage-minted `scan` command (proof or manual, decision 7), empty
	// for an ordinary timer scan -- exactly as today.
	RunID string
}

// wireScanEngine, wireScanFinding and wireScan mirror
// internal/ingest/scans.go's ingestScanEngine, ingestScanFinding and
// ingestScan field-for-field, deliberately duplicated rather than
// imported: this package must never depend on internal/ingest (server
// -only) or internal/scan (fenced to the scanner binary alone, ADR-0009
// decision 6), so the two sides can only drift apart by an edit this
// package's own tests -- run against internal/ingest's real handler, not
// a hand-written fake -- would catch.
type wireScanEngine struct {
	Name           string `json:"name,omitempty"`
	Version        string `json:"version,omitempty"`
	DBBuiltAt      string `json:"db_built_at,omitempty"`
	DBRefreshedAt  string `json:"db_refreshed_at,omitempty"`
	DBRefreshError string `json:"db_refresh_error,omitempty"`
}

type wireScanFinding struct {
	Target        string `json:"target"`
	Package       string `json:"package"`
	Version       string `json:"version"`
	Type          string `json:"type"`
	Vulnerability string `json:"vulnerability"`
	Severity      string `json:"severity"`
	FixVersion    string `json:"fix_version,omitempty"`
}

type wireScan struct {
	TakenAt      string            `json:"taken_at"`
	AgentVersion string            `json:"agent_version,omitempty"`
	Engine       wireScanEngine    `json:"engine"`
	Status       string            `json:"status"`
	Reason       string            `json:"reason,omitempty"`
	Findings     []wireScanFinding `json:"findings"`
	MaskedPaths  []string          `json:"masked_paths"`
	RunID        string            `json:"run_id,omitempty"`
}

// SendScan posts snapshot to POST /ingest/scans on token.
//
// A non-nil error is ErrUnauthorized or a *RetryableError (429, 5xx, a
// malformed response, or any status this package does not otherwise
// recognize -- including 413, "body too large": birdcage's own fail-
// closed rule treats an over-cap snapshot as never stored, never a
// truncated one, so the caller's own retry cadence is the right response
// here too, exactly as SendHeartbeat's own doc comment reasons about
// 404). #108's fail-closed rule -- an invalid or over-cap body is never
// stored -- is enforced entirely on birdcage's side; this function just
// reports whichever status came back.
func (c *Client) SendScan(ctx context.Context, token string, snapshot Snapshot) error {
	findings := make([]wireScanFinding, len(snapshot.Findings))
	for i, f := range snapshot.Findings {
		findings[i] = wireScanFinding(f)
	}
	maskedPaths := snapshot.MaskedPaths
	if maskedPaths == nil {
		maskedPaths = []string{}
	}

	var dbBuiltAt string
	if !snapshot.Engine.DBBuiltAt.IsZero() {
		dbBuiltAt = snapshot.Engine.DBBuiltAt.UTC().Format(time.RFC3339)
	}
	var dbRefreshedAt string
	if !snapshot.Engine.DBRefreshedAt.IsZero() {
		dbRefreshedAt = snapshot.Engine.DBRefreshedAt.UTC().Format(time.RFC3339)
	}

	body, err := json.Marshal(wireScan{
		TakenAt:      snapshot.TakenAt.UTC().Format(time.RFC3339),
		AgentVersion: snapshot.AgentVersion,
		Engine: wireScanEngine{
			Name:           snapshot.Engine.Name,
			Version:        snapshot.Engine.Version,
			DBBuiltAt:      dbBuiltAt,
			DBRefreshedAt:  dbRefreshedAt,
			DBRefreshError: snapshot.Engine.DBRefreshError,
		},
		Status:      snapshot.Status,
		Reason:      snapshot.Reason,
		Findings:    findings,
		MaskedPaths: maskedPaths,
		RunID:       snapshot.RunID,
	})
	if err != nil {
		return fmt.Errorf("client: encode scan: %w", err)
	}

	resp, doErr := c.post(ctx, "/ingest/scans", token, body)
	if doErr != nil {
		return doErr
	}
	defer closeBody(resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	default:
		return retryable(fmt.Errorf("client: scan: unexpected status %d (%s)", resp.StatusCode, errorMessage(resp)))
	}
}
