// Package store: this file is issue #46 slice 2's grade taxonomy --
// which of three strengths of proof a self-test target can reach, fixed
// per service by the owner-ratified tables in notes 19897 and 20740, and
// the read side (SelfTestServiceResults) internal/api uses to report a
// canary's per-service results (item 4 of the slice 2 brief).
package store

import (
	"context"
	"fmt"

	"github.com/tomlawesome/birdcage/internal/db"
)

// Grade is how strong the evidence a passing self-test target provides,
// given what that service's OpenCanary module actually logs (#46 note
// 19897, "three grades of proof"; note 20736 shows it on the canary
// page, but adds no new health state -- see health.go, untouched by
// this slice).
type Grade string

const (
	// GradeMarked: the marker rides in a field the service logs
	// (username, path, community string, filename, ...) and birdcage
	// matches it by exact substring in the raw event -- SelfTestIndex's
	// own match, unchanged by this slice.
	GradeMarked Grade = "marked"

	// GradeChallengeMarked: vnc alone. The module logs its own random
	// challenge and whatever the client answered, validating neither
	// (vnc.py's _recv_auth); the agent answers
	// HMAC-SHA256(marker, challenge) truncated to 16 bytes
	// (internal/agent/probe/vnc.go), and birdcage recomputes it against
	// every one of the canary's still-live markers
	// (SelfTestIndex.matchVNCChallenge in selftest_vnc.go). Stronger
	// than a plaintext marker: a captured response cannot be replayed,
	// since the server draws a fresh challenge per connection.
	GradeChallengeMarked Grade = "challenge_marked"

	// GradeAttributed: ntp, portscan, llmnr. Nothing attacker-supplied
	// is logged, so birdcage claims a target only when exactly one
	// candidate event of that service arrives from the canary's own
	// reported address inside the run's whole window --
	// resolveAttributedTargets in selftest_attribution.go, run once the
	// window provably closes. Two or more candidates, or none, and
	// nothing is claimed; every candidate stays a real alert (note
	// 19855's exactly-one rule, deliberately failing toward real).
	GradeAttributed Grade = "attributed"
)

// serviceGrades is the ratified table (note 19897, corrected by note
// 20740's move of llmnr out of "marked" and into "attributed" once the
// unsolicited-response experiment showed no placement survives into
// OpenCanary's llmnr logdata). smb and llmnr are listed here even
// though this build has no carrier for either yet (smb: needs a real
// Samba audit VFS, a deploy-script dependency; llmnr: #86's own
// detector does not exist yet, see internal/agent/probe/carrier.go) --
// the grade a service *can* reach is a fact about its protocol, not
// about whether this build already has a carrier for it, and keeping
// both consistent here means only the carrier needs to change later.
var serviceGrades = map[string]Grade{
	"ftp":      GradeMarked,
	"http":     GradeMarked,
	"telnet":   GradeMarked,
	"smb":      GradeMarked,
	"snmp":     GradeMarked,
	"tftp":     GradeMarked,
	"sip":      GradeMarked,
	"redis":    GradeMarked,
	"mysql":    GradeMarked,
	"mssql":    GradeMarked,
	"postgres": GradeMarked,
	"rdp":      GradeMarked,
	"ssh":      GradeMarked,
	"vnc":      GradeChallengeMarked,
	"ntp":      GradeAttributed,
	"portscan": GradeAttributed,
	"llmnr":    GradeAttributed,
}

// gradeForService returns service's grade, defaulting to GradeMarked for
// anything absent from serviceGrades: every target this schema minted
// before this slice assumed substring marker matching, so an
// unrecognised service keeps behaving exactly as it always has rather
// than being silently reclassified.
func gradeForService(service string) Grade {
	if g, ok := serviceGrades[service]; ok {
		return g
	}
	return GradeMarked
}

// SelfTestServiceResult is one service's outcome from a canary's most
// recently completed self-test run -- item 4 of the slice 2 brief, "the
// API can say, per service, pass-at-grade / failed / untested". Passed
// is true once matched_at is set, at the grade recorded when the target
// was minted (this build has no fallback path that could reach a
// service at a weaker grade than the one it was minted for, so "the
// grade it can achieve" and "the grade the pass was reached at",
// item 1's two phrases, are the same column). A service the canary
// offers but that never got a target at all in the run (llmnr, for now
// -- see serviceGrades' own comment) has no row here at all: absence is
// how "untested" is represented, per note 20736's ban on a new health
// state -- there is no third value to set, only a row that does not
// exist.
type SelfTestServiceResult struct {
	Service string `json:"service"`
	Grade   Grade  `json:"grade"`
	Passed  bool   `json:"passed"`
}

// SelfTestServiceResults returns canaryID's most recently completed
// self-test run's per-service results, ordered by service for a stable
// display. ok is false when the canary has never completed a run --
// matching LatestCompletedSelfTestRun's own "never run is not a
// failure" stance, not an empty passed-nothing result.
func SelfTestServiceResults(ctx context.Context, database *db.DB, canaryID string) (results []SelfTestServiceResult, ok bool, err error) {
	run, ok, err := LatestCompletedSelfTestRun(ctx, database, canaryID)
	if err != nil || !ok {
		return nil, ok, err
	}

	rows, err := database.QueryContext(ctx, `
		SELECT service, grade, matched_at FROM self_test_targets
		WHERE command_id = ? ORDER BY service`, run.CommandID)
	if err != nil {
		return nil, false, fmt.Errorf("query self_test_targets for %s: %w", run.CommandID, err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			service, grade string
			matchedAt      *string
		)
		if err := rows.Scan(&service, &grade, &matchedAt); err != nil {
			return nil, false, fmt.Errorf("scan self_test_target: %w", err)
		}
		results = append(results, SelfTestServiceResult{
			Service: service,
			Grade:   Grade(grade),
			Passed:  matchedAt != nil,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate self_test_targets: %w", err)
	}
	return results, true, nil
}
