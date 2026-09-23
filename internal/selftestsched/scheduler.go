// Package selftestsched runs issue #46's scheduled self-test: a ticker
// that, once a minute, mints a self-test command for every eligible
// honeypot canary on the operator's chosen time-of-day schedule, sweeps
// runs that passed their deadline still unmatched, and -- through
// RotationSucceeded -- mints immediately after a rotation instead, when
// the operator has chosen "same schedule as key rotation".
//
// This package is deliberately independent of internal/ingest: Scheduler
// implements internal/ingest.SelfTestRotationHook structurally (a Go
// interface needs no import to be satisfied by), so neither package
// imports the other. cmd/birdcage's main is the only thing that
// constructs both and wires one into the other.
package selftestsched

import (
	"context"
	"log/slog"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// selfTestWindow is a minted run's deadline, from issued_at (issue #46
// item 5b). Built up from the worst case an honest, on-time agent takes
// to answer:
//
//   - up to commandPollInterval + commandPollJitter (cmd/mockingbird's
//     own constants: 60s +/- 10s) before the agent even picks the
//     command up -- 70s worst case.
//   - probe.DefaultSweepTimeout (internal/agent/probe, 90s) bounds the
//     whole sweep regardless of target count -- the agent probes every
//     target concurrently in batches, not serially, so this does not
//     grow with the number of targets (capped at selftest.MaxTargets =
//     32 in any case).
//   - the probe outcomes still have to travel back as ordinary
//     OpenCanary events over the existing ingest roads, which are not
//     instant but are ordinarily seconds, not minutes.
//
// 70s + 90s is 160s (~2.7min); 10 minutes is a generous margin above
// that for a slow event road or a canary that is a little behind on its
// own clock, without leaving a dead service "still running" for so long
// that an operator watching the tile has to wonder whether it will ever
// resolve.
const selfTestWindow = 10 * time.Minute

// doubleMintGuard is how recently a run must have been issued to block
// minting a second one for the same canary -- issue #46 item 5b: "never
// mint twice in the same minute for the same canary". 2 minutes rather
// than exactly 1 covers a tick that lands a few seconds either side of
// the minute boundary, or a rotation landing moments after a scheduled
// mint, without letting a canary go an extra scheduled cycle unminted.
const doubleMintGuard = 2 * time.Minute

// scheduleTimeLayout matches store.validateSettingScheduleTime's own
// format: a strict, zero-padded 24-hour UTC "HH:MM".
const scheduleTimeLayout = "15:04"

// Scheduler owns the dependencies both the per-minute tick and the
// rotation-coupled hook need: db for settings/canaries/mint, idx so a
// freshly minted run's markers are recognised by internal/ingest the
// instant they exist (the same *store.SelfTestIndex the ingest handler
// itself was built with -- see ingest.NewHandler's own doc comment),
// and now so a test can pin "current time" instead of depending on the
// wall clock.
type Scheduler struct {
	db  *db.DB
	idx *store.SelfTestIndex
	now func() time.Time
	log *slog.Logger
}

// New constructs a Scheduler. idx must be the same index passed to
// ingest.NewHandler, constructed once by cmd/birdcage's main -- see that
// package's own doc comment for why sharing one instance matters.
func New(database *db.DB, idx *store.SelfTestIndex, now func() time.Time, log *slog.Logger) *Scheduler {
	return &Scheduler{db: database, idx: idx, now: now, log: log}
}

// Run ticks every interval until ctx is done, calling Tick on each one.
// interval is a parameter (not a package constant) so a test can drive
// it far faster than the real one-minute cadence -- the same shape
// cmd/nightjar's runHeartbeatLoop uses for the same reason. "Now" on
// each tick comes from s.now, not the ticker's own fire time, so a
// test can also pin the clock independently of how fast it drives the
// ticker.
func (s *Scheduler) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Tick(ctx)
		}
	}
}

// Tick is Run's per-interval body (issue #46 item 5), in three parts:
// the scheduled mint, which selftest_enabled and the schedule settings
// govern; the deadline sweep; and the pending retry (issue #47 step 9),
// which re-mints the enrolment proof for a canary still pending. The
// last two run whatever the settings say -- a first-contact run minted
// while the daily self-test is switched off still has to expire, and a
// canary whose first run expired still has to be proven -- so only the
// scheduled mint is skipped when selftest_enabled is false. If any
// setting fails to read or parse, Tick does nothing at all for this
// tick and logs the failure once; it never falls back to a default
// schedule.
func (s *Scheduler) Tick(ctx context.Context) {
	now := s.now().UTC()

	enabled, err := s.readBool(ctx, store.SettingSelfTestEnabled)
	if err != nil {
		s.log.Error("read selftest_enabled; doing nothing this tick", "err", err)
		return
	}
	if enabled {
		useRotation, err := s.readBool(ctx, store.SettingSelfTestUseRotationSchedule)
		if err != nil {
			s.log.Error("read selftest_use_rotation_schedule; doing nothing this tick", "err", err)
			return
		}

		// When the rotation-coupled schedule is on, this tick mints
		// nothing itself -- see RotationSucceeded, fired by
		// internal/ingest's handleRotate the instant a rotation actually
		// succeeds.
		if !useRotation {
			schedule, err := store.GetSetting(ctx, s.db, store.SettingSelfTestSchedule)
			if err != nil {
				s.log.Error("read selftest_schedule; doing nothing this tick", "err", err)
				return
			}
			if now.Format(scheduleTimeLayout) == schedule {
				s.mintForEligibleCanaries(ctx, now)
			}
		}
	}

	n, err := store.SweepExpiredSelfTestRuns(ctx, s.db, now)
	if err != nil {
		s.log.Error("sweep expired self-test runs", "err", err)
		return
	}
	if n > 0 {
		s.log.Info("swept expired self-test runs", "count", n)
	}

	s.retryPending(ctx, now)
}

// retryPending re-mints the enrolment proof for every honeypot canary
// still pending (issue #47 step 9: "retried the same way over the
// command channel"): FirstContact minted its first run; if that run
// expired unmatched the canary would otherwise stay pending until the
// daily schedule happened to reach it, or forever with the daily
// self-test switched off. One run per selfTestWindow, not per tick
// (mintForCanary's guard is the whole window here), so a canary that
// never answers costs one open run at a time and one failed run per
// window. Runs after the sweep so the run that just expired is the one
// being replaced, not a reason to wait.
func (s *Scheduler) retryPending(ctx context.Context, now time.Time) {
	canaries, err := store.ListHoneypotCanariesForSelfTest(ctx, s.db)
	if err != nil {
		s.log.Error("list honeypot canaries for pending retry", "err", err)
		return
	}
	for _, c := range canaries {
		if !c.Pending || c.LastSeenAddr == nil || *c.LastSeenAddr == "" || len(c.Ports) == 0 {
			continue
		}
		s.mintForCanary(ctx, c, now, selfTestWindow)
	}
}

// readBool reads a "true"/"false" setting (store.validateSettingBool's
// own closed vocabulary) as a bool.
func (s *Scheduler) readBool(ctx context.Context, key store.SettingKey) (bool, error) {
	v, err := store.GetSetting(ctx, s.db, key)
	if err != nil {
		return false, err
	}
	return v == "true", nil
}

// mintForEligibleCanaries mints one self-test command for every
// kind-honeypot canary with a LastSeenAddr and at least one port (issue
// #46 item 5b) -- a canary the scheduler has no address or nothing to
// probe for is silently skipped, not an error.
func (s *Scheduler) mintForEligibleCanaries(ctx context.Context, now time.Time) {
	canaries, err := store.ListHoneypotCanariesForSelfTest(ctx, s.db)
	if err != nil {
		s.log.Error("list honeypot canaries for self-test", "err", err)
		return
	}
	for _, c := range canaries {
		if c.LastSeenAddr == nil || *c.LastSeenAddr == "" || len(c.Ports) == 0 {
			continue
		}
		s.mintForCanary(ctx, c, now, doubleMintGuard)
	}
}

// mintForCanary is the mint helper shared by the scheduled tick,
// RotationSucceeded, FirstContact and the pending retry (issue #46
// items 5b/5c, #47 steps 8-9): the recent-run guard, target derivation
// (skipping ports with no known service, logging each skip) and the
// MintSelfTestCommand call all live here once, so the trigger paths can
// never disagree about any of it. guard is how recently a run must have
// been issued to block this one: doubleMintGuard for every trigger but
// the pending retry, which uses the whole selfTestWindow.
func (s *Scheduler) mintForCanary(ctx context.Context, c store.SelfTestCanary, now time.Time, guard time.Duration) {
	recent, err := store.HasRecentSelfTestRun(ctx, s.db, c.ID, now.Add(-guard))
	if err != nil {
		s.log.Error("check recent self-test runs", "canary", c.ID, "err", err)
		return
	}
	if recent {
		return
	}

	var targets []store.SelfTestTarget
	for _, port := range c.Ports {
		service, ok := store.WellKnownServiceForPort(port)
		if !ok {
			s.log.Warn("self-test: port maps to no known service, skipping", "canary", c.ID, "port", port)
			continue
		}
		targets = append(targets, store.SelfTestTarget{Service: service, DestPort: port})
	}
	if len(targets) == 0 {
		s.log.Warn("self-test: no probeable targets after filtering ports, skipping canary", "canary", c.ID)
		return
	}

	deadline := now.Add(selfTestWindow)
	cmd, err := store.MintSelfTestCommand(ctx, s.db, s.idx, c.ID, *c.LastSeenAddr, targets, now, deadline)
	if err != nil {
		s.log.Error("mint self-test command", "canary", c.ID, "err", err)
		return
	}
	s.log.Info("minted self-test command", "canary", c.ID, "command_id", cmd.ID, "targets", len(targets))
}

// FirstContact implements internal/ingest.SelfTestRotationHook's second
// method (issue #47 step 8): mints a self-test run the instant a
// provisioned canary's very first authenticated request lands --
// internal/ingest's requireBearerToken, the "first use of a canary's
// first token" branch of completeRotation, which can fire at most once
// per canary's lifetime. Unlike Tick and RotationSucceeded, this is
// unconditional: no selftest_enabled or schedule-setting read at all,
// because enrolment proof is not the daily schedule (#47's own "Step 8
// is the part that matters"). Reuses mintForCanary -- the same
// double-mint guard, target derivation and MintSelfTestCommand call
// every mint path shares -- so a first contact landing moments before or
// after a scheduled tick can never mint the run twice.
//
// Honeypot-only, the same restriction RotationSucceeded applies and for
// the same reason: a self-test command is only ever delivered to a
// kind-honeypot canary (internal/ingest's ingestRoutes gates POST
// /ingest/commands to Honeypot alone), so minting one for any other kind
// would only ever expire unmatched -- and here specifically would leave
// that canary's tile stuck on both "pending" and "self_test_failed" for
// a proof it can never pass. A canary of a kind with no self-test
// mechanism has no path off pending through this hook; see this build's
// report.
//
// c.LastSeenAddr would ordinarily still be nil at this exact moment (no
// heartbeat, and no earlier request, has ever run for this canary) -- the
// call site in internal/ingest/auth.go's completeRotation records the
// connection's own source address first, via the same
// store.SetCanaryLastSeenAddr internal/ingest/heartbeat.go's own
// last-seen write uses, so the lookup below already finds it set.
func (s *Scheduler) FirstContact(ctx context.Context, canaryID string, at time.Time) {
	c, ok, err := store.SelfTestCanaryByID(ctx, s.db, canaryID)
	if err != nil {
		s.log.Error("look up canary for first-contact self-test", "canary", canaryID, "err", err)
		return
	}
	if !ok || c.Kind != agentkind.Honeypot || c.LastSeenAddr == nil || *c.LastSeenAddr == "" || len(c.Ports) == 0 {
		return
	}
	s.mintForCanary(ctx, c, at.UTC(), doubleMintGuard)
}

// RotationSucceeded implements internal/ingest.SelfTestRotationHook
// (issue #46 item 5c): mints the rotation-coupled self-test the instant
// a canary's token rotation succeeds, when the operator has chosen
// "same schedule as key rotation" and self-test is enabled. Only a
// kind-honeypot canary is eligible -- a self-test command is never
// delivered to any other kind (internal/ingest's ingestRoutes gates
// POST /ingest/commands to Honeypot alone), so minting one for a
// Scanner would only ever expire unmatched. Every failure is logged and
// swallowed: handleRotate's own response has already been decided by
// the time this runs, and a self-test concern must never be allowed to
// affect it.
func (s *Scheduler) RotationSucceeded(ctx context.Context, canaryID string, at time.Time) {
	enabled, err := s.readBool(ctx, store.SettingSelfTestEnabled)
	if err != nil {
		s.log.Error("read selftest_enabled for rotation hook", "canary", canaryID, "err", err)
		return
	}
	if !enabled {
		return
	}
	useRotation, err := s.readBool(ctx, store.SettingSelfTestUseRotationSchedule)
	if err != nil {
		s.log.Error("read selftest_use_rotation_schedule for rotation hook", "canary", canaryID, "err", err)
		return
	}
	if !useRotation {
		return
	}

	c, ok, err := store.SelfTestCanaryByID(ctx, s.db, canaryID)
	if err != nil {
		s.log.Error("look up canary for rotation-coupled self-test", "canary", canaryID, "err", err)
		return
	}
	if !ok || c.Kind != agentkind.Honeypot || c.LastSeenAddr == nil || *c.LastSeenAddr == "" || len(c.Ports) == 0 {
		return
	}
	s.mintForCanary(ctx, c, at.UTC(), doubleMintGuard)
}
