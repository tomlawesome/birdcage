// Package driftsched runs issue #54's daily check: once a day, if any
// enrolled agent's last-reported version is behind birdcage's own
// (store's own agentBehindBirdcage, surfaced as
// store.StateAgentOutOfDate), send one email listing all of them.
//
// It follows internal/selftestsched's own shape -- a Scheduler holding
// its dependencies, New, Run ticking on an interval, Tick doing the
// work -- deliberately kept far smaller: there is no mint/probe/deadline
// machinery here, only a read of store.ListCanaries and, at most once a
// day, a write into mail_outbox through internal/mail.Sender. The daily
// bound itself lives in internal/mail's EnqueueAgentsBehind (it reads
// mail_outbox back, not any state this package keeps), which is what
// makes Tick safe to call far more often than once a day and safe across
// a restart: nothing here remembers "already sent today" itself.
package driftsched

import (
	"context"
	"log/slog"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/mail"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Scheduler owns the dependencies Tick needs: db to list agents,
// sender to enqueue the alert (nil when mail is off -- every method
// below stays a no-op, mirroring mail.Sender's own nil-receiver rule),
// birdcageVersion (cmd/birdcage's own stamped version, unreachable from
// internal/store) and now so a test can pin "current time" instead of
// depending on the wall clock.
type Scheduler struct {
	db              *db.DB
	sender          *mail.Sender
	birdcageVersion string
	now             func() time.Time
	log             *slog.Logger
}

// New constructs a Scheduler. sender may be nil (mail not configured);
// Tick then does nothing, ever, without touching the database.
func New(database *db.DB, sender *mail.Sender, birdcageVersion string, now func() time.Time, log *slog.Logger) *Scheduler {
	return &Scheduler{db: database, sender: sender, birdcageVersion: birdcageVersion, now: now, log: log}
}

// Run ticks every interval until ctx is done, calling Tick on each one.
// interval need not be anywhere near a day -- see the package comment
// for why a shorter cadence is safe -- and is a parameter rather than a
// package constant so a test can drive it fast.
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

// Tick lists every agent, keeps the ones store.ListCanaries already
// marked agent_out_of_date, and -- if there are any -- asks s.sender to
// enqueue one alert. A nil sender, or nothing behind, is a no-op: no
// query runs when mail is off, and no mail is ever composed when
// nothing is behind.
func (s *Scheduler) Tick(ctx context.Context) {
	if s.sender == nil {
		return
	}
	now := s.now().UTC()

	canaries, err := store.ListCanaries(ctx, s.db, now, 0, s.birdcageVersion)
	if err != nil {
		s.log.Error("list canaries for drift check", "err", err)
		return
	}

	var behind []mail.AgentBehindEntry
	for _, c := range canaries {
		if !hasState(c.ActiveStates, store.StateAgentOutOfDate) {
			continue
		}
		version := ""
		if c.AgentVersion != nil {
			version = *c.AgentVersion
		}
		behind = append(behind, mail.AgentBehindEntry{
			CanaryID:     c.ID,
			CanaryName:   c.Name,
			Lane:         c.Lane,
			AgentVersion: version,
		})
	}
	if len(behind) == 0 {
		return
	}

	if err := s.sender.EnqueueAgentsBehind(ctx, s.db, mail.AgentsBehindAlert{
		BirdcageVersion: s.birdcageVersion,
		Agents:          behind,
		At:              now,
	}); err != nil {
		s.log.Error("enqueue agents-behind mail", "err", err)
	}
}

// hasState reports whether states (a Canary's ActiveStates, plain
// strings on the wire) contains want.
func hasState(states []string, want store.HealthState) bool {
	for _, st := range states {
		if st == string(want) {
			return true
		}
	}
	return false
}
