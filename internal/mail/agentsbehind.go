package mail

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
)

// AgentsBehindSubject is the subject line of every agents-behind alert
// (issue #54), fixed and carrying no agent text -- the same reasoning
// TokenConflictSubject's own doc comment gives: a subject is read
// somewhere birdcage did not choose, so it says what happened and
// nothing that names a box.
const AgentsBehindSubject = "birdcage: one or more agents are running an out-of-date version"

// AgentBehindEntry is one line of the alert's list: an agent whose last
// reported version store.agentBehindBirdcage judged behind birdcage's
// own. AgentVersion is whatever the agent last reported (never empty --
// an agent this alert lists has, by definition, reported a version
// agentBehindBirdcage could parse).
type AgentBehindEntry struct {
	CanaryID     string
	CanaryName   string
	Lane         string
	AgentVersion string
}

// AgentsBehindAlert is everything AgentsBehindBody renders. Deliberately
// small, the same "what this message may carry is a security decision"
// reasoning TokenConflictAlert's own doc comment gives -- though a
// version string is far less sensitive than a hit or a source address,
// so this struct's bar is lower.
type AgentsBehindAlert struct {
	// BirdcageVersion is the release every entry below is behind.
	BirdcageVersion string
	// Agents is every agent behind, in the order the caller listed them
	// (driftsched.Scheduler.Tick: store.ListCanaries' own id order).
	Agents []AgentBehindEntry
	// At is when the check ran, rendered in UTC.
	At time.Time
}

// AgentsBehindBody renders the one message this file ever sends: what
// birdcage is running, which agents are behind and by how much, and
// where to act -- each canary's own page, never a link (the mailbox is
// outside birdcage's trust boundary, the same reasoning TokenConflictBody
// documents), since #54 deliberately leaves the exact upgrade command to
// that page rather than composing one into a mail an attacker's mailbox
// compromise could read.
func AgentsBehindBody(a AgentsBehindAlert) string {
	var b strings.Builder

	fmt.Fprintf(&b, "birdcage is running %s. %s behind that version:\n\n",
		a.BirdcageVersion, agentCountPhrase(len(a.Agents)))

	for _, e := range a.Agents {
		name, ok := displayName(e.CanaryName)
		if !ok {
			name = "(name withheld)"
		}
		fmt.Fprintf(&b, "  - %s (id %s), lane %s: running %s\n",
			name, displayID(e.CanaryID), displayLane(e.Lane), e.AgentVersion)
	}

	b.WriteString("\nWhat to do\n")
	b.WriteString("  - Open birdcage the way you always do, and open each agent's own\n    page there: the exact upgrade command for that agent is shown\n    there.\n")

	b.WriteString("\nThis message carries no link and no upgrade command, on purpose: the\n")
	b.WriteString("mailbox it arrived in is outside birdcage's trust boundary, so it\n")
	b.WriteString("points at the evidence rather than copying it.\n")

	return b.String()
}

// agentCountPhrase is AgentsBehindBody's own singular/plural line,
// spelled out for the same reason suppressedPhrase is: read by a person,
// not parsed by a machine.
func agentCountPhrase(n int) string {
	if n == 1 {
		return "1 agent is"
	}
	return fmt.Sprintf("%d agents are", n)
}

// displayLane is displayName's own withholding rule, applied to a
// canary's lane: attacker-influenced text (an operator's own free-text
// grouping) gets the same control-character strip, with "(withheld)"
// standing in for whatever doesn't survive it.
func displayLane(raw string) string {
	if lane, ok := displayName(raw); ok {
		return lane
	}
	return "(withheld)"
}

// EnqueueAgentsBehind is issue #54's daily check's own write path,
// called by internal/driftsched once it has computed which agents are
// behind. It enqueues at most one message per UTC calendar day: unlike
// EnqueueTokenConflict's attacker-paced signal, a version drift needs no
// per-agent cooldown or fleet-wide cap, only "not twice for the same
// day", which it gets by reading back the most recent agents_behind row
// (store.LatestMail with no canary id -- every row of this kind carries
// none) and comparing its CreatedAt's UTC calendar date against alert.At's.
//
// alert.Agents empty means nothing is behind: this function is never
// called for that case by driftsched, but treats it as a no-op rather
// than assuming a caller has already checked, the same defensive stance
// EnqueueTokenConflict's own nil-Sender check takes.
//
// A nil *Sender (mail is off) does nothing and reports no error.
func (s *Sender) EnqueueAgentsBehind(ctx context.Context, conn Conn, alert AgentsBehindAlert) error {
	if s == nil || len(alert.Agents) == 0 {
		return nil
	}
	at := alert.At.UTC()
	kind := store.MailKindAgentsBehind

	previous, err := store.LatestMail(ctx, conn, kind, "")
	if err != nil {
		return fmt.Errorf("look up the last %s mail: %w", kind, err)
	}
	if previous != nil && sameUTCDate(previous.CreatedAt, at) {
		// Already sent (or still owed) for today -- nothing suppressed
		// here, since driftsched ticks far more often than once a day
		// and simply has nothing new to report until tomorrow.
		return nil
	}

	return store.EnqueueMail(ctx, conn, store.MailMessage{
		Kind:          string(kind),
		CanaryID:      nil,
		Subject:       AgentsBehindSubject,
		Body:          AgentsBehindBody(alert),
		CreatedAt:     at,
		NextAttemptAt: at,
	})
}

// sameUTCDate reports whether a and b fall on the same UTC calendar
// day -- the whole of EnqueueAgentsBehind's "once a day" rule, and
// deliberately a calendar-date comparison rather than a 24h-duration
// one: the latter would let two ticks a few hours either side of
// midnight each send, or could suppress a second, genuinely
// next-day alert if the previous one landed late.
func sameUTCDate(a, b time.Time) bool {
	ay, am, ad := a.UTC().Date()
	by, bm, bd := b.UTC().Date()
	return ay == by && am == bm && ad == bd
}
