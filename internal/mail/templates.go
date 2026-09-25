package mail

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// TokenConflictSubject is the subject line of every token-conflict
// alert, fixed and carrying no canary text at all.
//
// Fixed because a subject is the part of a message most likely to be
// read somewhere birdcage did not choose -- a phone's lock screen, a
// notification, a ticketing system's list view, a mail server's logs --
// and the mailbox is outside the trust boundary either way. A subject
// naming the canary would put an attacker-influenced string in all of
// those places, and would also tell anyone watching the operator's
// notifications which box to go and wipe. It says what happened and
// nothing about where.
const TokenConflictSubject = "birdcage: an agent presented a revoked credential"

// maxNameRunes bounds how long a canary's name may be before this
// package stops trying to show it. A name is whoever named the canary's
// choice of string, so it is attacker-influenced text in an otherwise
// fixed message; past a couple of hundred characters it stops being a
// name and starts being a way to push the rest of the message out of
// view in a preview pane. Over the bound the name is withheld and the
// id is shown instead, the same as for a name that does not survive
// stripping.
const maxNameRunes = 200

// TokenConflictAlert is everything the body below says. Deliberately
// small: what this message may carry is a security decision, not a
// formatting one, so the only way to add a field to the mail is to add
// one here and argue for it.
//
// There is no hit, no source address, no token, no link and no port in
// this struct, and there will not be one. See the body's closing line.
type TokenConflictAlert struct {
	// CanaryID is birdcage's own identifier for the canary -- shown
	// when the name cannot be, and the thing an operator types into the
	// dashboard to find it.
	CanaryID string
	// CanaryName is whatever the canary is called. Attacker-influenced
	// text: stripped of control characters, and withheld entirely if
	// nothing usable survives.
	CanaryName string
	// At is when the conflict was recorded, rendered in UTC.
	At time.Time
	// SuppressedCount and SuppressedSince describe the alerts birdcage
	// deliberately did not send since the previous message for this
	// canary and kind -- the per-canary cooldown and the fleet-wide cap.
	// Zero means nothing was suppressed and the line is omitted.
	SuppressedCount int64
	SuppressedSince time.Time
}

// TokenConflictBody renders the one message birdcage sends.
//
// Four questions in order, because that is the order somebody woken up
// by this needs them in: what happened, when, what it probably means,
// what to do. Bullets rather than paragraphs, plain words rather than
// jargon: "the token was stolen" rather than "credential compromise
// suspected".
//
// What it deliberately does not contain, in every case for the same
// reason -- the mailbox is outside birdcage's trust boundary, so this
// message is a pointer and not a copy:
//
//   - No link. A link in an alert mail trains the operator to click
//     links in alert mails, which is the entire delivery mechanism of
//     the phishing mail that would impersonate this one.
//   - No token, no fingerprint, no part of any credential.
//   - No event content, no source address, no port. Whoever can read
//     this mailbox would otherwise learn what the attacker did and
//     where, from a copy sitting outside every control birdcage has.
//
// "Open birdcage the way you always do" is the instruction instead: the
// operator knows their own address for it, and an attacker reading this
// learns nothing from the sentence.
func TokenConflictBody(a TokenConflictAlert) string {
	var b strings.Builder

	b.WriteString("An agent presented a credential birdcage had already revoked.\n\n")

	b.WriteString("What happened\n")
	if name, ok := displayName(a.CanaryName); ok {
		fmt.Fprintf(&b, "  - Agent: %s (id %s)\n", name, displayID(a.CanaryID))
	} else {
		fmt.Fprintf(&b, "  - Agent id: %s\n", displayID(a.CanaryID))
		b.WriteString("  - The agent's name is withheld: it did not survive birdcage's own\n    check on the text before sending it.\n")
	}
	fmt.Fprintf(&b, "  - When: %s\n", a.At.UTC().Format(time.RFC1123))
	if a.SuppressedCount > 0 && !a.SuppressedSince.IsZero() {
		fmt.Fprintf(&b, "  - %s suppressed since %s.\n",
			suppressedPhrase(a.SuppressedCount), a.SuppressedSince.UTC().Format(time.RFC1123))
	}

	b.WriteString("\nWhat it probably means\n")
	b.WriteString("  - The token was stolen, and whoever took it rotated it before the\n    agent did. The real agent is now holding the older credential.\n")
	b.WriteString("  - Or two machines are running as one agent: a clone, a restored\n    snapshot, or the same install deployed twice.\n")

	b.WriteString("\nWhat to do\n")
	b.WriteString("  - Look at that box now. This is the one state birdcage will wake you\n    up for.\n")
	b.WriteString("  - Open birdcage the way you always do, and read the agent there.\n")

	b.WriteString("\nThis message carries no link, no token and no detail of what was seen,\n")
	b.WriteString("on purpose: the mailbox it arrived in is outside birdcage's trust\n")
	b.WriteString("boundary, so it points at the evidence rather than copying it.\n")

	return b.String()
}

// suppressedPhrase is the one line that reports what a rate limit
// stopped. Singular and plural are both written out rather than
// "1 further alerts": the message is read by a person, at speed,
// possibly at three in the morning.
func suppressedPhrase(n int64) string {
	if n == 1 {
		return "1 further alert was"
	}
	return fmt.Sprintf("%d further alerts were", n)
}

// displayName decides whether a canary's name can be shown. It strips
// control characters first (see stripControl), then withholds the
// result if nothing usable is left: empty after stripping and trimming,
// not valid UTF-8, or longer than maxNameRunes.
//
// Withholding rather than truncating or escaping is the choice here
// because the id is always available as a fallback that identifies the
// canary just as well, so there is no reason to show a mangled name at
// all.
func displayName(raw string) (string, bool) {
	if !utf8.ValidString(raw) {
		return "", false
	}
	name := strings.TrimSpace(stripControl(raw))
	if name == "" || utf8.RuneCountInString(name) > maxNameRunes {
		return "", false
	}
	return name, true
}

// displayID is displayName's equivalent for the canary id. An id is
// birdcage's own handle for the canary but it is not birdcage's own
// string -- enrolment takes it from the operator -- so it gets the same
// treatment, and the message still identifies the event even if nothing
// at all survives.
func displayID(raw string) string {
	if id, ok := displayName(raw); ok {
		return id
	}
	return "(withheld)"
}
