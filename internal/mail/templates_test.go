package mail

import (
	"strings"
	"testing"
	"time"
)

// TestTokenConflictBodyIsPinned holds the exact message birdcage sends.
// Pinned rather than spot-checked because this text is the whole
// feature: what it says, what it leaves out, and how quickly somebody
// woken by it can act are all decisions, and a diff on this string is
// the only way one of them changes visibly.
func TestTokenConflictBodyIsPinned(t *testing.T) {
	got := TokenConflictBody(TokenConflictAlert{
		CanaryID:   "canary-iot",
		CanaryName: "canary-iot",
		At:         time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC),
	})
	want := `A canary presented a credential birdcage had already revoked.

What happened
  - Canary: canary-iot (id canary-iot)
  - When: Thu, 17 Sep 2026 09:00:00 UTC

What it probably means
  - The token was stolen, and whoever took it rotated it before the
    canary did. The real canary is now holding the older credential.
  - Or two machines are running as one canary: a clone, a restored
    snapshot, or the same install deployed twice.

What to do
  - Look at that box now. This is the one state birdcage will wake you
    up for.
  - Open birdcage the way you always do, and read the canary there.

This message carries no link, no token and no detail of what was seen,
on purpose: the mailbox it arrived in is outside birdcage's trust
boundary, so it points at the evidence rather than copying it.
`
	if got != want {
		t.Errorf("body:\n%s\n---want---\n%s", got, want)
	}
}

// The suppression line only appears when something was suppressed, and
// reads correctly for one as well as for many.
func TestTokenConflictBodyReportsSuppressedAlerts(t *testing.T) {
	at := time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)
	since := at.Add(-time.Hour)

	none := TokenConflictBody(TokenConflictAlert{CanaryID: "c", CanaryName: "c", At: at})
	if strings.Contains(none, "suppressed") {
		t.Error("a message with nothing suppressed mentions suppression")
	}

	one := TokenConflictBody(TokenConflictAlert{
		CanaryID: "c", CanaryName: "c", At: at, SuppressedCount: 1, SuppressedSince: since,
	})
	if !strings.Contains(one, "  - 1 further alert was suppressed since Thu, 17 Sep 2026 08:00:00 UTC.\n") {
		t.Errorf("singular suppression line missing:\n%s", one)
	}

	many := TokenConflictBody(TokenConflictAlert{
		CanaryID: "c", CanaryName: "c", At: at, SuppressedCount: 7, SuppressedSince: since,
	})
	if !strings.Contains(many, "  - 7 further alerts were suppressed since Thu, 17 Sep 2026 08:00:00 UTC.\n") {
		t.Errorf("plural suppression line missing:\n%s", many)
	}
}

// A canary's name is whoever named it choosing a string. Ordinary names
// are shown; anything that does not survive the check is withheld and
// the id is shown instead, so the message still identifies the canary.
func TestTokenConflictBodyWithholdsAnUnusableName(t *testing.T) {
	at := time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"empty":              "",
		"whitespace only":    "   \t  ",
		"control characters": "\x00\x1b\x07",
		"invalid UTF-8":      "\xff\xfe",
		"absurdly long":      strings.Repeat("a", maxNameRunes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			got := TokenConflictBody(TokenConflictAlert{CanaryID: "canary-iot", CanaryName: raw, At: at})
			if !strings.Contains(got, "  - Canary id: canary-iot\n") {
				t.Errorf("the id is not shown in place of the name:\n%s", got)
			}
			if !strings.Contains(got, "name is withheld") {
				t.Errorf("the message does not say the name was withheld:\n%s", got)
			}
		})
	}
}

// Control characters inside an otherwise usable name are stripped, not
// escaped and not passed through: a header break or a terminal escape
// sequence chosen by whoever named the canary never reaches the wire.
func TestTokenConflictBodyStripsControlCharactersFromANameItShows(t *testing.T) {
	at := time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC)
	got := TokenConflictBody(TokenConflictAlert{
		CanaryID:   "canary-iot",
		CanaryName: "canary\r\nBcc: attacker@example.invalid",
		At:         at,
	})
	if !strings.Contains(got, "  - Canary: canaryBcc: attacker@example.invalid (id canary-iot)\n") {
		t.Errorf("the name was not stripped as expected:\n%s", got)
	}
	if strings.Contains(got, "\r") {
		t.Error("a carriage return survived into the body")
	}
}

// The id gets the same treatment as the name -- enrolment takes it from
// the operator, so it is not birdcage's own string either.
func TestTokenConflictBodyWithholdsAnUnusableID(t *testing.T) {
	got := TokenConflictBody(TokenConflictAlert{
		CanaryID:   "\x00\x00",
		CanaryName: "",
		At:         time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC),
	})
	if !strings.Contains(got, "  - Canary id: (withheld)\n") {
		t.Errorf("an unusable id was not withheld:\n%s", got)
	}
}

// The subject is fixed and says nothing about which canary or where.
func TestSubjectCarriesNoCanaryText(t *testing.T) {
	if TokenConflictSubject != "birdcage: a canary presented a revoked credential" {
		t.Errorf("subject = %q", TokenConflictSubject)
	}
	if !headerSafe(TokenConflictSubject) {
		t.Error("the subject is not a safe header value")
	}
}

// What the message must never contain, asserted directly rather than
// left to the pin above to catch by accident.
func TestTokenConflictBodyCarriesNoPointerToAnything(t *testing.T) {
	got := TokenConflictBody(TokenConflictAlert{
		CanaryID: "canary-iot", CanaryName: "canary-iot",
		At: time.Date(2026, 9, 17, 9, 0, 0, 0, time.UTC),
	})
	for _, forbidden := range []string{"http://", "https://", "token=", "://"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the body contains %q:\n%s", forbidden, got)
		}
	}
}
