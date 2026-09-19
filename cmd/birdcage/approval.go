package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/approval"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/mailbox"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/term"
)

// approvalPollInterval is how often birdcage looks in the approval
// mailbox. An upgrade approval is a human replying to an email, so a
// minute of latency is nothing next to the minutes or hours the human
// takes; polling faster would only mean more IMAP logins for the same
// answer.
const approvalPollInterval = 60 * time.Second

// checkMaxAge is the window `birdcage approval check` measures a
// message's Date against. Thirty days, far wider than the real flow
// will ever use, because this command exists for an operator holding a
// message their provider signed some time ago and asking "would this
// have been accepted?" -- refusing it for being a week old would answer
// a question they did not ask.
const checkMaxAge = 30 * 24 * time.Hour

// loadMailboxConfig reads issue #54's approval-mailbox configuration
// from the environment and logs what it found -- never the password,
// and never anything derived from it.
//
// It refuses to start rather than returning, for the reason
// loadMailConfig does: a half-configured mailbox that only discovers it
// has no password at the moment an approval arrives has failed at
// exactly the moment it was the point.
//
// With none of the variables set the mailbox is simply off, and nothing
// else about birdcage changes.
func loadMailboxConfig(log *slog.Logger) (cfg mailbox.Config, enabled bool) {
	loaded, err := mailbox.Load(os.Getenv)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	if !loaded.Enabled {
		log.Info(fmt.Sprintf("%s not set; the approval mailbox is disabled", mailbox.EnvHost))
		return mailbox.Config{}, false
	}

	for _, w := range loaded.Warnings {
		log.Warn(w)
	}

	// Everything on this line is the operator's own routing information
	// or a fixed word. The password is not logged, is not summarised,
	// and its length is not printed either -- a length is a fact about
	// a secret.
	passwordSource := mailbox.EnvPassword
	if os.Getenv(mailbox.EnvPasswordFile) != "" {
		passwordSource = mailbox.EnvPasswordFile
	}
	log.Info(fmt.Sprintf("%s=%s (implicit TLS, fully verified) %s=%s %s=%s, password from %s",
		mailbox.EnvHost, loaded.Config.Host,
		mailbox.EnvUsername, loaded.Config.Username,
		mailbox.EnvMailbox, loaded.Config.Mailbox,
		passwordSource))

	return loaded.Config, true
}

// approvalHandler returns the mailbox handler for one poll: verify the
// message and write down what came of it.
//
// Slice 1 stops there. Nothing is minted -- `upgrade` is still
// unmintable (store.CommandKind, pinned by
// TestUpgradeCommandCannotBeMinted) and no request has been sent for an
// approval to match, so there is nothing to apply even when a message
// verifies. The row and the log line are the whole output, and slice 2
// picks them up.
//
// A message that cannot be stored returns an error, which leaves it
// unread so the next poll owes it still. A message that simply fails
// verification is not an error: it is a recorded rejection, and the
// poll moves on.
func approvalHandler(database *db.DB, log *slog.Logger) mailbox.Handler {
	return func(ctx context.Context, raw []byte) error {
		now := time.Now().UTC()

		pinned, err := store.GetSetting(ctx, database, store.SettingAdminApprovalAddress)
		if err != nil {
			return fmt.Errorf("read %s: %w", store.SettingAdminApprovalAddress, err)
		}

		// The reference is whatever the subject carries: birdcage has
		// not sent a request yet, so there is no expected value to
		// compare against. It is still checked, because Verify requires
		// the subject to contain the token it was given -- reading the
		// reference out of the subject and handing it back means the
		// rule proves the subject is well formed rather than proving
		// nothing.
		reference := approval.SubjectReference(subjectOf(raw))

		record := store.Approval{
			FromAddress: fromOf(raw),
			Subject:     subjectOf(raw),
			Reference:   reference,
			ReceivedAt:  now,
			Raw:         raw,
		}

		verified, verifyErr := approval.Verify(ctx, raw, approval.Rules{
			PinnedFrom: pinned,
			Reference:  reference,
			Now:        now,
			MaxAge:     approvalMaxAge,
			Resolver:   net.LookupTXT,
			Seen: func(messageID string) bool {
				seen, err := store.ApprovalSeen(ctx, database, messageID)
				if err != nil {
					// Unknown is not the same as unseen. Saying "seen"
					// on a failed lookup rejects the message, which
					// costs the administrator a second reply; saying
					// "unseen" would accept a replay.
					log.Error(fmt.Sprintf("look up whether %s has been seen: %v", messageID, err))
					return true
				}
				return seen
			},
		})

		outcome := "verified"
		reason := ""
		if verifyErr != nil {
			outcome = "rejected"
			reason = verifyErr.Error()
			record.RejectReason = &reason
			if record.MessageID == "" {
				// A message that failed before its Message-ID was read
				// still needs one to be stored under, since that column
				// is what stops a replay. Falling back to the header as
				// it arrived keeps the row unique per message without
				// inventing anything.
				record.MessageID = messageIDOf(raw)
			}
		} else {
			at := now
			record.VerifiedAt = &at
			record.MessageID = verified.MessageID
			record.FromAddress = verified.From
			record.Subject = verified.Subject
		}
		if record.MessageID == "" {
			// Nothing to record it under and nothing to stop it being
			// replayed. Log it and let the poll mark it read: retrying
			// would produce the same result forever.
			log.Warn("an approval reply arrived with no Message-ID; there is no way to recognise a replay of it, so it is being ignored")
			return nil
		}
		if record.Reference == "" {
			record.Reference = "(none)"
		}

		err = store.RecordApproval(ctx, database, record)
		switch {
		case errors.Is(err, store.ErrApprovalAlreadyRecorded):
			// A replay, or the same message seen twice across a
			// restart. Already recorded, nothing more owed.
			log.Info(fmt.Sprintf("approval %s has already been recorded; ignoring the copy", term.Escape(record.MessageID)))
			return nil
		case err != nil:
			return fmt.Errorf("record approval: %w", err)
		}

		detail := ""
		if reason != "" {
			detail = " (" + reason + ")"
		}
		log.Info(fmt.Sprintf("approval received for %s from %s: %s%s -- nothing to apply yet (#54 slice 2)",
			term.Escape(record.Reference), term.Escape(record.FromAddress), outcome, term.Escape(detail)))
		return nil
	}
}

// approvalMaxAge is how far from now a live approval's Date may be. An
// hour: the administrator is replying to a mail birdcage has just sent,
// and a reply that took longer than an hour to arrive is one worth
// asking for again rather than acting on.
const approvalMaxAge = time.Hour

// runApprovalCheck implements `birdcage approval check <file>`: read a
// raw .eml and say, in plain words, what passed and the first thing
// that did not.
//
// This exists because a real provider's signature cannot be a committed
// fixture -- it would be the owner's own mail -- so the only honest way
// to find out whether a given mail provider's signing will satisfy the
// rules is to try one. It runs exactly the same approval.Verify the
// agents will, against the same pinned address, so a message that
// passes here passes there.
//
// Two things differ from a live poll, both deliberate and both stated
// in the output: the age limit is thirty days rather than an hour, and
// the replay check is skipped, since a message saved to a file is being
// re-read on purpose.
func runApprovalCheck(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: birdcage approval check <file.eml>")
	}
	path := args[0]

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", term.Escape(path), err)
	}
	if len(raw) > approval.MaxRawSize {
		return fmt.Errorf("%s is %d bytes; birdcage refuses anything over %d", term.Escape(path), len(raw), approval.MaxRawSize)
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	pinned, err := store.GetSetting(ctx, database, store.SettingAdminApprovalAddress)
	if err != nil {
		return fmt.Errorf("read %s: %w", store.SettingAdminApprovalAddress, err)
	}
	if pinned == "" {
		return fmt.Errorf("no administrator address is set. Run: birdcage settings set %s you@example.net", store.SettingAdminApprovalAddress)
	}

	reference := approval.SubjectReference(subjectOf(raw))
	if reference == "" {
		fmt.Printf("No: the subject carries no %s token, so there is nothing for an approval to be an approval of.\n",
			term.Escape(approval.Token("<reference>")))
		fmt.Printf("    The subject is: %s\n", term.Escape(subjectOf(raw)))
		return nil
	}

	fmt.Printf("Checking %s\n", term.Escape(path))
	fmt.Printf("  pinned administrator address: %s\n", term.Escape(pinned))
	fmt.Printf("  request reference in the subject: %s\n", term.Escape(reference))
	fmt.Printf("  age limit for this check: %s (a live approval gets %s)\n", checkMaxAge, approvalMaxAge)
	fmt.Println("  the replay check is skipped: you are re-reading a saved message on purpose")
	fmt.Println()

	result, err := approval.Verify(ctx, raw, approval.Rules{
		PinnedFrom: pinned,
		Reference:  reference,
		Now:        time.Now().UTC(),
		MaxAge:     checkMaxAge,
		// Real DNS, deliberately: the whole point of this command is to
		// try a real provider's signature against the key it actually
		// published.
		Resolver: net.LookupTXT,
		Seen:     func(string) bool { return false },
	})
	if err != nil {
		fmt.Println("No. The first thing that failed:")
		fmt.Printf("  %s\n", term.Escape(err.Error()))
		return nil
	}

	fmt.Println("Yes. This message would be accepted as an approval.")
	fmt.Printf("  from:       %s\n", term.Escape(result.From))
	fmt.Printf("  subject:    %s\n", term.Escape(result.Subject))
	fmt.Printf("  dated:      %s\n", result.Date.UTC().Format(time.RFC3339))
	fmt.Printf("  signed by:  %s, selector %s\n", term.Escape(result.Domain), term.Escape(result.Selector))
	fmt.Printf("  message id: %s\n", term.Escape(result.MessageID))
	return nil
}

// subjectOf, fromOf and messageIDOf pull one header out of a raw
// message for the record kept about a message that never got as far as
// being parsed properly. They are deliberately crude -- first match,
// unfolded only as far as the first line -- because they are used on
// input that has already failed: a message this cannot read a subject
// out of is stored with an empty one rather than refused.
func subjectOf(raw []byte) string { return firstHeader(raw, "subject") }
func fromOf(raw []byte) string    { return firstHeader(raw, "from") }

func messageIDOf(raw []byte) string { return firstHeader(raw, "message-id") }

func firstHeader(raw []byte, name string) string {
	lines := splitHeaderLines(raw)
	prefix := name + ":"
	for _, line := range lines {
		if len(line) < len(prefix) {
			continue
		}
		if !equalFoldASCII(line[:len(prefix)], prefix) {
			continue
		}
		return trimSpaceASCII(line[len(prefix):])
	}
	return ""
}

// splitHeaderLines returns the message's header lines, with continuation
// lines folded onto the line they continue. It stops at the blank line
// that ends the header, so nothing in the body is ever read as a header.
func splitHeaderLines(raw []byte) []string {
	var lines []string
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i != len(raw) && raw[i] != '\n' {
			continue
		}
		line := string(raw[start:i])
		start = i + 1
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		if line == "" {
			break // end of the header
		}
		if (line[0] == ' ' || line[0] == '\t') && len(lines) > 0 {
			lines[len(lines)-1] += " " + trimSpaceASCII(line)
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func trimSpaceASCII(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}
