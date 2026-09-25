package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/hostmask"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/term"
)

// openCanaryDB opens and migrates the database these `birdcage canary`
// subcommands operate on, following the same DATABASE_URL/BIRDCAGE_DB_PATH
// precedence as the main server (main.go) so the CLI always points at the
// same database a running birdcage instance would.
func openCanaryDB() (*db.DB, error) {
	databaseURL := os.Getenv(envDatabaseURL)
	if databaseURL == "" {
		databaseURL = os.Getenv(envDBPath)
	}
	if databaseURL == "" {
		databaseURL = defaultDBPath
	}
	database, err := db.Open(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := db.Migrate(context.Background(), database); err != nil {
		if cerr := database.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "close database: %v\n", cerr)
		}
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return database, nil
}

func closeCanaryDB(database *db.DB) {
	if err := database.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close database: %v\n", err)
	}
}

// rollbackCanaryTx rolls back tx unless committed is true, logging
// anything other than the expected "already closed" error -- the same
// shape internal/ingest/rotate.go's handleRotate uses for its
// mint-plus-audit transaction.
func rollbackCanaryTx(tx *db.Tx, committed *bool) {
	if *committed {
		return
	}
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		fmt.Fprintf(os.Stderr, "rollback transaction: %v\n", err)
	}
}

// runCanaryAdd implements `birdcage canary add <id> <name> <lane> <ports> [interval_s]`,
// a dev/testing convenience for registering a canary before #1's
// enrollment UI exists (see issue #34's "Not in this slice"). ports is
// the raw comma-separated port list store.Canary.Ports expects before
// display formatting, e.g. "22,80,445".
func runCanaryAdd(args []string) error {
	if len(args) < 4 || len(args) > 5 {
		return fmt.Errorf("usage: birdcage agent add <id> <name> <lane> <ports> [interval_s]")
	}
	interval := store.DefaultHeartbeatIntervalS
	if len(args) == 5 {
		n, err := strconv.Atoi(args[4])
		if err != nil || n <= 0 {
			return fmt.Errorf("interval_s must be a positive integer")
		}
		interval = n
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	// Kind is always agentkind.Honeypot here: `canary add` is a
	// dev/testing convenience that predates kinds entirely (issue #34's
	// "Not in this slice"), with no --kind flag of its own, and every
	// node it has ever registered has been a honeypot.
	c := store.Canary{
		ID: args[0], Name: args[1], Lane: args[2], Kind: agentkind.Honeypot, Ports: args[3],
		HeartbeatIntervalS: interval, EnrolledAt: time.Now().UTC(),
	}
	if err := store.InsertCanary(ctx, database, c); err != nil {
		return fmt.Errorf("insert canary: %w", err)
	}
	// c.ID is whatever the caller typed on the command line, stored
	// verbatim by InsertCanary above -- SECURITY.md's rule is that it
	// stays that way in the row, so it is escaped only here, at the
	// point it reaches this terminal.
	fmt.Printf("canary %s enrolled\n", term.Escape(c.ID))
	return nil
}

// runCanaryMint implements `birdcage canary mint <canary_id>` (issue #32
// item 9). It mints a fresh bearer token for canary_id and records the
// mint in the audit log in one transaction -- item 10's "a mint ... whose
// audit write fails, fails with it", built the same way
// internal/ingest/rotate.go's handleRotate does its mint-plus-audit: if
// the audit append fails the whole transaction rolls back, so the newly
// minted token was never actually persisted.
//
// The raw token is printed here, once -- store.MintCanaryToken never
// returns it again, and no other command in this file (list, in
// particular) ever sees it.
func runCanaryMint(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: birdcage agent mint <agent_id>")
	}
	canaryID := args[0]

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	tx, err := database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer rollbackCanaryTx(tx, &committed)

	now := time.Now().UTC()
	raw, tok, err := store.MintCanaryToken(ctx, tx, canaryID, now)
	if err != nil {
		return fmt.Errorf("mint agent token: %w", err)
	}

	if _, err := audit.Append(ctx, tx, audit.Entry{
		Action:      "canary.token_minted",
		Target:      canaryID,
		Reason:      "minted via CLI",
		TriggeredBy: "cli",
		CreatedAt:   now,
	}); err != nil {
		return fmt.Errorf("record mint audit entry: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true

	// tok.ID and raw are both generated by store.MintCanaryToken itself
	// (random hex), never attacker-influenced, but canaryID is whatever
	// the caller passed and is echoed back verbatim below -- escape it
	// at this print, not before it went into the audit entry above.
	fmt.Printf("minted token %s for agent %s\n", tok.ID, term.Escape(canaryID))
	fmt.Printf("token (shown once, record it now): %s\n", raw)
	return nil
}

// runCanaryList implements `birdcage canary list` (issue #32 item 9:
// "list ... never printing a token"). It prints only what
// store.ListCanaryTokens returns, and that type carries neither the raw
// token nor its hash, so there is no value here that could be printed by
// mistake.
func runCanaryList(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: birdcage agent list")
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	tokens, err := store.ListCanaryTokens(context.Background(), database)
	if err != nil {
		return fmt.Errorf("list agent tokens: %w", err)
	}
	if len(tokens) == 0 {
		fmt.Println("no agent tokens")
		return nil
	}
	for _, tok := range tokens {
		status := "active"
		if tok.RevokedAt != nil {
			status = "revoked " + tok.RevokedAt.Format(time.RFC3339)
		}
		lastUsed := "never"
		if tok.LastUsedAt != nil {
			lastUsed = tok.LastUsedAt.Format(time.RFC3339)
		}
		// tok.ID and tok.CanaryID are read back from the database exactly
		// as stored (SECURITY.md: never altered at rest); escape both
		// here, at the point they reach this terminal, not before.
		fmt.Printf("%s\tcanary=%s\tminted=%s\tlast_used=%s\t%s\n",
			term.Escape(tok.ID), term.Escape(tok.CanaryID), tok.CreatedAt.Format(time.RFC3339), lastUsed, status)
	}
	return nil
}

// runCanaryRevoke implements `birdcage canary revoke <canary_id>`
// (ADR-0012 Part B5: "one operator action ends both holders"). It
// revokes every live token and every live certificate for canary_id in
// one transaction, via store.RevokeCanaryCredentials, with the audit
// entry (`canary.revoked`) written on the same tx -- the same mint/
// revoke-plus-audit shape runCanaryMint above and
// internal/ingest/rotate.go both use, so a failed audit write rolls the
// revocation back with it rather than leaving it silently unrecorded.
// From the moment this commits, the next request from either holder --
// the honest node or a copy of its credentials -- is 401: the ingest
// auth path looks up both the token and the certificate fresh on every
// request, which excludes a revoked row at the SQL level, so there is
// no cache in between that could serve one more authenticated request
// off a stale answer.
//
// Before #130 this command took a token id; it now takes the canary id
// the ADR specifies, since a copied credential's token and certificate
// must die together, not one at a time.
func runCanaryRevoke(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: birdcage agent revoke <agent_id>")
	}
	canaryID := args[0]

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	tx, err := database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer rollbackCanaryTx(tx, &committed)

	now := time.Now().UTC()
	revoked, err := store.RevokeCanaryCredentials(ctx, tx, canaryID, now)
	if err != nil {
		return fmt.Errorf("revoke agent credentials: %w", err)
	}

	if _, err := audit.Append(ctx, tx, audit.Entry{
		Action:      "canary.revoked",
		Target:      canaryID,
		Reason:      "revoked via CLI",
		TriggeredBy: "cli",
		CreatedAt:   now,
	}); err != nil {
		return fmt.Errorf("record revoke audit entry: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true

	// canaryID is the caller-supplied argument, echoed back verbatim;
	// escaped here, at the point it reaches this terminal, not before.
	fmt.Printf("revoked agent %s: %d token(s), %d certificate(s)\n",
		term.Escape(canaryID), revoked.Tokens, revoked.Certificates)
	return nil
}

// kindNames renders agentkind.Kinds() as strings, for `--kind`'s
// unknown-value error message (issue #105: "validated with an error
// listing valid kinds").
func kindNames() []string {
	kinds := agentkind.Kinds()
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = string(k)
	}
	return names
}

// runCanaryEnrol implements `birdcage canary enrol --name <name> --lane
// <lane> [--kind <kind>]` (issue #47 slice 1b, "The flow" steps 1-2;
// --name/--lane added slice 3; --kind added issue #105) and, via
// --status, a read-only listing of every enrolment_sessions row (issue
// #47 slice 1b item 6).
//
// --name and --lane are required: they name the canary before it exists,
// carried on the session until a later Provision call (store.Provision)
// uses them to build its canaries row. --kind defaults to
// agentkind.Honeypot, so every runbook written before #105 keeps working
// unchanged; an unregistered kind is refused here, before any database
// write, with an error naming the valid set.
//
// It refuses to mint a session until #54's two addresses are set (issue
// #47 slice 1b item 3: "enrolment refuses to mint until both are set"),
// and until BIRDCAGE_ADVERTISE_HOST is set -- without it there is no
// address to put in the docker run command this prints, and the
// certificate the canary is about to verify against wouldn't cover it
// either (see main.go's own envAdvertiseHost doc comment).
func runCanaryEnrol(args []string) error {
	if len(args) == 1 && args[0] == "--status" {
		return runCanaryEnrolStatus()
	}

	const usage = "usage: birdcage agent enrol --name <name> --lane <lane> " +
		"[--kind <kind>] [--lure smb=off] [--smb-workgroup <name>] [--smb-shares <a,b,c>] " +
		"[--bait-names <a,b>] [--segment-profile <windows|linux|off>] (or --status)"
	fs := flag.NewFlagSet("agent enrol", flag.ContinueOnError)
	name := fs.String("name", "", "agent name (required)")
	lane := fs.String("lane", "", "agent lane (required)")
	kindFlag := fs.String("kind", string(agentkind.Honeypot), "agent kind (issue #105)")
	// The lure flags (issue #87 slice C). They change what this command
	// prints -- see canary_lure.go, lureState, for what that does and does
	// not deliver.
	lures := lureState{smb: true}
	lureArg := &lureFlag{state: &lures}
	fs.Var(lureArg, "lure", "turn a lure off, as name=state (the only lure is smb)")
	smbWorkgroup := fs.String("smb-workgroup", defaultSMBWorkgroup, "workgroup the SMB lure announces")
	smbShares := fs.String("smb-shares", defaultSMBShares, "the SMB lure's three share names, comma-separated")
	baitNames := fs.String("bait-names", "", "two or three names in your own naming style for the poisoner detector to ask for (issue #86)")
	segmentProfile := fs.String("segment-profile", "", "which protocols the poisoner detector uses: windows (default), linux or off (issue #86)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(usage)
	}
	if *name == "" || *lane == "" {
		return fmt.Errorf("%s: --name and --lane are required", usage)
	}
	kind := agentkind.Kind(*kindFlag)
	profile, ok := agentkind.Lookup(kind)
	if !ok {
		return fmt.Errorf("%s: unknown --kind %q (valid kinds: %s)", usage, *kindFlag, strings.Join(kindNames(), ", "))
	}
	// Only the honeypot has lures. Refusing rather than ignoring: an
	// operator who asked a scanner for an SMB share has misunderstood
	// something, and silence would leave them believing it worked.
	smbFlagsSet := lureArg.set || *smbWorkgroup != defaultSMBWorkgroup || *smbShares != defaultSMBShares
	if kind != agentkind.Honeypot && smbFlagsSet {
		return fmt.Errorf("%s: --lure and the --smb-* flags apply to --kind %s only, not %q",
			usage, agentkind.Honeypot, kind)
	}
	smb, err := parseSMBSettings(*smbWorkgroup, *smbShares)
	if err != nil {
		return err
	}

	// #86's two optional settings, validated here, before anything is
	// minted. The order matters for the same reason #108's own comment
	// below gives: a check that ran after the session was created would
	// burn a live token on a typo. Both are validated with the agent's own
	// parsers, so what this command accepts and what the agent accepts can
	// never drift -- the call internal/hostmask already makes for the
	// scanner's mounts.
	bait, err := poisonerBaitNames(*baitNames)
	if err != nil {
		return fmt.Errorf("%s: %w", usage, err)
	}
	segment, err := poisoner.ParseProfile(*segmentProfile)
	if err != nil {
		return fmt.Errorf("%s: %w", usage, err)
	}
	if *segmentProfile == "" {
		// Nothing to put in the run command: the agent's own default is
		// the same value, and an explicit flag for a default is noise in
		// the one instruction the product asks an operator to paste.
		segment = ""
	}

	advertiseHost := os.Getenv(envAdvertiseHost)
	if advertiseHost == "" {
		return fmt.Errorf("%s must be set to the address canaries reach this birdcage instance on", envAdvertiseHost)
	}

	caDir := os.Getenv(envCADir)
	if caDir == "" {
		caDir = defaultCADir
	}
	birdcageCA, _, err := ca.Load(caDir, nil)
	if err != nil {
		return fmt.Errorf("load CA (%s=%q): %w", envCADir, caDir, err)
	}

	enrolAddr := os.Getenv(envEnrolAddr)
	if enrolAddr == "" {
		enrolAddr = defaultEnrolAddr
	}
	_, enrolPort, err := net.SplitHostPort(enrolAddr)
	if err != nil {
		return fmt.Errorf("%s=%q is not a valid address: %w", envEnrolAddr, enrolAddr, err)
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	if err := requireEnrolAddresses(ctx, database); err != nil {
		return err
	}

	tx, err := database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer rollbackCanaryTx(tx, &committed)

	now := time.Now().UTC()
	raw, session, err := store.MintEnrolmentSession(ctx, tx, *name, *lane, kind, now)
	if err != nil {
		return fmt.Errorf("mint enrolment session: %w", err)
	}

	if _, err := audit.Append(ctx, tx, audit.Entry{
		Action:      "enrolment.session_minted",
		Target:      session.ID,
		Reason:      "minted via CLI",
		TriggeredBy: "cli",
		CreatedAt:   now,
	}); err != nil {
		return fmt.Errorf("record mint audit entry: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true

	// advertiseHost and image are operator-supplied (an environment
	// variable each), escaped here at the point they reach this
	// terminal, matching this file's rule for every other caller-
	// supplied value. birdcageCA.Pin() and raw are both generated by
	// this process itself (a hash digest and random hex respectively),
	// never attacker- or even operator-influenced, so neither is
	// escaped -- the same distinction runCanaryMint draws between
	// canaryID and tok.ID/raw.
	//
	// The switch is per kind, not just per image, because a future
	// kind's install instructions may not be a `docker run` line at all
	// (#105 delivery plan section 4: printEnrolRunCommand "stays
	// honeypot-shaped; a future kind brings its own run-command
	// renderer").
	switch kind {
	case agentkind.Honeypot:
		image := os.Getenv(profile.ImageEnv)
		if image == "" {
			image = profile.DefaultImage
		}
		if err := printEnrolRunCommand(os.Stdout, advertiseHost, enrolPort, birdcageCA.Pin(), raw, image, lures.smb, bait, string(segment)); err != nil {
			return fmt.Errorf("print docker run command: %w", err)
		}
		// The lure is a second container, so it is a second command --
		// printed after the canary's, because it joins that container's
		// network namespace and cannot start before it exists. The volume
		// comes first inside that block, for the reason smbAuditVolume's
		// own comment gives.
		if lures.smb {
			if _, err := fmt.Println(); err != nil {
				return fmt.Errorf("print smb lure run command: %w", err)
			}
			if err := printSMBLureRunCommand(os.Stdout, smbLureImage(), smb); err != nil {
				return fmt.Errorf("print smb lure run command: %w", err)
			}
		} else {
			// One line, so the ledger's "untested" smb card later is not
			// a surprise. Issue #87 decision 10.
			if _, err := fmt.Println("\nsmb lure off by request: this canary serves no SMB share, and smb stays untested on its ledger"); err != nil {
				return fmt.Errorf("print smb lure note: %w", err)
			}
		}
	case agentkind.Scanner:
		// #108's own trap: this case has to land in the same commit as
		// the profile, or --kind scanner mints a session here and then
		// falls into default below, failing half-way through its own
		// output with a live token already burned.
		image := os.Getenv(profile.ImageEnv)
		if image == "" {
			image = profile.DefaultImage
		}
		if err := printScannerEnrolRunCommand(os.Stdout, advertiseHost, enrolPort, birdcageCA.Pin(), raw, image); err != nil {
			return fmt.Errorf("print docker run command: %w", err)
		}
	default:
		return fmt.Errorf("no install instructions registered for kind %q", kind)
	}
	fmt.Printf("token valid for 5 minutes (until %s); single use\n", session.FirstContactDeadline.Format(time.RFC3339))

	return nil
}

// printEnrolRunCommand writes the `docker run` line an operator pastes
// onto the box they are turning into a canary. Split out of
// runCanaryEnrol so a test can assert on the exact flags without also
// needing a database, a CA and a minted session -- this command is the
// product's one install instruction, and a flag silently dropped from it
// is a canary that comes up missing something.
//
// advertiseHost and image are operator-supplied (an environment variable
// each) and are escaped here, at the point they reach the terminal,
// matching this file's rule for every other caller-supplied value. pin
// and token are generated by this process itself -- a hash digest and
// random hex -- never attacker- or even operator-influenced, so neither
// is escaped, the same distinction runCanaryMint draws between canaryID
// and tok.ID/raw.
// baitNames and segmentProfile are #86's two optional per-canary
// settings. Both are empty unless the operator asked for them, and an
// empty one prints no line at all rather than an explicit default: the
// agent's own default is the same value, and the run command is the
// product's one install instruction, not a place to restate defaults.
//
// baitNames has already been through the agent's own parser (see
// poisonerBaitNames), so by the time it reaches here it holds only
// lower-case letters, digits, hyphens and the commas between them.
// term.Escape is applied anyway, because this file's rule is that every
// operator-supplied value is escaped at the point it reaches the
// terminal, and a rule with an exception is a rule somebody forgets.
func printEnrolRunCommand(w io.Writer, advertiseHost, enrolPort, pin, token, image string, smbLure bool, baitNames, segmentProfile string) error {
	if _, err := fmt.Fprintf(w, "docker run -d --name mockingbird --restart unless-stopped --init \\\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  --sysctl net.ipv4.ip_unprivileged_port_start=0 \\\n"); err != nil {
		return err
	}
	// --cap-add NET_RAW (#65): the agent watches for port scans with one
	// raw socket in the container's own network namespace, because
	// OpenCanary's own portscan module needs iptables-legacy and root,
	// which this image does not have. NET_RAW is the only capability the
	// container gets, and the binary carries cap_net_raw as a file
	// capability so the process stays uid 65532. Leave it off and the
	// canary still reports every hit on an emulated service -- it just
	// cannot see somebody sweeping the ports nothing answers on, and
	// says so in one line at startup.
	if _, err := fmt.Fprintf(w, "  --cap-add NET_RAW \\\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  -v mockingbird-state:/var/lib/mockingbird -v mockingbird-log:/var/log/opencanary \\\n"); err != nil {
		return err
	}
	// The SMB lure's audit volume (#87), mounted READ-ONLY and only when
	// the lure is being deployed. Read-only is the whole of decision 6:
	// the volume is the only thing the two containers share, the lure
	// writes and this container reads, so a compromised smbd can forge
	// SMB alerts on its own canary and nothing else. Without
	// MOCKINGBIRD_SMB_AUDIT_PATH the agent's smb road does not run at
	// all, which is what `--lure smb=off` leaves behind.
	if smbLure {
		if _, err := fmt.Fprintf(w, "  -v %s:/audit:ro \\\n", smbAuditVolume); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  -e MOCKINGBIRD_SMB_AUDIT_PATH=%s \\\n", smbAuditPath); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "  -e MOCKINGBIRD_BIRDCAGE_URL=https://%s:%s \\\n", term.Escape(advertiseHost), enrolPort); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  -e MOCKINGBIRD_CA_PIN=%s \\\n", pin); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  -e MOCKINGBIRD_DEPLOY_TOKEN=%s \\\n", token); err != nil {
		return err
	}
	if baitNames != "" {
		if _, err := fmt.Fprintf(w, "  -e MOCKINGBIRD_POISONER_NAMES=%s \\\n", term.Escape(baitNames)); err != nil {
			return err
		}
	}
	if segmentProfile != "" {
		if _, err := fmt.Fprintf(w, "  -e MOCKINGBIRD_POISONER_PROFILE=%s \\\n", term.Escape(segmentProfile)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "  %s\n", term.Escape(image))
	return err
}

// poisonerBaitNames validates the --bait-names list and returns it in the
// form the run command carries: the agent's own normalisation, re-joined
// with commas.
//
// Every entry has to be usable. A partly-good list is refused rather than
// silently trimmed, because this is the operator typing their own network
// in, once, at the moment they are watching the output -- unlike the
// agent's own read of the environment variable later, where refusing the
// lot would leave a running canary with no bait at all.
//
// The error names the rule and how many entries broke it. It does not
// quote the offending name back, because this output can end up in a
// terminal recording, a runbook or a ticket, and the whole point of
// deriving bait names from the operator's own network is that there is
// nothing for an attacker to look up.
func poisonerBaitNames(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	names, refused, err := poisoner.ParseNames(raw)
	if err != nil {
		return "", err
	}
	if refused > 0 {
		return "", fmt.Errorf("%d of the --bait-names entries could not be used: a bait name is 1 to 15 characters of letters, digits and hyphens, not starting or ending with a hyphen, and at most %d are used", refused, poisoner.MaxOperatorNames)
	}
	return strings.Join(names, ","), nil
}

// printScannerEnrolRunCommand writes the `docker run` line for the
// scanner kind (issue #108 slice 1) -- ADR-0010 decision 3's shape (own
// image, no listener) plus the owner-ratified host-mount covering
// (issue #108, "the host mount is whole-root read-only, with the
// secret-bearing paths covered over"): a read-only whole-root bind, one
// flag per hostmask.Masks entry so the printed command and Nightjar's
// own startup check (internal/hostmask.Check, cmd/nightjar/scanner.go)
// can never drift, and no sysctl, no added capability and no published
// port -- Nightjar listens on nothing.
//
// One operational trap this command can hit, named in
// docs/enrolment.md: a --tmpfs or -v /dev/null flag over a path the
// target host does not have fails the container at start with a
// read-only-filesystem error, because Docker cannot create a mountpoint
// under a read-only bind for a path that was never there. The remedy is
// to drop that one flag from the pasted command -- e.g. a host with no
// /etc/ssh -- not to abandon the covering; internal/hostmask.Check
// treats an absent mask path as nothing to cover, matching this.
func printScannerEnrolRunCommand(w io.Writer, advertiseHost, enrolPort, pin, token, image string) error {
	if _, err := fmt.Fprintf(w, "docker run -d --name nightjar --restart unless-stopped \\\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  --read-only --cap-drop ALL --security-opt no-new-privileges \\\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  -v /:/host:ro \\\n"); err != nil {
		return err
	}
	for _, flag := range hostmask.RunFlags("/host") {
		if _, err := fmt.Fprintf(w, "  %s \\\n", flag); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "  -v nightjar-state:/var/lib/nightjar -v nightjar-grype-db:/var/lib/nightjar-grype-db \\\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  -e NIGHTJAR_BIRDCAGE_URL=https://%s:%s \\\n", term.Escape(advertiseHost), enrolPort); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  -e NIGHTJAR_CA_PIN=%s \\\n", pin); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  -e NIGHTJAR_DEPLOY_TOKEN=%s \\\n", token); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "  %s\n", term.Escape(image))
	return err
}

// requireEnrolAddresses reads #54's two settings and fails with a clear,
// actionable error (naming the `birdcage settings set` command) if
// either is still at its empty default -- issue #47 slice 1b item 3:
// "enrolment refuses to mint until both are set." Their values aren't
// needed here -- POST /enrol/hello reads them itself at first contact
// (internal/enrol) -- only that both are set is.
func requireEnrolAddresses(ctx context.Context, database *db.DB) error {
	adminApprovalAddress, err := store.GetSetting(ctx, database, store.SettingAdminApprovalAddress)
	if err != nil {
		return fmt.Errorf("get setting %s: %w", store.SettingAdminApprovalAddress, err)
	}
	releaseAddress, err := store.GetSetting(ctx, database, store.SettingReleaseAddress)
	if err != nil {
		return fmt.Errorf("get setting %s: %w", store.SettingReleaseAddress, err)
	}
	if adminApprovalAddress == "" || releaseAddress == "" {
		return fmt.Errorf(
			"enrolment refuses to mint until both %s and %s are set: run `birdcage settings set %s <value>` and `birdcage settings set %s <value>` first",
			store.SettingAdminApprovalAddress, store.SettingReleaseAddress,
			store.SettingAdminApprovalAddress, store.SettingReleaseAddress)
	}
	return nil
}

// runCanaryEnrolStatus implements `birdcage canary enrol --status`:
// every enrolment_sessions row, id/state/timestamps only -- never a hash,
// since EnrolmentSession itself carries neither token_hash nor
// enrolment_secret_hash (store.ListEnrolmentSessions' own doc comment).
func runCanaryEnrolStatus() error {
	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	sessions, err := store.ListEnrolmentSessions(context.Background(), database)
	if err != nil {
		return fmt.Errorf("list enrolment sessions: %w", err)
	}
	if len(sessions) == 0 {
		fmt.Println("no enrolment sessions")
		return nil
	}
	for _, s := range sessions {
		contacted := "not contacted"
		if s.BurnedAt != nil {
			contacted = s.BurnedAt.Format(time.RFC3339)
		}
		window := "n/a"
		if s.WindowDeadline != nil {
			window = s.WindowDeadline.Format(time.RFC3339)
		}
		canaryID := "n/a"
		if s.CanaryID != nil {
			// *s.CanaryID is read back from the database exactly as
			// stored (SECURITY.md: never altered at rest); escaped
			// here, at the point it reaches this terminal.
			canaryID = term.Escape(*s.CanaryID)
		}
		// s.ID and s.State are, respectively, generated by this
		// package's own random hex and a closed Go enum this binary
		// itself writes -- neither needs escaping, the same distinction
		// the mint/list/revoke commands above draw. s.Name and s.Lane
		// are operator-supplied (`--name`/`--lane`), escaped here at the
		// point they reach this terminal. s.Kind is escaped too, even
		// though this binary only ever mints a registered one: a row
		// this instance reads back may have been written by a newer
		// binary carrying a kind this one doesn't register (issue #105
		// delivery plan section 1, "opaque on read"), so it is treated
		// like caller-supplied text, not like s.State.
		fmt.Printf("%s\tname=%s\tlane=%s\tkind=%s\tstate=%s\tcreated=%s\tfirst_contact_deadline=%s\tcontacted=%s\twindow_deadline=%s\tcanary=%s\n",
			s.ID, term.Escape(s.Name), term.Escape(s.Lane), term.Escape(string(s.Kind)), s.State, s.CreatedAt.Format(time.RFC3339), s.FirstContactDeadline.Format(time.RFC3339), contacted, window, canaryID)
	}
	return nil
}
