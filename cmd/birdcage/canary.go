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
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/term"
)

const (
	// envMockingbirdImage overrides the image `birdcage canary enrol`
	// prints in its docker run command.
	//
	// TODO(#69 registry): birdcage doesn't publish this image anywhere
	// yet, so defaultMockingbirdImage names a tag an operator has to
	// build and load by hand until #69 lands a real registry to pull it
	// from.
	envMockingbirdImage     = "MOCKINGBIRD_IMAGE"
	defaultMockingbirdImage = "mockingbird:latest"
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
		return fmt.Errorf("usage: birdcage canary add <id> <name> <lane> <ports> [interval_s]")
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
		return fmt.Errorf("usage: birdcage canary mint <canary_id>")
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
		return fmt.Errorf("mint canary token: %w", err)
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
	fmt.Printf("minted token %s for canary %s\n", tok.ID, term.Escape(canaryID))
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
		return fmt.Errorf("usage: birdcage canary list")
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	tokens, err := store.ListCanaryTokens(context.Background(), database)
	if err != nil {
		return fmt.Errorf("list canary tokens: %w", err)
	}
	if len(tokens) == 0 {
		fmt.Println("no canary tokens")
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

// runCanaryRevoke implements `birdcage canary revoke <token_id>` (issue
// #32 item 9). Revocation and its audit entry (item 10) run in one
// transaction, the same mint-plus-audit shape runCanaryMint above and
// internal/ingest/rotate.go both use. The next request authenticating
// with this token is refused immediately: the ingest auth path
// (internal/ingest/auth.go) looks it up fresh on every request via
// store.LookupCanaryTokenByHash, which excludes a revoked row at the SQL
// level, so there is no cache anywhere in between that could serve one
// more authenticated request off a stale answer.
func runCanaryRevoke(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: birdcage canary revoke <token_id>")
	}
	tokenID := args[0]

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

	tok, err := store.LookupCanaryTokenByID(ctx, tx, tokenID)
	if err != nil {
		return fmt.Errorf("look up token %s: %w", tokenID, err)
	}

	now := time.Now().UTC()
	if err := store.RevokeCanaryToken(ctx, tx, tokenID, now); err != nil {
		return fmt.Errorf("revoke canary token: %w", err)
	}

	if _, err := audit.Append(ctx, tx, audit.Entry{
		Action:      "canary.token_revoked",
		Target:      tok.CanaryID,
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

	// tokenID is the caller-supplied argument; tok.CanaryID came back
	// from the lookup above exactly as stored. Both are escaped here, at
	// the point they reach this terminal, not before.
	fmt.Printf("revoked token %s for canary %s\n", term.Escape(tokenID), term.Escape(tok.CanaryID))
	return nil
}

// runCanaryEnrol implements `birdcage canary enrol --name <name> --lane
// <lane>` (issue #47 slice 1b, "The flow" steps 1-2; --name/--lane added
// slice 3) and, via --status, a read-only listing of every
// enrolment_sessions row (issue #47 slice 1b item 6).
//
// --name and --lane are required: they name the canary before it exists,
// carried on the session until a later Provision call (store.Provision)
// uses them to build its canaries row.
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

	const usage = "usage: birdcage canary enrol --name <name> --lane <lane> (or --status)"
	fs := flag.NewFlagSet("canary enrol", flag.ContinueOnError)
	name := fs.String("name", "", "canary name (required)")
	lane := fs.String("lane", "", "canary lane (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New(usage)
	}
	if *name == "" || *lane == "" {
		return fmt.Errorf("%s: both flags are required", usage)
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

	image := os.Getenv(envMockingbirdImage)
	if image == "" {
		image = defaultMockingbirdImage
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
	// agentkind.Honeypot is hardcoded here for now; the #105 delivery
	// plan's commit 3 adds a --kind flag and passes it through instead.
	raw, session, err := store.MintEnrolmentSession(ctx, tx, *name, *lane, agentkind.Honeypot, now)
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
	if err := printEnrolRunCommand(os.Stdout, advertiseHost, enrolPort, birdcageCA.Pin(), raw, image); err != nil {
		return fmt.Errorf("print docker run command: %w", err)
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
func printEnrolRunCommand(w io.Writer, advertiseHost, enrolPort, pin, token, image string) error {
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
	if _, err := fmt.Fprintf(w, "  -e MOCKINGBIRD_BIRDCAGE_URL=https://%s:%s \\\n", term.Escape(advertiseHost), enrolPort); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  -e MOCKINGBIRD_CA_PIN=%s \\\n", pin); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  -e MOCKINGBIRD_DEPLOY_TOKEN=%s \\\n", token); err != nil {
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
		// package's own random hex and a closed Go enum -- neither
		// needs escaping, the same distinction the mint/list/revoke
		// commands above draw. s.Name and s.Lane are operator-supplied
		// (`--name`/`--lane`), escaped here at the point they reach this
		// terminal.
		fmt.Printf("%s\tname=%s\tlane=%s\tstate=%s\tcreated=%s\tfirst_contact_deadline=%s\tcontacted=%s\twindow_deadline=%s\tcanary=%s\n",
			s.ID, term.Escape(s.Name), term.Escape(s.Lane), s.State, s.CreatedAt.Format(time.RFC3339), s.FirstContactDeadline.Format(time.RFC3339), contacted, window, canaryID)
	}
	return nil
}
