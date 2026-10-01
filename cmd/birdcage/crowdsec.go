package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/tomlawesome/birdcage/internal/crowdsec"
	"github.com/tomlawesome/birdcage/internal/neverblock"
	"github.com/tomlawesome/birdcage/internal/term"
)

// crowdsecTriggeredBy is the audit_log triggered_by every row written
// through this command carries. #6's engine, when it exists, names
// itself differently, so the two are told apart in the record.
const crowdsecTriggeredBy = "cli"

// loadCrowdsecConfig is the startup half of ADR-0014: the connection
// is validated when birdcage starts, so a half-set configuration or an
// unreadable password file refuses here, with the variable named,
// rather than at the moment an operator is trying to block an
// attacker. Nothing is contacted at startup -- a LAPI that is down
// must not stop birdcage serving its dashboard -- and nothing in the
// server uses the connection yet: there is no automatic trigger (#6).
func loadCrowdsecConfig(log *slog.Logger) (crowdsec.Config, bool) {
	loaded, err := crowdsec.Load(os.Getenv)
	if err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
	if !loaded.Enabled {
		log.Info(fmt.Sprintf("%s not set; CrowdSec blocking is off", crowdsec.EnvLAPIURL))
		return crowdsec.Config{}, false
	}
	// Routing information and fixed words only. The password is not
	// logged, not summarised, and its length is not printed either.
	roots := "system roots"
	if loaded.Config.CAFile != "" {
		roots = crowdsec.EnvCAFile + "=" + loaded.Config.CAFile
	}
	log.Info(fmt.Sprintf("%s=%s (TLS fully verified against %s) %s=%s, password from %s; `birdcage crowdsec add` is the only caller, no automatic trigger",
		crowdsec.EnvLAPIURL, loaded.Config.LAPIURL, roots,
		crowdsec.EnvMachineID, loaded.Config.MachineID,
		crowdsec.EnvPasswordFile))
	return loaded.Config, true
}

// runCrowdsec dispatches `birdcage crowdsec <add> ...` (ADR-0014,
// decision 2): the one operator door onto a CrowdSec ban. There is no
// dashboard write path (the API stays read-only until login exists,
// #8), and there is deliberately no `remove`: add-only is a property of
// this binary, not a setting (ADR-0014, decision 3).
func runCrowdsec(args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: birdcage crowdsec add <ip> --reason \"<why>\"")
	}
	switch args[0] {
	case "add":
		return runCrowdsecAdd(args[1:], getenv, stdout, stderr)
	default:
		return fmt.Errorf("unknown crowdsec subcommand %q (want add; there is no remove -- a ban is removed with cscli on the CrowdSec host)", args[0])
	}
}

// runCrowdsecAdd implements `birdcage crowdsec add <ip> --reason "<why>"`:
// load and validate the connection (all-or-nothing, exactly as startup
// does), load the never-block floor from the same environment, open
// the database for the audit row, and run Blocker.Block. The printed
// line is the outcome; everything that went wrong is the returned
// error, already free of the password and the token.
func runCrowdsecAdd(args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("crowdsec add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reason := fs.String("reason", "", "why this address is being banned (required; one line, recorded in CrowdSec and in audit_log)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: birdcage crowdsec add <ip> --reason \"<why>\"")
		fs.PrintDefaults()
	}
	// Accept the address before or after the flag: `add 203.0.113.9
	// --reason x` and `add --reason x 203.0.113.9` both read naturally.
	var positional []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		rest = fs.Args()
		if len(rest) > 0 {
			positional = append(positional, rest[0])
			rest = rest[1:]
		}
	}
	if len(positional) != 1 {
		fs.Usage()
		return errors.New("exactly one address is required")
	}
	target := positional[0]

	loaded, err := crowdsec.Load(getenv)
	if err != nil {
		return err
	}
	if !loaded.Enabled {
		return crowdsec.ErrNotConfigured
	}
	floorConfig, err := neverblock.Load(getenv)
	if err != nil {
		return err
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	blocker := crowdsec.New(crowdsec.NewClient(loaded.Config), neverblock.New(floorConfig), nil)
	out, err := blocker.Block(context.Background(), database, target, *reason, crowdsecTriggeredBy, neverblock.Inputs{})
	if err != nil {
		return err
	}

	// The address and the id are read back from the LAPI's own
	// answer, so they are escaped at the terminal like every other
	// value this binary prints from outside itself.
	id := out.AlertID
	if id == "" {
		id = "(not returned)"
	}
	switch out.Status {
	case crowdsec.StatusAdded:
		fmt.Fprintf(stdout, "added: permanent ban on %s (LAPI alert %s, duration %s); recorded in audit_log as %s\n",
			term.Escape(out.Target), term.Escape(id), out.Duration, crowdsec.ActionAdded)
	case crowdsec.StatusExists:
		fmt.Fprintf(stdout, "already banned by birdcage: %s (LAPI alert %s, %s remaining); nothing posted; recorded in audit_log as %s\n",
			term.Escape(out.Target), term.Escape(id), term.Escape(out.Duration), crowdsec.ActionExists)
	default:
		return fmt.Errorf("unexpected outcome %q", out.Status)
	}
	return nil
}
