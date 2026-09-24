// Command nightjar is the scanner agent (ADR-0010, issue #108 slice 1):
// the only process running on a box birdcage has enrolled with `--kind
// scanner`. It mounts the host read-only at /host, checks that every
// secret-bearing path is actually covered before trusting that mount at
// all (internal/hostmask, scanner.go's checkMounts), runs pinned Grype
// as a subprocess over what remains, and posts the resulting snapshot to
// birdcage's POST /ingest/scans.
//
// Unlike cmd/mockingbird, this binary has no receiver, no log tailer and
// no command poll -- ADR-0010 decision 3 ("never runs inside mockingbird
// ... no listener"). It does send the common heartbeat (issue #106
// split /ingest/heartbeat's body into a log-tailer-shaped Honeypot half
// and a common-only half every kind can send; #108's own scope had
// deferred this exact loop to that split -- "a scanner sending
// queue_depth would be lying" no longer applies, since the common shape
// carries no such field). Otherwise its whole job is one loop: check the
// mount, scan, post, wait, repeat -- see scanner.go; heartbeat.go is the
// second, independent loop.
//
// Never import internal/ingest, internal/store, internal/api or
// internal/opencanary from this package or anything it calls -- doing so
// would link the server, or the honeypot's own emulation code, into the
// binary that ships to a scanner box (scripts/agent-deps-check.sh
// enforces this per agent kind, ADR-0009 decision 6).
//
// Logging: this binary runs privileged, with read access to the whole
// host filesystem, so its own log output deserves the same discipline
// cmd/mockingbird's package doc comment describes for its box -- never
// the bearer token, a certificate's path or content, or the state
// directory. safelog.go is this package's own copy of that redaction,
// duplicated rather than shared for the reason its own doc comment
// gives.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/renewal"
	"github.com/tomlawesome/birdcage/internal/logging"
)

// envLogLevel selects internal/logging's threshold -- see config.go.

// version is stamped at build time (-ldflags "-X main.version=..."),
// left at "dev" for a build outside the release pipeline, matching both
// other binaries' own convention.
var version = "dev"

func main() {
	logging.SetLevel(os.Getenv(envLogLevel))

	// `nightjar version` prints the stamped build version and exits,
	// matching cmd/mockingbird's and cmd/birdcage's own `version`
	// argument exactly -- see version.go.
	if len(os.Args) > 1 && os.Args[1] == "version" {
		if err := runVersion(os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}

	mainLog := logging.New("nightjar")

	cfg, err := loadConfig()
	if err != nil {
		mainLog.Error(fmt.Sprintf("configuration: %s", safeErr(err)))
		os.Exit(1)
	}

	cli, token, rm, err := boot(cfg)
	if err != nil {
		mainLog.Error(safeErr(err))
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	run(ctx, cfg, cli, token, rm, version, mainLog)
}

// boot builds the birdcage client and loads this agent's bearer token --
// everything main does between loadConfig and starting its long-lived
// loops, split out (mirroring cmd/mockingbird/main.go's own boot) so a
// test can drive each dependency-failure return without a real signal
// context or a real scan/heartbeat loop running underneath it. Every
// error returned here already carries its safeErr-redacted cause, the
// same "wrap once here, safeErr again at the call site" shape
// cmd/mockingbird's boot/main pair uses -- harmless to repeat, since
// safeErr's redaction is a no-op the second time a path or address has
// already been replaced.
func boot(cfg Config) (*client.Client, string, *renewal.Manager, error) {
	cli, err := client.New(client.Config{
		BaseURL:    cfg.BirdcageURL,
		CACert:     cfg.CACert,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	})
	if err != nil {
		return nil, "", nil, fmt.Errorf("build birdcage client: %s", safeErr(err))
	}

	token, err := loadToken(cfg.TokenPath)
	if err != nil {
		return nil, "", nil, fmt.Errorf("load token: %s", safeErr(err))
	}

	rm := renewal.NewManager(cfg.StateDir, clientKeyFileName, clientCertFileName, cfg.ClientCert, cfg.ClientKey)

	return cli, token, rm, nil
}

// run starts nightjar's two independent loops -- scan and heartbeat --
// and blocks until ctx is done and both have returned, logging the same
// "started"/"shutting down" lines main used to log directly. Split out
// from main so a test can prove the cadence contract (both loops start,
// both stop promptly on a cancelled context) without a real signal
// handler -- see TestRunStopsPromptlyOnCancelledContext.
func run(ctx context.Context, cfg Config, cli *client.Client, token string, rm *renewal.Manager, version string, log *slog.Logger) {
	log.Info(fmt.Sprintf("nightjar %s started, talking to %s, scanning every %s", version, cfg.BirdcageURL, cfg.ScanInterval))

	// Two independent loops (issue #106 adds the second): the scan loop
	// is this agent's whole reason to exist, and the heartbeat loop is
	// the common self-report every kind now sends. Concurrent, not
	// sequential, so a heartbeat is not gated behind however long a scan
	// cycle takes -- mirroring cmd/mockingbird's own wg.Add/go-func
	// shape for its several loops (main.go there), scaled down to two.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		runScanLoop(ctx, cli, token, version, cfg.ScanInterval, logging.New("scan"), time.Now)
	}()
	go func() {
		defer wg.Done()
		runHeartbeatLoop(ctx, cli, token, rm, version, heartbeatInterval)
	}()
	wg.Wait()

	log.Info("shutting down")
}
