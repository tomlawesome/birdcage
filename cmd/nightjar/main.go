// Command nightjar is the scanner agent (ADR-0010, issue #108 slice 1):
// the only process running on a box birdcage has enrolled with `--kind
// scanner`. It mounts the host read-only at /host, checks that every
// secret-bearing path is actually covered before trusting that mount at
// all (internal/hostmask, scanner.go's checkMounts), runs pinned Grype
// as a subprocess over what remains, and posts the resulting snapshot to
// birdcage's POST /ingest/scans.
//
// Unlike cmd/mockingbird, this binary has no receiver and no log tailer
// -- ADR-0010 decision 3 ("never runs inside mockingbird ... no
// listener"). It does send the common heartbeat (issue #106 split
// /ingest/heartbeat's body into a log-tailer-shaped Honeypot half and a
// common-only half every kind can send) and, since ADR-0012, an outbound
// poll of its own commands: `/ingest/commands` widened to include a
// `scan` order birdcage mints for a proof or an admin-ordered scan
// (command.go). That poll is still outbound over the same mTLS channel
// as the heartbeat -- decision 3's "no listener" stands -- and every
// other command kind is logged and skipped, never executed. Four loops
// run concurrently: scan (scanner.go), heartbeat (heartbeat.go), command
// poll and order runner (command.go); a scanGate (command.go) keeps a
// timer scan and an ordered scan from ever running at once.
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
	"github.com/tomlawesome/birdcage/internal/scan"
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

	// ADR-0012 decision 10: whatever a previous boot recorded about the
	// vulnerability-database refresh -- last success, an open failing
	// span -- must survive this restart, so it is loaded before either
	// loop that reads or writes it starts.
	dbTracker, err := loadDBRefreshTracker(cfg.StateDir)
	if err != nil {
		mainLog.Error(fmt.Sprintf("database refresh state: %s", safeErr(err)))
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	run(ctx, cfg, cli, token, rm, dbTracker, version, mainLog)
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
func run(ctx context.Context, cfg Config, cli *client.Client, token string, rm *renewal.Manager, dbTracker *dbRefreshTracker, version string, log *slog.Logger) {
	log.Info(fmt.Sprintf("nightjar %s started, talking to %s, scanning every %s", version, cfg.BirdcageURL, cfg.ScanInterval))

	// gate serialises every scan cycle -- timer or ordered -- so at most
	// one ever runs at once (ADR-0012 decision 2); runTracker is the
	// in-flight ordered run's stage, read by the ordinary heartbeat loop
	// so it keeps repeating that stage until the run is answered
	// (decision 9).
	gate := newScanGate()
	runTracker := newCurrentRunTracker()

	deps := scanCycleDeps{
		version:     version,
		now:         time.Now,
		checkMounts: checkMounts,
		refreshDB:   func(ctx context.Context) error { return scan.UpdateDB(ctx, grypeBin) },
		runScan:     realScan,
		dbTracker:   dbTracker,
		reportStage: newStageReporter(cli, token, version, dbTracker, runTracker, commandLog),
		runTracker:  runTracker,
	}
	orders := make(chan scanOrder, orderRunnerBuffer)

	// Four independent loops: the scan loop is this agent's whole reason
	// to exist; the heartbeat loop is the common self-report every kind
	// sends; the command poll and order runner (ADR-0012) are the
	// outbound half of an ordered scan. Concurrent, not sequential, so a
	// heartbeat is never gated behind however long a scan cycle takes --
	// mirroring cmd/mockingbird's own wg.Add/go-func shape for its
	// several loops (main.go there).
	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		runScanLoop(ctx, cli, token, deps, gate, cfg.ScanInterval, logging.New("scan"))
	}()
	go func() {
		defer wg.Done()
		runHeartbeatLoop(ctx, cli, token, rm, version, heartbeatInterval, dbTracker, runTracker)
	}()
	go func() {
		defer wg.Done()
		runCommandPollLoop(ctx, cli, token, orders, time.Now)
	}()
	go func() {
		defer wg.Done()
		runOrderRunner(ctx, deps, gate, cli, token, commandLog, orders)
	}()
	wg.Wait()

	log.Info("shutting down")
}
