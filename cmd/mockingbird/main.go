// Command mockingbird is the process that runs on every canary box
// (issue #48): the only thing there that talks to birdcage. OpenCanary's
// own webhook handler makes one attempt per event and drops it on
// failure -- this binary is what makes posting that attempt safe, and
// everything past it (retries, acknowledgement, credential rotation,
// the heartbeat, command polling) is our code.
//
// This slice (#48's process-composition design note) wires the event
// path -- the loopback receiver, the log tailer, the memory queue, the
// acknowledged-position ledger and the sender that ties them together
// -- and the command poll/runner into the process skeleton the previous
// slice built. Ten long-lived goroutines share one cancellation context
// and one TokenStore: the receiver, the log road (tailer plus its
// eviction-recovery restart), the sender, the heartbeat, the command
// poll, the command runner, token rotation, (#69) the OpenCanary child
// supervisor, (#65) the port-scan road, and (#88) the snmp road.
//
// The port-scan road (#65) is the third way an event reaches the queue,
// alongside the webhook receiver and the log tailer, and the only one
// that produces an event nothing else generated: internal/agent/portscan
// watches this container's own network namespace through a
// kernel-filtered raw socket and emits an OpenCanary-shaped event when
// somebody sweeps ports nothing is listening on. It needs CAP_NET_RAW
// and nothing else; a run without it logs one WARN and carries on with
// detection off. See portscan.go.
//
// The snmp road (#88) is the fourth: internal/agent/snmp is a plain UDP
// listener on port 161 that decodes SNMP v1/v2c requests itself and
// never answers. OpenCanary's own snmp module stays disabled -- it
// needs scapy, which #85 keeps out of this image -- so this is our own
// reader, not a wrapper around theirs. See snmp.go.
//
// Never import internal/ingest from this package or anything it calls:
// doing so would pull db, store, api and stream in behind it, linking
// the whole server into the binary that ships to canary boxes (#48's own
// hard constraint). internal/opencanary exists for whatever this binary
// needs from that side.
//
// Logging (#71): this binary runs on the honeypot, the one machine in
// this whole system an attacker who compromises the box gets to read
// stdout/stderr from directly -- so, unlike cmd/birdcage, it never
// prints a boot banner or a configuration inventory. What it does log
// through internal/logging's component loggers is deliberately narrow:
// "started" with its own version, each connection failure to birdcage
// (the existing lines below), the OpenCanary child's start/exit, and
// (#65) one line saying whether port-scan detection is running. That
// last one is the nearest thing this binary has to an inventory, and it
// is deliberately thin: a count of how many ports are treated as
// listening, never which, and no address beyond the source of a scan
// that is already on its way to birdcage anyway.
// What it must never log, in any component, at any level: the bearer
// token, any certificate's path or content, the receiver's listen
// address, the log path, the state directory, or an event body. Every
// error that could carry one of those (a file or listen-address error
// from the standard library embeds its path/address verbatim in its own
// Error() text) goes through safeErr (safelog.go) before it reaches a
// log line -- see cmd/mockingbird/nolog_test.go for the test that
// startup path can never regress.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/logging"
)

// envLogLevel selects internal/logging's threshold (debug/info/warn/
// error, case-insensitive; unset or unrecognized falls back to info) --
// see docs/configuration.md. Named and read the same way cmd/birdcage's
// own envLogLevel is.
const envLogLevel = "MOCKINGBIRD_LOG_LEVEL"

// version is stamped at build time (-ldflags "-X main.version=...") --
// #48's ratified deliverable design, item 1: "Stamped into the binary at
// build ... reported in every heartbeat." Left at "dev" for a build
// outside the release pipeline, so a local build's self-report is still
// honest about not being a tagged release.
var version = "dev"

func main() {
	logging.SetLevel(os.Getenv(envLogLevel))

	// `mockingbird version` prints the stamped build version and exits
	// (issue #97), matching cmd/birdcage's own `version` argument (issue
	// #90, cmd/birdcage/main.go around line 195) exactly: it comes first,
	// before mainLog or cfg exist, and writes to stdout rather than the
	// log, because the release job compares its output with the tag it
	// built from -- one line, no level prefix. It also has to come before
	// os.Args[1:] is handed to runChild below as OpenCanary's own
	// arguments: `docker run <image> version` replaces the Dockerfile's
	// CMD entirely, so without this check "version" would be run as
	// OpenCanary's argv instead of being answered.
	if len(os.Args) > 1 && os.Args[1] == "version" {
		if err := runVersion(os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}

	mainLog := logging.New("mockingbird")

	cfg, err := loadConfig()
	if err != nil {
		// Fail-closed per #48 decision 1: "Any missing or unreadable
		// required input ... is a loud non-zero exit ... a
		// half-credentialed agent must never half-run." systemd's own
		// Restart= policy is what retries this, with backoff, rather
		// than anything in this process looping on its own. safeErr:
		// loadConfig's own error already names which file by its bare
		// name (see config.go), but a wrapped os error under it would
		// otherwise still carry the real StateDir path.
		mainLog.Error(fmt.Sprintf("configuration: %s", safeErr(err)))
		os.Exit(1)
	}

	c, ts, in, err := boot(cfg, version, mainLog)
	if err != nil {
		mainLog.Error(safeErr(err))
		os.Exit(1)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// A second, derived cancel: the run must also stop if OpenCanary (see
	// runChild, below) exits on its own, not only on a signal.
	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()

	var wg sync.WaitGroup

	// Start order per #48's process-composition note, decision 1: the
	// receiver first, so the webhook road is open as early as possible
	// -- every moment it is not is one more webhook attempt OpenCanary's
	// single, synchronous try can drop, even though the log road
	// recovers it. Everything else follows, log road (tailer) last,
	// mirroring the note's own ordering exactly.
	receiverLog := logging.New("receiver")
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := in.Receiver.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			receiverLog.Warn(fmt.Sprintf("stopped: %s", safeErr(err)))
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = in.Receiver.Close()
	}()

	pacer := newPacer()
	commands := make(chan *client.Command, commandRunnerBuffer)

	// The port-scan road (#65): the capture socket is opened here, on
	// the startup path, so an operator who forgot --cap-add NET_RAW sees
	// one WARN beside the rest of the startup log rather than whenever a
	// goroutine happened to be scheduled. A nil detector means detection
	// is off -- disabled, or the capability was missing -- and
	// runPortscanRoad is then a no-op, so the goroutine count below does
	// not depend on it.
	portscanLog := logging.New("portscan")
	detector, inventory := newPortscanRoad(cfg, in, portscanLog)
	portscanLog.Info(inventory.line())

	// The snmp road (#88): the UDP socket is opened here for the same
	// reason -- an operator whose port is unexpectedly privileged (see
	// snmp.go) sees one WARN at startup rather than whenever the
	// goroutine gets scheduled. A nil detector means the road is
	// disabled or the bind failed, and runSNMPRoad is then a no-op.
	snmpLog := logging.New("snmp")
	snmpDetector, snmpInv := newSNMPRoad(in, snmpLog)
	snmpLog.Info(snmpInv.line())

	wg.Add(8)
	go func() {
		defer wg.Done()
		runSenderLoop(ctx, c, ts, in, pacer)
	}()
	go func() {
		defer wg.Done()
		runHeartbeatLoop(ctx, c, ts, func() client.SelfReport {
			return currentSelfReport(version, in)
		})
	}()
	go func() {
		defer wg.Done()
		runCommandPollLoop(ctx, c, ts, commands)
	}()
	go func() {
		defer wg.Done()
		runCommandRunner(ctx, commands)
	}()
	go func() {
		defer wg.Done()
		runRotationLoop(ctx, c, ts)
	}()
	go func() {
		defer wg.Done()
		in.RunLogRoad(ctx)
	}()
	go func() {
		defer wg.Done()
		runPortscanRoad(ctx, detector, portscanLog)
	}()
	go func() {
		defer wg.Done()
		runSNMPRoad(ctx, snmpDetector, snmpLog)
	}()

	// OpenCanary as mockingbird's child process (#69): the receiver above
	// is already listening, so OpenCanary's first webhook attempt finds
	// it open. With no arguments (os.Args[1:] empty) this is a no-op --
	// today's behaviour, untouched.
	childLog := logging.New("child")
	var childDied atomic.Bool
	if len(os.Args) > 1 {
		childLog.Info(fmt.Sprintf("starting %v", os.Args[1:]))
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		runChild(ctx, os.Args[1:], func(err error) {
			if err != nil {
				childLog.Warn(fmt.Sprintf("%v exited: %v", os.Args[1:], err))
			} else {
				childLog.Info(fmt.Sprintf("%v exited", os.Args[1:]))
			}
			childDied.Store(true)
			cancel()
		})
	}()

	// The readiness road (#65): only meaningful alongside a real
	// OpenCanary child -- os.Args[1:] empty is the same "no child at all"
	// case runChild itself no-ops on, and a check that only ever reads its
	// own agent's empty environment has nothing to prove.
	if len(os.Args) > 1 {
		readinessLog := logging.New("readiness")
		wg.Add(1)
		go func() {
			defer wg.Done()
			runReadinessCheck(ctx, defaultReadinessConfig(), readinessLog)
		}()
	}

	<-ctx.Done()
	mainLog.Info("shutting down")
	// Queued-but-unsent events are deliberately abandoned here rather
	// than flushed (#48 decision 1): the acknowledged position never
	// advanced past them, so the next start re-reads them from the log
	// -- the durability design working, not a loss.
	wg.Wait()
	// A run ended by the child dying is a failure whatever the child's
	// own status -- even a clean exit means the honeypot is gone -- and
	// the container's restart policy only acts on a non-zero exit.
	if childDied.Load() {
		os.Exit(1)
	}
}

// boot builds the birdcage client, token store and intake from cfg, and
// logs the "started" line -- everything main does before starting its
// long-lived goroutines. Split out from main so a test (see
// nolog_test.go) can run exactly this path with a fake config and
// capture its log output, without also running main's blocking service
// loops.
func boot(cfg Config, version string, logger *slog.Logger) (*client.Client, *TokenStore, *Intake, error) {
	c, err := client.New(client.Config{
		BaseURL:    cfg.BirdcageURL,
		CACert:     cfg.CACert,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build birdcage client: %s", safeErr(err))
	}

	ts, err := loadTokenStore(cfg.TokenPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load token: %s", safeErr(err))
	}

	in, err := NewIntake(IntakeConfig{
		LogPath:      cfg.LogPath,
		PositionPath: cfg.PositionPath,
		Listen:       cfg.Listen,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("build intake: %s", safeErr(err))
	}

	logger.Info(fmt.Sprintf("mockingbird %s started, talking to %s", version, cfg.BirdcageURL))
	return c, ts, in, nil
}

// currentSelfReport builds the heartbeat's self-report from the real
// queue, tailer and ledger state (#48's process-composition note, "the
// heartbeat currently lies" -- this slice is what stops it). Every
// field is a live read of counters that exist and are always known once
// the intake is running: MemQueue.Depth/Dropped/RejectedCount, the
// tailer's LogReadOK and ResumeFound (PositionFound), the ledger's
// cumulative Collisions, and the sender's own record of the last
// birdcage-acknowledged event id. None of these is left at a placeholder
// zero -- migration 0008 stores them nullable specifically so "never
// reported" (the previous slice's honest zero SelfReport) stays distinct
// from "reported zero," and an agent that has actually measured these
// values must say so.
func currentSelfReport(version string, in *Intake) client.SelfReport {
	return client.SelfReport{
		QueueDepth:        in.Queue.Depth(),
		LogReadOK:         in.LogReadOK(),
		LastEventID:       in.LastEventID(),
		AgentVersion:      version,
		Dropped:           int64(in.Queue.Dropped()),
		Rejected:          int64(in.Queue.RejectedCount()),
		EventIDCollisions: int64(in.Collisions()),
		PositionFound:     in.PositionFound(),
	}
}
