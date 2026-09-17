// Command birdcage-agent is the process that runs on every canary box
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
// slice built. Seven long-lived goroutines share one cancellation
// context and one TokenStore: the receiver, the log road (tailer plus
// its eviction-recovery restart), the sender, the heartbeat, the
// command poll, the command runner, and token rotation.
//
// Never import internal/ingest from this package or anything it calls:
// doing so would pull db, store, api and stream in behind it, linking
// the whole server into the binary that ships to canary boxes (#48's own
// hard constraint). internal/opencanary exists for whatever this binary
// needs from that side.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// version is stamped at build time (-ldflags "-X main.version=...") --
// #48's ratified deliverable design, item 1: "Stamped into the binary at
// build ... reported in every heartbeat." Left at "dev" for a build
// outside the release pipeline, so a local build's self-report is still
// honest about not being a tagged release.
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("birdcage-agent: ")

	cfg, err := loadConfig()
	if err != nil {
		// Fail-closed per #48 decision 1: "Any missing or unreadable
		// required input ... is a loud non-zero exit ... a
		// half-credentialed agent must never half-run." systemd's own
		// Restart= policy is what retries this, with backoff, rather
		// than anything in this process looping on its own.
		log.Fatalf("configuration: %v", err)
	}

	c, err := client.New(client.Config{
		BaseURL:    cfg.BirdcageURL,
		CACert:     cfg.CACert,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	})
	if err != nil {
		log.Fatalf("build birdcage client: %v", err)
	}

	ts, err := loadTokenStore(cfg.TokenPath)
	if err != nil {
		log.Fatalf("load token: %v", err)
	}

	in, err := NewIntake(IntakeConfig{
		LogPath:      cfg.LogPath,
		PositionPath: cfg.PositionPath,
		Listen:       cfg.Listen,
	})
	if err != nil {
		log.Fatalf("build intake: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	// Start order per #48's process-composition note, decision 1: the
	// receiver first, so the webhook road is open as early as possible
	// -- every moment it is not is one more webhook attempt OpenCanary's
	// single, synchronous try can drop, even though the log road
	// recovers it. Everything else follows, log road (tailer) last,
	// mirroring the note's own ordering exactly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := in.Receiver.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("receiver: stopped: %v", err)
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

	wg.Add(6)
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

	log.Printf("birdcage-agent %s started, talking to %s", version, cfg.BirdcageURL)

	<-ctx.Done()
	log.Printf("shutting down")
	// Queued-but-unsent events are deliberately abandoned here rather
	// than flushed (#48 decision 1): the acknowledged position never
	// advanced past them, so the next start re-reads them from the log
	// -- the durability design working, not a loss.
	wg.Wait()
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
