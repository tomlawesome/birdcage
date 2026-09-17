// Command birdcage-agent is the process that runs on every canary box
// (issue #48): the only thing there that talks to birdcage. OpenCanary's
// own webhook handler makes one attempt per event and drops it on
// failure -- this binary is what makes posting that attempt safe, and
// everything past it (retries, acknowledgement, credential rotation,
// the heartbeat, command polling) is our code.
//
// This slice (#48's "process composition" design note, decisions 1, 4
// and 6) builds the process skeleton and the two credential loops every
// other loop this binary will eventually run shares: token rotation and
// the heartbeat. The event path -- the loopback receiver, the log
// tailer, the memory queue, the acknowledged-position ledger and the
// sender that ties them together -- and the command poll/runner are a
// later slice ("Explicitly NOT in this slice" in the brief that produced
// this file). main is structured so they start alongside rotation and
// heartbeat, sharing the same context and TokenStore, without
// restructuring what is here.
//
// Never import internal/ingest from this package or anything it calls:
// doing so would pull db, store, api and stream in behind it, linking
// the whole server into the binary that ships to canary boxes (#48's own
// hard constraint). internal/opencanary exists for whatever this binary
// needs from that side.
package main

import (
	"context"
	"log"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The two credential loops this slice builds. A later slice starts
	// the receiver first (so the webhook road is open as early as
	// possible -- #48 decision 1), then the tailer, sender and command
	// poll/runner, all added to this same WaitGroup and sharing ctx and
	// ts.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		runRotationLoop(ctx, c, ts)
	}()
	go func() {
		defer wg.Done()
		runHeartbeatLoop(ctx, c, ts, func() client.SelfReport {
			return currentSelfReport(version)
		})
	}()

	log.Printf("birdcage-agent %s started, talking to %s", version, cfg.BirdcageURL)

	<-ctx.Done()
	log.Printf("shutting down")
	// Queued-but-unsent events, once a later slice adds the queue, are
	// deliberately abandoned here rather than flushed (#48 decision 1):
	// the acknowledged position never advanced past them, so the next
	// start re-reads them from the log -- the durability design working,
	// not a loss. Nothing to abandon yet in this slice.
	wg.Wait()
}

// currentSelfReport builds the heartbeat body this slice can honestly
// send: the event path -- queue, tailer, ledger -- is not wired yet
// ("Explicitly NOT in this slice"), so QueueDepth, Dropped, Rejected and
// EventIDCollisions are truthfully zero (nothing is queued, dropped or
// resolved because nothing runs yet), and LogReadOK and PositionFound
// are truthfully false (the log is not being read yet). A later slice
// replaces this with the real queue's Depth/Dropped/RejectedCount, the
// tailer's log-read status, and the ledger's collision count.
func currentSelfReport(version string) client.SelfReport {
	return client.SelfReport{AgentVersion: version}
}
