// Command e2e-live-hit posts one real event through birdcage's real
// canary-ingest path -- POST /enrol/hello, POST /enrol/provision, POST
// /ingest/events -- so issue #81's smoke journey can prove the SSE stream
// (/api/stream, internal/stream.Hub) actually fires for an already-open
// dashboard, not just that the 30s poll eventually notices a new row.
//
// hub.PublishAlert (internal/stream/stream.go) is called from exactly one
// place, internal/ingest/batch.go's handleBatch -- a row written directly
// into the database (the way cmd/seed-story seeds the rest of the story)
// never reaches it. So this command runs the same three-step handshake
// cmd/mockingbird's agent runs at boot and on every event, using the same
// exported client packages (internal/agent/enrol, internal/agent/client)
// rather than a hand-rolled HTTP call -- a wire-format drift between this
// command and the real agent would be a bug worth having break here, not
// a coincidence worth risking.
//
// It does not run OpenCanary or any emulated service: `birdcage canary
// enrol --name --lane` (run separately, against the same database, before
// this command) mints the deploy token and CA pin this reads from its
// flags -- see frontend/e2e/smoke.mjs, which drives both.
//
// Usage:
//
//	go run ./cmd/e2e-live-hit \
//	  -enrol-url https://127.0.0.1:PORT -pin HEX -token TOKEN \
//	  -source-ip 203.0.113.9 -dest-port 22 -service ssh \
//	  -raw '{"logdata":{"USERNAME":"root","PASSWORD":"toor"}}'
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/enrol"
	"github.com/tomlawesome/birdcage/internal/agent/event"
)

// handshakeTimeout bounds the whole enrol-then-push call: three requests
// against a birdcage this program just watched come up on loopback, none
// of which should ever approach this.
const handshakeTimeout = 20 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "e2e-live-hit:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("e2e-live-hit", flag.ContinueOnError)
	enrolURL := fs.String("enrol-url", "", "birdcage's enrolment listener, e.g. https://127.0.0.1:8444 (required)")
	pin := fs.String("pin", "", "birdcage CA pin, from `birdcage canary enrol` (required)")
	token := fs.String("token", "", "deploy token, from `birdcage canary enrol` (required)")
	sourceIP := fs.String("source-ip", "203.0.113.9", "event source_ip")
	destPort := fs.Int("dest-port", 22, "event dest_port")
	service := fs.String("service", "ssh", "event service")
	raw := fs.String("raw", `{"logdata":{"USERNAME":"root","PASSWORD":"toor"}}`, "verbatim OpenCanary-shaped raw message")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *enrolURL == "" || *pin == "" || *token == "" {
		return errors.New("-enrol-url, -pin and -token are all required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()

	// Step 1/3, "The flow": trust nothing about the enrolment listener's
	// TLS ahead of time except the pin -- FirstContact does the pinned
	// verification itself (see its own doc comment).
	hello, err := enrol.FirstContact(ctx, *enrolURL, *pin, *token)
	if err != nil {
		return fmt.Errorf("first contact: %w", err)
	}

	// Step 2/3: exchange the one-time enrolment secret for a lasting
	// canary identity -- bearer token plus an mTLS client certificate
	// birdcage's own CA issued.
	creds, err := enrol.Provision(ctx, *enrolURL, hello.CAPEM, hello.EnrolmentSecret)
	if err != nil {
		return fmt.Errorf("provision: %w", err)
	}

	c, err := client.New(client.Config{
		BaseURL:    hello.IngestURL,
		CACert:     hello.CAPEM,
		ClientCert: creds.ClientCertPEM,
		ClientKey:  creds.ClientKeyPEM,
	})
	if err != nil {
		return fmt.Errorf("build ingest client: %w", err)
	}

	message := []byte(*raw)
	id, err := event.IDFromEmittedMessage(message)
	if err != nil {
		return fmt.Errorf("compute event id: %w", err)
	}

	// Step 3/3: the real POST /ingest/events call -- the only thing in
	// this whole binary that calls hub.PublishAlert on birdcage's side.
	result, err := c.PushBatch(ctx, creds.CanaryToken, []client.Event{{
		ID:       id,
		SourceIP: *sourceIP,
		DestPort: *destPort,
		Service:  *service,
		Raw:      string(message),
	}})
	if err != nil {
		return fmt.Errorf("push batch: %w", err)
	}
	for _, stored := range result.Stored {
		if stored == id {
			fmt.Printf("stored canary=%s event=%s\n", creds.CanaryID, id)
			return nil
		}
	}
	if reason, rejected := result.Rejected[id]; rejected {
		return fmt.Errorf("birdcage rejected the event: %s", reason)
	}
	return fmt.Errorf("birdcage gave no ack for event %s (result: %+v)", id, result)
}
