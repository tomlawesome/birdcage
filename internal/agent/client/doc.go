// Package client is the HTTPS client a canary's agent (#48) uses to talk
// to birdcage's ingest submux (#32): push batches of OpenCanary events,
// rotate its own bearer token, send its heartbeat, and poll for commands.
// It is deliberately thin -- one goroutine-safe *http.Client, four
// request shapes matching internal/ingest's four routes wire-for-wire,
// and enough response classification to tell the caller "birdcage
// permanently rejected this event" apart from "try again" -- and carries
// none of the state an agent needs around it: no on-disk queue, no token
// file, no schedule. #48: "the caller owns writing it to disk. Do not
// write files"; "expose what the caller needs [to pace its backfill];
// do not build a scheduler."
//
// TLS is verified against a CA the caller supplies (#47 installs it on
// the canary); every redirect is refused unconditionally (#48 "What the
// research changed" #1: GO-2025-3420 and CVE-2019-3462 are both a
// redirect carrying a credential, or a fetch, somewhere it should not
// go); HTTP/1.1 only, matching internal/ingest/tlsserver.go's own
// Server.Protocols pin; every call has an explicit timeout, and every
// response this package reads is bounded (#48: "no unbounded reads").
//
// Every wire type here mirrors internal/ingest's own field-for-field
// (batch.go's ingestEvent/ingestBatch/ackResponse, rotate.go's
// rotateResponse, heartbeat.go's ingestHeartbeat, command.go's
// commandPoll/deliveredCommand) rather than a shape invented
// independently, so the two sides can only drift apart by an edit this
// package's own tests -- run against internal/ingest's real handlers,
// not a hand-written fake -- would catch.
package client
