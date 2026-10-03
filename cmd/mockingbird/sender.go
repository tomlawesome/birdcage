package main

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/ledger"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var senderLog = logging.New("sender")

// senderIdleInterval is how often the sender checks an empty queue for
// new arrivals. Short, since a healthy fleet's normal latency floor is
// this number, not the once-a-minute retry cadence below.
const senderIdleInterval = 250 * time.Millisecond

// senderRetryInterval is #32's transport semantics, "429, 5xx, timeouts
// and connection failures mean retry," on the ratified once-a-minute
// cadence (#48, "Batches and pushes ... Retries once a minute until
// birdcage acknowledges").
const senderRetryInterval = 1 * time.Minute

// runSenderLoop is #48's process-composition note, "the process at a
// glance": "sender Peek -> ExtractFields -> client.PushBatch ->
// Ack/Reject -> ledger -> PositionStore.Save." It runs until ctx is
// done; a queued-but-unsent event at that point is deliberately
// abandoned in memory (main.go's own doc comment on this), never
// flushed.
func runSenderLoop(ctx context.Context, c *client.Client, ts *TokenStore, in *Intake, p *pacer) {
	for {
		if ctx.Err() != nil {
			return
		}

		batch := in.Queue.Peek(client.MaxEventsPerBatch)
		if len(batch) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(senderIdleInterval):
			}
			continue
		}

		// #46 slice 3: an event still awaiting its claim window's
		// exactly-one decision (claim.go) is left queued for another
		// round rather than sent unclaimed -- "the agent claims before
		// the event leaves the box" (note 19897) only holds if the
		// sender never ships a candidate ahead of that decision. Every
		// other event in the batch ships on this round exactly as
		// before, claimed or not: holding back only the undecided ones
		// costs one held-back event at most twice a day, not the batch.
		ids := make([]string, 0, len(batch))
		events := make([]client.Event, 0, len(batch))
		for _, qe := range batch {
			if in.claims.pending(qe.ID) {
				continue
			}
			fields := fieldsOrFallback(qe.Payload)
			marker, _ := in.claims.marker(qe.ID)
			ids = append(ids, qe.ID)
			events = append(events, client.Event{
				ID:             qe.ID,
				SourceIP:       fields.SourceIP,
				DestPort:       fields.DestPort,
				Service:        fields.Service,
				Raw:            string(qe.Payload),
				SelfTestMarker: marker,
			})
		}
		if len(events) == 0 {
			// Every peeked event is still awaiting a claim decision --
			// wait out the idle interval and Peek again rather than
			// pushing p's own rate budget for an empty send.
			select {
			case <-ctx.Done():
				return
			case <-time.After(senderIdleInterval):
			}
			continue
		}

		if err := p.wait(ctx, len(events)); err != nil {
			return
		}

		result, err := authedRetryValue(ts, func(token string) (client.BatchResult, error) {
			return c.PushBatch(ctx, token, events)
		})
		if err != nil {
			if client.IsUnauthorized(err) {
				senderLog.Warn("token unauthorized -- this canary has no channel to birdcage; recovery is re-enrolment (#47)")
			} else {
				senderLog.Warn(fmt.Sprintf("push failed, will retry: %s", safeErr(err)))
			}
			// #48 fail-closed: "Push gets 429, 5xx, timeout or connection
			// failure -> retry ... queue holds." Nothing is resolved for
			// this batch: every id in it stays exactly as unresolved and
			// queued as it was before this attempt.
			select {
			case <-ctx.Done():
				return
			case <-time.After(senderRetryInterval):
			}
			continue
		}

		in.applyVerdicts(ids, result)
	}
}

// applyVerdicts is #48's verdict mapping: the one place a birdcage
// response for a batch becomes queue Ack/Reject calls, ledger.Resolve
// calls, and a possible saved-position advance.
//
// ledger.Resolve panics on any Verdict but Stored or Rejected, and its
// zero value is deliberately invalid -- protection against silently
// resolving on an unrecognised response, which would advance the saved
// position past an unconfirmed event with no spool to fall back on
// (ledger.go's own doc comment). This function is what keeps that
// promise on the caller's side: every id PushBatch was given is
// resolved to at most one of Stored or Rejected, using only what result
// actually named it as. Anything else -- named as neither (birdcage's
// own Retry case: an infrastructure failure, or a batch this package
// split and could not finish) or, should client.BatchResult's
// documented split ever be violated by a malformed or unexpected
// response, named as both -- is left completely unresolved. There is no
// third ledger.Verdict for either case to fall into by mistake: the
// switch below only ever calls Resolve with Stored or Rejected, never
// with anything derived directly from the wire.
func (in *Intake) applyVerdicts(sentIDs []string, result client.BatchResult) {
	stored := toSet(result.Stored)
	rejected := make(map[string]bool, len(result.Rejected))
	for id := range result.Rejected {
		rejected[id] = true
	}

	ldg := in.Ledger()
	var lastStored string
	for _, id := range sentIDs {
		isStored, isRejected := stored[id], rejected[id]
		switch {
		case isStored && !isRejected:
			in.Queue.Ack(id)
			ldg.Resolve(id, ledger.Stored)
			lastStored = id
			in.claims.forget(id) // #46 slice 3: terminal resolution, nothing left to attach a marker to
		case isRejected && !isStored:
			in.Queue.Reject(id)
			ldg.Resolve(id, ledger.Rejected)
			in.claims.forget(id) // #46 slice 3: terminal resolution, same as Stored above
		case isStored && isRejected:
			// Contradiction: client.BatchResult's own contract
			// guarantees Stored and Rejected never share an id, so this
			// can only mean a defect somewhere on the wire. #48's
			// protective rule: an unrecognised response is a retry,
			// never a resolve -- so this id is left queued and
			// unresolved rather than settled either way.
			senderLog.Warn(fmt.Sprintf("event %s named as both stored and rejected, treating as unresolved", id))
		default:
			// Named as neither: birdcage's Retry case. Left queued and
			// unresolved, retried on the next Peek.
		}
	}

	if lastStored != "" {
		in.setLastEventID(lastStored)
	}

	if pos, ok := ldg.Advance(); ok {
		if err := in.PositionStore().Save(pos); err != nil {
			// #48 fail-closed: "Acknowledged position unwritable ...
			// keep forwarding, report it; on restart, re-read from the
			// last written position." Nothing here needs to retry the
			// save itself -- the next Advance that moves the frontier
			// tries again. safeErr: PositionStore.Save's own error
			// wraps the position file's path, inside StateDir -- one of
			// the values this agent must never log (see safelog.go).
			senderLog.Warn(fmt.Sprintf("save acknowledged position failed, will retry on the next advance: %s", safeErr(err)))
		}
	}
}

func toSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}
