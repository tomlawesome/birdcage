package main

import (
	"context"
	"fmt"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/renewal"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var renewalLog = logging.New("renewal")

// runRenewalTick attempts one certificate renewal check (ADR-0012 B2:
// "from the certificate's half-life ... on every heartbeat tick try
// POST /ingest/renew"), called once per heartbeat.go tick, on the same
// cadence as the heartbeat itself. rm.Tick already does nothing at all
// until the current certificate has passed its half-life, so most calls
// here are a no-op check.
//
// c's mTLS certificate and rm's own record of the live pair are switched
// together, inside rm.Tick, only once a renewal fully succeeds and is
// durably written to disk -- see internal/agent/renewal's own doc
// comment for the crash-safety argument. ts (the bearer token store) is
// untouched either way: ADR-0012 B2, "the server moves the live bearer
// token to the new certificate itself; the agent keeps using its
// current token."
//
// A persistent failure here is logged and left for the next tick, the
// same "log and continue" stance every other loop in this package takes
// on its own dead credential -- including the case this line exists for
// specifically: a canary enrolled before ADR-0012 Part B holds a
// server-issued key birdcage's own client_certs table has no row for, so
// its very first renewal attempt is refused. That refusal must not
// crash-loop the agent; the certificate it already has keeps working
// for ordinary ingest routes until it expires or the operator
// re-enrols.
func runRenewalTick(ctx context.Context, rm *renewal.Manager, c *client.Client, ts *TokenStore) {
	renewed, err := rm.Tick(ctx, c, ts.Current())
	if err != nil {
		if client.IsUnauthorized(err) {
			renewalLog.Warn("certificate renewal unauthorized -- birdcage does not recognise this canary's certificate (likely enrolled before ADR-0012 Part B, or already revoked); recovery is re-enrolment (#47)")
			return
		}
		renewalLog.Warn(fmt.Sprintf("renewal failed, keeping current certificate: %s", safeErr(err)))
		return
	}
	if renewed {
		renewalLog.Info("certificate renewed")
	}
}
