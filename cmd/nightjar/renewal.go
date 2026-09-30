package main

import (
	"context"
	"fmt"

	"github.com/tomlawesome/birdcage/internal/agent/client"
	"github.com/tomlawesome/birdcage/internal/agent/renewal"
	"github.com/tomlawesome/birdcage/internal/logging"
)

var renewalLog = logging.New("renewal")

// runRenewalTick is cmd/mockingbird/renewal.go's own runRenewalTick,
// applied to Nightjar's own shape: no TokenStore here (token.go's own
// doc comment -- this binary mints no rotation loop at all), so the
// current token is passed straight through as a plain string. See that
// function's doc comment for the full ADR-0012 B2 rationale, which
// applies here unchanged.
func runRenewalTick(ctx context.Context, rm *renewal.Manager, c *client.Client, token string) {
	renewed, err := rm.Tick(ctx, c, token)
	if err != nil {
		if client.IsUnauthorized(err) {
			renewalLog.Warn("certificate renewal unauthorized -- birdcage does not recognise this scanner's certificate (likely enrolled before ADR-0012 Part B, or already revoked); recovery is re-enrolment (#47)")
			return
		}
		renewalLog.Warn(fmt.Sprintf("renewal failed, keeping current certificate: %s", safeErr(err)))
		return
	}
	if renewed {
		renewalLog.Info("certificate renewed")
	}
}
