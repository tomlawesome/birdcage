// Package enrol implements issue #47's canary-side half of enrolment ("The
// flow" steps 3, 5 and 6): first contact with birdcage's enrolment listener,
// pinned by the CA's SHA-256 fingerprint rather than any certificate birdcage
// itself has not yet handed over, followed by provisioning the canary's
// lasting mTLS client certificate and bearer token once that CA is trusted.
//
// Standard library only, deliberately -- this package is linked into
// cmd/mockingbird, which ships on the canary box (scripts/agent-deps-check.sh
// enforces the fence), so it does not import internal/agent/client or
// anything server-side, even though the two share very similar HTTP-client
// plumbing (timeouts, response caps, redirect refusal) by convention rather
// than by sharing code.
//
// Two calls, in order:
//
//   - FirstContact (POST /enrol/hello) trusts nothing about the server ahead
//     of time except the CA pin printed alongside the deploy token
//     (MOCKINGBIRD_CA_PIN, docs/enrolment.md) -- the same trust-on-first-use
//     shape k3s's agent join flow uses (cmd/agent/main.go's --token carrying
//     a "K10<CA sha256>::" prefix, verified in pkg/clientaccess before any
//     request is trusted), adapted here to a separate pin rather than a
//     token prefix. See FirstContact's own doc comment for exactly what gets
//     verified.
//   - Provision (POST /enrol/provision) runs after FirstContact has handed
//     back a CA certificate proven to match that pin, so it verifies stock,
//     against that CA as the only root -- no custom callback, the same rule
//     internal/agent/client's own Config.CACert follows once a canary is
//     enrolled.
package enrol
