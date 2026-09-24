package renewal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/certkey"
	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// Manager holds one agent's current client key/certificate pair in
// memory and drives ADR-0012 B2's renewal loop against it: "from the
// certificate's half-life ... on every heartbeat tick try POST
// /ingest/renew ... until one succeeds ... with a fresh key each time."
// Both mockingbird and nightjar construct one of these at boot, seeded
// with the pair enrolment (or a previous renewal) wrote to disk, and
// call Tick from their own heartbeat loop.
//
// Safe for concurrent use; Tick is meant to be called from one loop only
// (mirroring cmd/mockingbird/rotate.go's own token rotation, which is
// also single-flight), but CertPEM/KeyPEM may be read from elsewhere.
type Manager struct {
	mu      sync.Mutex
	certPEM []byte
	keyPEM  []byte

	stateDir     string
	keyFileName  string
	certFileName string
}

// NewManager builds a Manager seeded with the key/certificate pair
// already on disk at stateDir/keyFileName and stateDir/certFileName --
// the caller's own loadConfig has already read certPEM/keyPEM once for
// building the birdcage client; this constructor just gives the renewal
// loop its own copy to track going forward.
func NewManager(stateDir, keyFileName, certFileName string, certPEM, keyPEM []byte) *Manager {
	return &Manager{
		stateDir:     stateDir,
		keyFileName:  keyFileName,
		certFileName: certFileName,
		certPEM:      certPEM,
		keyPEM:       keyPEM,
	}
}

// CertPEM returns the certificate currently believed live -- for tests
// and for a caller's own diagnostics; never logged verbatim (a
// certificate is not secret, but this package takes no view on that --
// see each cmd package's own safelog.go for what it chooses to print).
func (m *Manager) CertPEM() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.certPEM
}

// KeyPEM returns the private key currently believed live. Callers must
// never log this value.
func (m *Manager) KeyPEM() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keyPEM
}

// Tick is the whole renewal loop's per-call unit of work, meant to be
// invoked from the caller's own heartbeat tick (ADR-0012 B2: "on every
// heartbeat tick"). It reports (false, nil) when the current certificate
// has not reached its half-life yet -- nothing to do. Once past
// half-life, it attempts exactly one renewal:
//
//  1. Generate a fresh key and CSR (certkey) -- "a fresh key each time",
//     never the key the current certificate was issued for.
//  2. POST /ingest/renew over c, authenticated with token (the agent's
//     current bearer token, untouched by this call: "the agent keeps
//     using its current token").
//  3. On success, durably persist the new pair (StageAndSwap -- see that
//     function's own doc comment for the crash-safety argument), then
//     switch c itself to present the new pair on its next connection
//     (c.SwapClientCert), then update this Manager's in-memory copy.
//     Only after all three succeed is (true, nil) returned.
//  4. On any failure -- the request itself, or either write -- the old
//     pair is left completely alone, in memory and on disk, and the
//     error is returned for the caller to log (via its own safeErr) and
//     retry on the next tick, the same "log and continue" shape every
//     other loop in this codebase uses for a failed heartbeat or a
//     failed rotation.
func (m *Manager) Tick(ctx context.Context, c *client.Client, token string) (bool, error) {
	m.mu.Lock()
	certPEM := m.certPEM
	m.mu.Unlock()

	half, err := certkey.HalfLife(certPEM)
	if err != nil {
		return false, fmt.Errorf("renewal: read current certificate: %w", err)
	}
	if time.Now().Before(half) {
		return false, nil
	}

	key, err := certkey.GenerateKey()
	if err != nil {
		return false, fmt.Errorf("renewal: generate key: %w", err)
	}
	csrPEM, err := certkey.BuildCSR(key)
	if err != nil {
		return false, fmt.Errorf("renewal: build CSR: %w", err)
	}

	result, err := c.RenewCert(ctx, token, csrPEM)
	if err != nil {
		return false, fmt.Errorf("renewal: request: %w", err)
	}

	newKeyPEM, err := certkey.MarshalKeyPEM(key)
	if err != nil {
		return false, fmt.Errorf("renewal: encode new key: %w", err)
	}

	if err := StageAndSwap(m.stateDir, m.keyFileName, m.certFileName, newKeyPEM, result.ClientCertPEM); err != nil {
		return false, fmt.Errorf("renewal: persist new pair: %w", err)
	}
	if err := c.SwapClientCert(result.ClientCertPEM, newKeyPEM); err != nil {
		// The new pair is already durable on disk at this point -- a
		// later boot will pick it up correctly even though this running
		// process failed to switch to it live. Not updating m.certPEM
		// means the next Tick sees the same (still past half-life) old
		// certificate and simply tries again with another fresh key,
		// which is safe: the old certificate is still valid and still in
		// use, so nothing here has cut this agent off from birdcage.
		return false, fmt.Errorf("renewal: switch client to new pair: %w", err)
	}

	m.mu.Lock()
	m.certPEM, m.keyPEM = result.ClientCertPEM, newKeyPEM
	m.mu.Unlock()
	return true, nil
}
