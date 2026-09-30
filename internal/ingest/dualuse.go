package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// dualUseWindow is ADR-0012 B4's "within one heartbeat interval (60
// seconds)": the same certificate seen from two source addresses, or
// with two agent build versions, inside this window is two holders of
// one credential.
const dualUseWindow = 60 * time.Second

// dualUseTrackerPruneAt is the map size past which observe drops entries
// with nothing inside the window. Keys are fingerprints of live
// certificates only (observe runs after the registry check), so the map
// is bounded by the fleet's certificates, not by anything a caller
// controls; pruning just keeps renewed-away fingerprints from piling up.
const dualUseTrackerPruneAt = 4096

// dualUseTracker remembers, per certificate fingerprint, the last
// source address and the last agent build version seen with it. In
// memory, like the coalescer and the limiters: after a restart the
// first observation of each certificate is a fresh baseline, which can
// only delay a flag by one request, never raise a false one.
//
// The peer address is evidence here, never authorisation (ADR-0012 B4):
// nothing is refused on it, and nothing is ever revoked on it.
type dualUseTracker struct {
	mu   sync.Mutex
	seen map[string]*dualUseEntry
}

type dualUseEntry struct {
	addr      string
	addrAt    time.Time
	version   string
	versionAt time.Time
}

func newDualUseTracker() *dualUseTracker {
	return &dualUseTracker{seen: make(map[string]*dualUseEntry)}
}

// observe records value (an address, or a version when version is true)
// for fingerprint at now, and reports the previous, different value if
// it was seen within dualUseWindow -- the other half of a dual use.
func (t *dualUseTracker) observe(fingerprint, value string, version bool, now time.Time) (previous string, dual bool) {
	if value == "" {
		return "", false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.seen) > dualUseTrackerPruneAt {
		for fp, e := range t.seen {
			if now.Sub(e.addrAt) > dualUseWindow && now.Sub(e.versionAt) > dualUseWindow {
				delete(t.seen, fp)
			}
		}
	}

	e, ok := t.seen[fingerprint]
	if !ok {
		e = &dualUseEntry{}
		t.seen[fingerprint] = e
	}
	last, lastAt := &e.addr, &e.addrAt
	if version {
		last, lastAt = &e.version, &e.versionAt
	}
	if *last != "" && *last != value && now.Sub(*lastAt) <= dualUseWindow {
		previous, dual = *last, true
	}
	*last, *lastAt = value, now
	return previous, dual
}

// recordDualUse writes ingest.credential_dual_use for canaryID through
// the coalescer (one row per kind of observation per coalescing
// interval, however many requests collide) and, on the same admitted
// write, stores the pair on the canary row for the dashboard
// (store.RecordCredentialDualUse). Never refuses the request and never
// revokes anything: a copied key must not become a button that silences
// the real canary (ADR-0012 B4).
func recordDualUse(ctx context.Context, database *db.DB, now func() time.Time, coalescer *auditCoalescer, canaryID string, kind store.DualUseKind, a, b string) {
	at := now().UTC()
	key, base := "ingest.credential_dual_use:addresses", fmt.Sprintf("credential in use from two addresses: %s and %s", a, b)
	if kind == store.DualUseVersions {
		key, base = "ingest.credential_dual_use:versions", fmt.Sprintf("credential in use by two agent builds: %q and %q", a, b)
	}
	write, occurrences := coalescer.admit(canaryID, key, at)
	if !write {
		return
	}
	if _, err := audit.Append(ctx, database, audit.Entry{
		Action:      "ingest.credential_dual_use",
		Target:      canaryID,
		Reason:      coalescedReason(base, occurrences, "observations"),
		TriggeredBy: canaryID,
		CreatedAt:   at,
	}); err != nil {
		slog.Error("ingest: record credential dual use", "canary", canaryID, "err", err)
	}
	if err := store.RecordCredentialDualUse(ctx, database, canaryID, kind, a, b, at); err != nil {
		slog.Error("ingest: store credential dual use", "canary", canaryID, "err", err)
	}
}

// observeAgentVersion is the version half of B4's dual-use signal,
// called by the heartbeat handlers (the one place an agent states its
// build) with the certificate requireBearerToken resolved.
//
// Issue #54's one exception (ADR-0012's B4 amendment): a version pair
// store.UpgradeWindowCovers says is exactly the agent's own accepted
// upgrade -- its old build and birdcage's, inside the five minutes the
// upgrade token opened -- is the old build disappearing, and is audited
// as ingest.credential_dual_use_upgrade instead of being flagged. Only
// this half asks: an address change is never covered, and neither is a
// third version. A failed lookup flags, never the other way round.
func (h *ingestHandler) observeAgentVersion(ctx context.Context, tok store.CanaryToken, version string) {
	cert, ok := clientCertFromContext(ctx)
	if !ok || h.dualUse == nil {
		return
	}
	now := h.now().UTC()
	prev, dual := h.dualUse.observe(cert.Fingerprint, version, true, now)
	if !dual {
		return
	}
	covered, err := store.UpgradeWindowCovers(ctx, h.db, tok.CanaryID, prev, version, now)
	if err != nil {
		slog.Error("ingest: check upgrade window; flagging the dual use", "canary", tok.CanaryID, "err", err)
		covered = false
	}
	if covered {
		h.recordKeyedAudit(ctx, tok.CanaryID, "ingest.credential_dual_use_upgrade", "ingest.credential_dual_use_upgrade",
			fmt.Sprintf("credential in use by two agent builds: %q and %q, inside this agent's upgrade window; not flagged", prev, version),
			"observations")
		return
	}
	recordDualUse(ctx, h.db, h.now, h.coalescer, tok.CanaryID, store.DualUseVersions, prev, version)
}
