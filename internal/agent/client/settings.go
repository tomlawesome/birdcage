package client

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// SettingsHash is the sha256 hex of pairs' current key/value pairs,
// independent of map iteration order -- issue #124's own mechanism: an
// agent sends this on every heartbeat (its own currently-effective
// per-canary settings), and birdcage answers with the full settings
// block only when this differs from the hash of what it has stored.
//
// This is internal/store's own SettingsHash/hashSettingsPairs algorithm,
// duplicated rather than imported: an agent binary must never import
// internal/store (ADR-0008 decision 4, enforced by
// scripts/agent-deps-check.sh), so the two packages each carry their own
// copy of this one small function, the same way wireHeartbeat mirrors
// ingestHeartbeat in heartbeat.go above. Change one, change the other.
func SettingsHash(pairs map[string]string) string {
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(pairs[k])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
