package poisoner

import (
	"encoding/json"
	"fmt"
	"os"
)

// DefaultNodeID and DefaultConfPath mirror internal/agent/portscan's and
// internal/agent/snmp's constants of the same name -- see portscan's
// opencanaryconf.go for the reasoning, which applies here unchanged:
// DefaultNodeID is the literal build/mockingbird/opencanary.conf ships as
// device.node_id, so an agent whose configuration file is missing still
// emits events that group with the rest of the box's own.
const (
	DefaultNodeID   = "mockingbird"
	DefaultConfPath = "/etc/opencanaryd/opencanary.conf"
)

// readNodeID reads OpenCanary's device.node_id out of its configuration
// file. Like internal/agent/snmp's reader, this package needs nothing else
// from that file -- it opens its own sockets, and what it asks for comes
// from its own settings.
//
// The node id does double duty here: it attributes the event, and it seeds
// the canary's own rhythm and derived names (see NewSchedule). That makes
// the fallback matter more than it does for the other roads: two canaries
// both falling back to DefaultNodeID would share a rhythm, which is the
// one thing decision 33's per-canary seeding exists to prevent. The caller
// is told through the returned warning, and that warning is worth acting
// on rather than noting.
func readNodeID(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read OpenCanary configuration: %w", err)
	}

	// Operator-supplied and possibly bind-mounted from anywhere, so parsed
	// as untyped values and checked below rather than trusted into a typed
	// struct -- the same caution the other two readers take.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", fmt.Errorf("parse OpenCanary configuration: %w", err)
	}

	rawID, ok := fields["device.node_id"]
	if !ok {
		return "", fmt.Errorf("OpenCanary configuration has no device.node_id")
	}
	var id string
	if err := json.Unmarshal(rawID, &id); err != nil || id == "" {
		return "", fmt.Errorf("OpenCanary configuration has an unusable device.node_id")
	}
	return id, nil
}
