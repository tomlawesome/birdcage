package snmp

import (
	"encoding/json"
	"fmt"
	"os"
)

// DefaultNodeID and DefaultConfPath mirror internal/agent/portscan's
// constants of the same name -- see that package's opencanaryconf.go
// for the reasoning, which applies here unchanged: DefaultNodeID is the
// literal build/mockingbird/opencanary.conf ships as device.node_id, so
// an agent whose config file is missing still emits events that group
// with the rest of the box's own.
const (
	DefaultNodeID   = "mockingbird"
	DefaultConfPath = "/etc/opencanaryd/opencanary.conf"
)

// readNodeID reads OpenCanary's device.node_id out of its configuration
// file. Unlike portscan's readOpenCanaryConf, this package needs
// nothing else out of that file: it opens its own UDP socket
// independent of anything opencanary.conf enables, so the ports/enabled
// scan portscan's reader does has nothing here to reuse.
func readNodeID(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read OpenCanary configuration: %w", err)
	}

	// Operator-supplied and possibly bind-mounted from anywhere, so
	// parsed as untyped values and range/type-checked below rather than
	// trusted into a typed struct -- the same caution portscan's reader
	// takes.
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
