package smbaudit

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
//
// This is the third package in internal/agent with its own copy of this
// read. Extracting one shared reader is worth doing and is not done here:
// it would touch both of the others, which are outside this issue.
const (
	DefaultNodeID   = "mockingbird"
	DefaultConfPath = "/etc/opencanaryd/opencanary.conf"
)

// ReadNodeID reads OpenCanary's device.node_id out of its configuration
// file, so an event from this road carries the same node id as one
// OpenCanary reported itself. Exported because the reader that needs it
// lives in cmd/mockingbird, not in this package.
//
// The file is operator-supplied and may be bind-mounted from anywhere, so
// it is decoded as untyped values and checked, never trusted straight
// into a typed struct -- the same caution the other two readers take.
func ReadNodeID(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read OpenCanary configuration: %w", err)
	}

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
