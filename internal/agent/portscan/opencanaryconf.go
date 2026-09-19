package portscan

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// DefaultNodeID is what an event's node_id falls back to when the
// OpenCanary configuration could not be read or names none. It is the
// same literal build/mockingbird/opencanary.conf ships as
// device.node_id, so an agent whose config file is missing still emits
// events that group with the ones OpenCanary itself emitted on that box
// rather than under an empty or invented name.
const DefaultNodeID = "mockingbird"

// DefaultConfPath is where build/mockingbird/Dockerfile puts
// OpenCanary's configuration inside the Mockingbird image, and where
// OpenCanary itself reads it from.
const DefaultConfPath = "/etc/opencanaryd/opencanary.conf"

// openCanaryConf is what this package needs out of OpenCanary's own
// configuration: which ports it has a module listening on, and the node
// id it stamps into every event.
type openCanaryConf struct {
	NodeID string
	Ports  map[uint16]struct{}
}

// readOpenCanaryConf reads the ports OpenCanary is listening on out of
// its configuration file.
//
// Reading the config rather than probing the ports, or keeping a second
// hard-coded list here, is the point: the operator is told in
// docs/enrolment.md that bind-mounting their own opencanary.conf is how
// they change which services the canary presents, so any list this
// package kept of its own would be wrong the moment they did. A probe
// would be worse -- it would race OpenCanary's own startup and report
// every module as non-listening for the first seconds of a run, which is
// exactly when a scan of the box is most likely to be under way.
//
// The file is a flat JSON object of "<module>.<setting>" keys, so the
// rule is uniform: every "<module>.port" whose matching
// "<module>.enabled" is true. That covers the numbered modules
// (tcpbanner_1.port / tcpbanner_1.enabled) without naming them.
//
// Ports are collected without regard to protocol, so a TCP SYN to UDP
// port 69 is treated as landing on a listening port and does not count
// towards a scan. That is the cautious direction: OpenCanary's own
// portscan.ignore_ports is protocol-blind too, and a missed hit on one
// port of a scan that touches five is still a detected scan, whereas the
// other way round produces alerts for a canary talking to itself.
func readOpenCanaryConf(path string) (openCanaryConf, error) {
	conf := openCanaryConf{NodeID: DefaultNodeID, Ports: map[uint16]struct{}{}}

	raw, err := os.ReadFile(path)
	if err != nil {
		return conf, fmt.Errorf("read OpenCanary configuration: %w", err)
	}

	// The file is operator-supplied and may be bind-mounted from
	// anywhere, so it is parsed as untyped values and every field is
	// range-checked below rather than trusted into a typed struct: a
	// port of -1 or 70000, or an "enabled" that is a string, must be
	// ignored rather than crash the agent or wrap around into a real
	// port number.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return conf, fmt.Errorf("parse OpenCanary configuration: %w", err)
	}

	if rawID, ok := fields["device.node_id"]; ok {
		var id string
		if err := json.Unmarshal(rawID, &id); err == nil && id != "" {
			conf.NodeID = id
		}
	}

	for key, value := range fields {
		module, ok := strings.CutSuffix(key, ".port")
		if !ok {
			continue
		}
		var enabled bool
		if rawEnabled, present := fields[module+".enabled"]; present {
			if err := json.Unmarshal(rawEnabled, &enabled); err != nil {
				continue
			}
		}
		if !enabled {
			continue
		}
		var port int
		if err := json.Unmarshal(value, &port); err != nil {
			continue
		}
		if port <= 0 || port > 65535 {
			continue
		}
		conf.Ports[uint16(port)] = struct{}{}
	}

	return conf, nil
}
