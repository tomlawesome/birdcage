package readiness

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// DefaultConfPath is where build/mockingbird/Dockerfile puts OpenCanary's
// configuration inside the Mockingbird image, and where OpenCanary itself
// reads it from -- the same path internal/agent/portscan and
// internal/agent/snmp already use.
const DefaultConfPath = "/etc/opencanaryd/opencanary.conf"

// ModulePorts reads which ports OpenCanary is configured to listen on,
// keyed by module name, out of its own configuration file at path.
//
// This intentionally duplicates internal/agent/portscan's own conf
// parsing (readOpenCanaryConf) rather than importing that package:
// portscan needs a flat port set for its scan-detector ignore list, this
// package needs the module name attached to each port so a readiness
// failure can name which module it is, and the two packages have no other
// reason to depend on each other. Same parsing rule in both places,
// because it is dictated by the same file: a flat JSON object of
// "<module>.<setting>" keys, and every "<module>.port" whose matching
// "<module>.enabled" is true.
//
// The file is operator-supplied and may be bind-mounted from anywhere, so
// it is parsed as untyped values and every field is range-checked rather
// than trusted into a typed struct -- a port of -1 or 70000, or an
// "enabled" that is a string, is skipped rather than crashing this check
// or being dialed as a real port number.
func ModulePorts(path string) (map[string]int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OpenCanary configuration: %w", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("parse OpenCanary configuration: %w", err)
	}

	ports := map[string]int{}
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
		ports[module] = port
	}
	return ports, nil
}
