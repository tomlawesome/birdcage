package snmp

import (
	"encoding/json"
	"fmt"
	"time"
)

// LogTypeSNMPCmd is OpenCanary's own logtype for one SNMP command --
// LOG_SNMP_CMD in opencanary/logger.py. internal/opencanary's
// ServiceForLogType already maps 13001 to the service name "snmp", so
// an event carrying it lands on the dashboard as an snmp alert with
// nothing downstream changed. That is the whole reason this package
// emits OpenCanary's shape rather than one of its own -- see
// internal/agent/portscan/event.go's doc comment for the fuller version
// of this argument, which applies here unchanged.
const LogTypeSNMPCmd = 13001

// openCanaryTimeLayout is the timestamp format OpenCanary writes into
// every event -- see internal/agent/portscan/event.go's constant of the
// same name for why.
const openCanaryTimeLayout = "2006-01-02 15:04:05.000000"

// wireEvent is one emitted event, in OpenCanary's own JSON shape.
// Same eight top-level fields as internal/agent/portscan's wireEvent,
// in the same alphabetical declaration order and for the same reason:
// encoding/json emits struct fields in declaration order, and
// OpenCanary emits json.dumps(logdata, sort_keys=True), so declaring
// fields already sorted is how a Go struct reproduces that.
//
// local_time and utc_time are both UTC and both the same value, for the
// same reason portscan's event carries that redundancy: OpenCanary's
// sanitizeLog sets both from datetime.utcnow().
type wireEvent struct {
	DstHost   string    `json:"dst_host"`
	DstPort   int       `json:"dst_port"`
	LocalTime string    `json:"local_time"`
	LogData   wireLogda `json:"logdata"`
	LogType   int       `json:"logtype"`
	NodeID    string    `json:"node_id"`
	SrcHost   string    `json:"src_host"`
	SrcPort   int       `json:"src_port"`
	UTCTime   string    `json:"utc_time"`
}

// wireLogda is the event's logdata object, with upstream's own field
// names verbatim: opencanary/modules/snmp.py's MiniSNMP.datagramReceived
// builds logdata = {"REQUESTS": requests, "COMMUNITY_STRING": community}
// -- requests a list of dotted OID strings, community the community
// string as received. Copied rather than renamed, so a consumer written
// against upstream's SNMP events needs no special case for ours.
type wireLogda struct {
	CommunityString string   `json:"COMMUNITY_STRING"`
	Requests        []string `json:"REQUESTS"`
}

// detection is one parsed SNMP v1/v2c request, ready to encode.
type detection struct {
	Src       string
	SrcPort   int
	Dst       string
	DstPort   int
	Community string
	OIDs      []string
}

// encode renders one parsed request as the exact bytes to hash into the
// event id and queue as the alert's raw value. Nothing re-serialises
// these bytes afterwards -- see portscan/event.go's encode for why this
// is the one and only place the wire form is decided, which applies
// here unchanged.
func encode(d detection, nodeID string, now time.Time) ([]byte, error) {
	stamp := now.UTC().Format(openCanaryTimeLayout)

	// A GetRequest with zero varbinds is a degenerate but valid
	// request; the OIDs list still belongs in the event as an empty
	// JSON array (matching Python's requests = []), never a JSON null.
	oids := d.OIDs
	if oids == nil {
		oids = []string{}
	}

	ev := wireEvent{
		DstHost:   d.Dst,
		DstPort:   d.DstPort,
		LocalTime: stamp,
		LogData: wireLogda{
			CommunityString: d.Community,
			Requests:        oids,
		},
		LogType: LogTypeSNMPCmd,
		NodeID:  nodeID,
		SrcHost: d.Src,
		SrcPort: d.SrcPort,
		UTCTime: stamp,
	}

	body, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("encode snmp event: %w", err)
	}
	return body, nil
}
