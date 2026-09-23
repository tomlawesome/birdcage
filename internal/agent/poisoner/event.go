package poisoner

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/opencanary"
)

// LogTypePoisonerAnswer is the logtype a poisoner alert carries.
//
// Unlike internal/agent/portscan and internal/agent/snmp, which reuse
// OpenCanary's own LOG_PORT_SYN and LOG_SNMP_CMD, this one is birdcage's
// own: upstream has no logtype for "something answered a name that does
// not exist". Its own 19001 (LOG_LLMNR_QUERY_RESPONSE, service "llmnr")
// is the nearest, and it is the wrong one twice over -- it names one of
// the three protocols this detector uses, and issue #86 decision 34
// settled the service name as "poisoner", because what the operator is
// being told about is a poisoner on the segment, not a protocol.
//
// 30001 is chosen to sit well clear of upstream's own numbering in both
// directions: its service ranges run contiguously from 1000 to 20001 and
// then jump to the 99000-99009 user band, so a new upstream service would
// land near 21001, not here. internal/opencanary.ServiceForLogType maps it
// to "poisoner"; nothing else in this repository mints a logtype of its
// own, and anything that does should take the next value in this band and
// say so here.
const LogTypePoisonerAnswer = 30001

// openCanaryTimeLayout is the timestamp format OpenCanary writes into
// every event -- see internal/agent/portscan/event.go's constant of the
// same name for why this package reproduces it rather than using RFC 3339.
const openCanaryTimeLayout = "2006-01-02 15:04:05.000000"

// wireEvent is one emitted event, in OpenCanary's own JSON shape. Same
// eight top-level fields, in the same alphabetical declaration order, as
// internal/agent/portscan's and internal/agent/snmp's, and for the same
// reason: encoding/json emits struct fields in declaration order and
// OpenCanary emits json.dumps(logdata, sort_keys=True), so declaring them
// already sorted is how a Go struct reproduces a Python sorted-keys dump.
//
// local_time and utc_time are both UTC and both the same value, the same
// redundancy the other two roads carry, because OpenCanary's sanitizeLog
// sets both from datetime.utcnow().
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

// wireLogda is the event's logdata object: the four facts issue #86
// decision 34 asks an alert to name, minus the answering IP, which is
// already src_host.
//
// Upper-case keys because that is OpenCanary's own convention for logdata
// (COMMUNITY_STRING, REQUESTS, PORTS), and a consumer written against its
// events should not have to learn a second style for ours. Declared in
// sorted order for the reason wireEvent gives.
type wireLogda struct {
	// MAC is the answering host's hardware address, read passively from
	// the kernel's neighbour table. Empty when there is none to read --
	// see lookupMAC. Empty rather than absent, so a consumer never has to
	// tell "no MAC" from "an older agent that did not report one".
	MAC string `json:"MAC"`

	// NAME is the bait name that was answered for. This is the agent's own
	// record of what it asked, not the name the reply claims: the reply is
	// attacker-controlled and issue #86 design point 6 says to act only on
	// its source.
	NAME string `json:"NAME"`

	// PROTOCOL is which of the three protocols carried the answer.
	PROTOCOL string `json:"PROTOCOL"`
}

// Answer is one reply to a bait query: everything the alert needs and
// nothing the agent could be talked into acting on.
//
// There is deliberately no field for the address the poisoner offered. It
// is the one piece of a reply this agent must never use -- connecting to
// it is the trap -- so it is not decoded, not stored and not reported.
// What blocks an attacker later (#103) and what a lookback keys on (#111)
// is the pair of Source and MAC, which is where the answer came *from*.
type Answer struct {
	// Source is the address that answered.
	Source string

	// SourcePort is the port it answered from.
	SourcePort int

	// Protocol is which bait protocol it answered on.
	Protocol Protocol

	// Name is the bait name it claimed to be.
	Name string

	// MAC is the answering host's hardware address, or empty.
	MAC string

	// Local and LocalPort are this agent's own address and port on the
	// socket the answer arrived on -- the event's dst_host and dst_port,
	// matching what OpenCanary fills those from.
	Local     string
	LocalPort int
}

// encode renders one answer as the exact bytes to hash into the event id
// and queue as the alert's raw value. Nothing re-serialises these bytes
// afterwards: this is the one and only place the wire form is decided, the
// same contract portscan/event.go's encode states.
func encode(a Answer, nodeID string, now time.Time) ([]byte, error) {
	stamp := now.UTC().Format(openCanaryTimeLayout)
	body, err := json.Marshal(wireEvent{
		DstHost:   a.Local,
		DstPort:   a.LocalPort,
		LocalTime: stamp,
		LogData: wireLogda{
			MAC:      a.MAC,
			NAME:     a.Name,
			PROTOCOL: string(a.Protocol),
		},
		LogType: LogTypePoisonerAnswer,
		NodeID:  nodeID,
		SrcHost: a.Source,
		SrcPort: a.SourcePort,
		UTCTime: stamp,
	})
	if err != nil {
		return nil, fmt.Errorf("encode poisoner event: %w", err)
	}
	return body, nil
}

// serviceName is the name the dashboard will show this alert under. Read
// from internal/opencanary rather than written out again here, so a change
// to that mapping cannot leave this package claiming a name the ingest
// side no longer derives.
func serviceName() string {
	logType := LogTypePoisonerAnswer
	return opencanary.ServiceForLogType(&logType)
}
