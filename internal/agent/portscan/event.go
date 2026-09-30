package portscan

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// LogTypePortSYN is OpenCanary's own logtype for a SYN seen against a
// port nothing is listening on -- LOG_PORT_SYN in opencanary/logger.py.
// internal/opencanary's ServiceForLogType already maps 5001 to the
// service name "portscan", so an event carrying it lands on the
// dashboard as a portscan alert with nothing downstream changed. That is
// the whole reason this package emits OpenCanary's shape rather than one
// of its own.
const LogTypePortSYN = 5001

// openCanaryTimeLayout is the timestamp format OpenCanary writes into
// every event: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f") in
// LoggerBase.sanitizeLog. %f is always six digits, zero-padded, which is
// Go's ".000000" rather than ".999999".
const openCanaryTimeLayout = "2006-01-02 15:04:05.000000"

// wireEvent is one emitted event, in OpenCanary's own JSON shape.
//
// Field order is alphabetical because encoding/json emits struct fields
// in declaration order, and OpenCanary emits json.dumps(logdata,
// sort_keys=True) -- so declaring them sorted is how a Go struct
// reproduces a Python sorted-keys dump. Adding a field means inserting
// it in sorted position, not appending it.
//
// local_time and utc_time are both UTC, and both are the same value.
// That is not a mistake here: sanitizeLog sets both from
// datetime.utcnow(), and the only field that carries real local time is
// local_time_adjusted. This package omits local_time_adjusted
// deliberately (issue #65 specified the field set) -- it is optional
// everywhere downstream, and a canary's own idea of local time is not
// evidence.
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

// wireLogda is the event's logdata object. OpenCanary's own portscan
// module fills logdata with the key=value tags it scraped out of an
// iptables log line, all of them strings; these three keep that
// convention -- COUNT is "7", not 7 -- so a consumer written against
// upstream's events needs no special case for ours.
type wireLogda struct {
	Count string `json:"COUNT"`
	Ports string `json:"PORTS"`
	Proto string `json:"PROTO"`
}

// encode renders one detection as the exact bytes that will be hashed
// into the event id and queued as the alert's raw value. Nothing
// re-serialises these bytes afterwards (internal/agent/event's package
// doc: Go's key order and escaping differ from Python's, and a
// parse-and-reserialise would re-mint ids), so this function is the one
// and only place the wire form is decided.
func encode(d detection, nodeID string, now time.Time) ([]byte, error) {
	stamp := now.UTC().Format(openCanaryTimeLayout)

	ev := wireEvent{
		DstHost:   d.Dst.String(),
		DstPort:   int(d.FirstPort),
		LocalTime: stamp,
		LogData: wireLogda{
			Count: strconv.Itoa(len(d.Ports)),
			Ports: joinPorts(d.Ports),
			Proto: d.Protocol,
		},
		LogType: LogTypePortSYN,
		NodeID:  nodeID,
		SrcHost: d.Src.String(),
		SrcPort: int(d.SrcPort),
		UTCTime: stamp,
	}

	body, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("encode portscan event: %w", err)
	}
	return body, nil
}

// maxPortsListed caps how many ports logdata.PORTS names. A scan of the
// whole port range would otherwise put 65535 numbers -- about 380 KiB --
// into one event, past event.MaxLogLineBytes and straight into the
// queue's byte cap. COUNT still reports the true total, so the event
// stays honest about the size of the scan while the list stays a sample
// of it.
const maxPortsListed = 64

func joinPorts(ports []uint16) string {
	listed := ports
	truncated := false
	if len(listed) > maxPortsListed {
		listed = listed[:maxPortsListed]
		truncated = true
	}
	var b strings.Builder
	for i, p := range listed {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(int(p)))
	}
	if truncated {
		b.WriteString(",...")
	}
	return b.String()
}
