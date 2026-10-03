// Package ingest parses OpenCanary alert payloads and persists the
// resulting alerts to SQLite.
package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/opencanary"
)

// MaxDatagramSize is the hard upper bound on a single incoming datagram
// (64 KiB, a realistic UDP ceiling). Larger inputs are rejected without
// being parsed.
const MaxDatagramSize = 64 * 1024

// Alert is one OpenCanary hit as stored in the alerts table.
type Alert struct {
	InstanceID string
	SourceIP   string
	Service    string
	Raw        string
	DestPort   int
	// ReceivedAt is birdcage's own UTC receipt time, never a value from
	// the (untrusted) payload. It is set by the Server at the moment the
	// datagram is received.
	ReceivedAt time.Time
}

type openCanaryPayload struct {
	NodeID  string `json:"node_id"`
	SrcHost string `json:"src_host"`
	DstPort *int   `json:"dst_port"`
	LogType *int   `json:"logtype"`
}

// ParseOpenCanaryMessage decodes one OpenCanary syslog datagram.
//
// OpenCanary ships its JSON log payload inside a syslog envelope (a <PRI>
// byte sequence, a formatter-controlled prefix, and usually a trailing
// NUL). The prefix is not matched: OpenCanary's docs explicitly let
// operators change the logger formatter, so the message is parsed from
// the first '{' byte onward. The whole original datagram is preserved
// verbatim in Alert.Raw for forensics.
func ParseOpenCanaryMessage(raw []byte) (Alert, error) {
	if len(raw) > MaxDatagramSize {
		return Alert{}, fmt.Errorf("datagram of %d bytes exceeds the %d-byte limit", len(raw), MaxDatagramSize)
	}
	start := bytes.IndexByte(raw, '{')
	if start < 0 {
		return Alert{}, errors.New("message contains no JSON object")
	}
	// Decode exactly one JSON value from the first '{', ignoring anything
	// after the closing brace — in particular the trailing NUL that
	// Python's SysLogHandler appends by default.
	var payload openCanaryPayload
	if err := json.NewDecoder(bytes.NewReader(raw[start:])).Decode(&payload); err != nil {
		return Alert{}, fmt.Errorf("decode JSON payload: %w", err)
	}

	alert := Alert{
		InstanceID: payload.NodeID,
		SourceIP:   payload.SrcHost,
		Service:    serviceForLogType(payload.LogType),
		Raw:        string(raw),
		DestPort:   opencanary.NoDestPort,
	}
	if alert.InstanceID == "" {
		alert.InstanceID = "unknown"
	}
	if payload.DstPort != nil {
		alert.DestPort = *payload.DstPort
	}
	return alert, nil
}

// serviceForLogType maps an OpenCanary logtype to a service name. Values
// outside every range — including an absent logtype — map to "unknown"
// rather than dropping the alert.
//
// The mapping itself lives in internal/opencanary, shared with the
// canary-side agent (internal/agent/event), which cannot import this
// package: internal/ingest pulls in internal/db, internal/store,
// internal/api and internal/stream, and linking those into the agent
// binary that ships to canaries is not acceptable.
func serviceForLogType(logType *int) string {
	return opencanary.ServiceForLogType(logType)
}
