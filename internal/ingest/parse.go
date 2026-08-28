// Package ingest receives OpenCanary UDP syslog datagrams, parses them,
// and persists the resulting alerts to SQLite.
package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
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
		DestPort:   -1,
	}
	if alert.InstanceID == "" {
		alert.InstanceID = "unknown"
	}
	if payload.DstPort != nil {
		alert.DestPort = *payload.DstPort
	}
	return alert, nil
}

// logTypeRange is an inclusive range of OpenCanary logtype values mapping
// to one service name.
type logTypeRange struct {
	min     int
	max     int
	service string
}

// logTypeRanges mirrors the LOG_* constants in upstream OpenCanary's
// logger.py LoggerBase, grouped as ranges. Verified against the upstream
// repository; see issue #19 for the source table.
var logTypeRanges = []logTypeRange{
	{1000, 1006, "base"},
	{2000, 2001, "ftp"},
	{3000, 3003, "http"},
	{4000, 4002, "ssh"},
	{5000, 5000, "smb"},
	{5001, 5005, "portscan"},
	{6001, 6002, "telnet"},
	{7001, 7001, "httpproxy"},
	{8001, 8001, "mysql"},
	{9001, 9002, "mssql"},
	{9003, 9003, "mysql"},
	{10001, 10001, "tftp"},
	{11001, 11001, "ntp"},
	{12001, 12001, "vnc"},
	{13001, 13001, "snmp"},
	{14001, 14001, "rdp"},
	{15001, 15001, "sip"},
	{16001, 16001, "git"},
	{17001, 17001, "redis"},
	{18001, 18005, "tcpbanner"},
	{19001, 19001, "llmnr"},
	{20001, 20001, "mongodb"},
	{99000, 99009, "user"},
}

// serviceForLogType maps an OpenCanary logtype to a service name. Values
// outside every range — including an absent logtype — map to "unknown"
// rather than dropping the alert.
func serviceForLogType(logType *int) string {
	if logType == nil {
		return "unknown"
	}
	for _, r := range logTypeRanges {
		if *logType >= r.min && *logType <= r.max {
			return r.service
		}
	}
	return "unknown"
}
