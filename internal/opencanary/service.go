// Package opencanary holds the OpenCanary wire-format conventions that
// birdcage's server-side ingest pipeline (internal/ingest) and the
// canary-side agent (internal/agent/event) both need to agree on: the
// log-type -> service-name mapping, and the sentinel values OpenCanary's
// JSON payload uses when it omits a field.
//
// This package has no dependencies outside the Go standard library. The
// agent binary that ships to canaries cannot import internal/ingest --
// that package pulls in internal/db, internal/store, internal/api and
// internal/stream, which would link the whole server into the agent. This
// package exists so both sides can share the mapping without that import.
package opencanary

// NoDestPort is the DestPort value used when OpenCanary reported no
// destination port at all, distinguishing "OpenCanary reported none" from
// port 0, which is a real (if unusual) port number.
const NoDestPort = -1

// NoSourceAddress is the SourceIP value used when OpenCanary reported no
// source host.
const NoSourceAddress = ""

// UnknownService is the fallback service name for a logtype that maps to
// no known service -- either because OpenCanary reported none, or because
// the value is outside every known range. An empty service is not treated
// as a failure: see issue #53 and the equivalent fallback in
// internal/ingest/batch.go, which maps an empty service to this same value
// before persisting an alert.
const UnknownService = "unknown"

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

// ServiceForLogType maps an OpenCanary logtype to a service name. Values
// outside every range -- including an absent logtype -- map to
// UnknownService rather than dropping the alert.
func ServiceForLogType(logType *int) string {
	if logType == nil {
		return UnknownService
	}
	for _, r := range logTypeRanges {
		if *logType >= r.min && *logType <= r.max {
			return r.service
		}
	}
	return UnknownService
}
