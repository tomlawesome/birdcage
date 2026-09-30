package smbaudit

import (
	"encoding/json"
	"fmt"
)

// LogTypeSMBFileOpen is OpenCanary's own logtype for an SMB file access
// -- LOG_SMB_FILE_OPEN in opencanary/logger.py. internal/opencanary's
// ServiceForLogType maps 5000, and only 5000, to the service name "smb"
// (5001-5005 are portscan), so every event this package emits carries it:
// birdcage stores them as smb alerts with nothing downstream changed,
// which is the same argument internal/agent/portscan/event.go and
// internal/agent/snmp/event.go make for emitting OpenCanary's shape
// rather than one of our own.
//
// The four kinds are told apart inside logdata by AUDITEVENT, not by a
// logtype of our own invention: a logtype outside upstream's table maps
// to "unknown" and the alert stops being an smb alert at all.
const LogTypeSMBFileOpen = 5000

// SMBPort is the port an SMB event is reported against. Fixed rather
// than read from the audit line, which does not carry it: the lure
// listens on 445 and only 445 (`smb ports = 445` in its smb.conf).
const SMBPort = 445

// openCanaryTimeLayout is the timestamp format OpenCanary writes into
// every event -- see internal/agent/portscan/event.go's constant of the
// same name for why this package reproduces it rather than using
// time.RFC3339. Parse rewrites the line's own timestamp into it.
const openCanaryTimeLayout = "2006-01-02 15:04:05.000000"

// wireEvent is one emitted event in OpenCanary's own JSON shape. Same
// eight top-level fields as internal/agent/portscan's and
// internal/agent/snmp's wireEvent, in the same alphabetical declaration
// order and for the same reason: encoding/json emits struct fields in
// declaration order and OpenCanary emits json.dumps(logdata,
// sort_keys=True), so declaring them already sorted is how a Go struct
// reproduces that.
//
// local_time and utc_time are both UTC and both the same value, matching
// upstream's sanitizeLog, which sets both from datetime.utcnow().
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

// wireLogda is the event's logdata object.
//
// SHARENAME and FILENAME are upstream OpenCanary's own key names for an
// SMB event, and they are here because birdcage already reads them:
// internal/store/visitor.go's triedFor takes an smb hit's SHARENAME for
// the dashboard's "what was tried" line, and scripts/e2e/smb.sh asserts
// on FILENAME. Renaming either would quietly break both.
//
// USER, AUDITACTION, AUDITRESULT and AUDITEVENT are ours. AUDITEVENT is
// the one a reader should branch on: it carries Kind.Wording, so "file
// access", "unexpected operation", "unparseable audit line" and "server
// panic" are distinguishable without inferring anything from which other
// fields happen to be empty.
type wireLogda struct {
	AuditAction string `json:"AUDITACTION"`
	AuditEvent  string `json:"AUDITEVENT"`
	AuditResult string `json:"AUDITRESULT"`
	Filename    string `json:"FILENAME"`
	Note        string `json:"NOTE"`
	Sharename   string `json:"SHARENAME"`
	User        string `json:"USER"`
}

// Encode renders one parsed line as the exact bytes to hash into the
// event id and to queue as the alert's raw value. Nothing re-serialises
// these bytes afterwards: this is the one and only place the wire form is
// decided, for the reason internal/agent/portscan/event.go's encode
// states -- an id is the SHA-256 of these bytes verbatim, so a second
// marshal of the same event with different key order would mint a
// different id for the same line.
//
// There is no clock argument, and that is the point: everything in the
// output comes from ev, so encoding the same line twice gives the same
// bytes and therefore the same id. That is what lets the caller re-read a
// line it had not confirmed yet -- after a restart, or after the saved
// position turned out to be behind -- without birdcage storing the same
// access twice. See Event.Timestamp.
func Encode(ev Event, nodeID string) ([]byte, error) {
	stamp := ev.Timestamp

	wire := wireEvent{
		// dst_host is empty: the audit line does not carry the address
		// the client connected to, and the agent cannot see it -- the
		// lure is a separate container that binds the port. Empty rather
		// than guessed; internal/agent/event.ExtractFields does not read
		// this field, and inventing an address would be inventing
		// evidence.
		DstHost:   "",
		DstPort:   SMBPort,
		LocalTime: stamp,
		LogData: wireLogda{
			AuditAction: ev.Operation,
			AuditEvent:  ev.Kind.Wording(),
			AuditResult: ev.Result,
			Filename:    ev.Path,
			Note:        ev.Message,
			Sharename:   ev.Share,
			User:        ev.User,
		},
		LogType: LogTypeSMBFileOpen,
		NodeID:  nodeID,
		SrcHost: ev.SourceIP,
		// src_port is unknown for the same reason dst_host is: the audit
		// line carries the client's address and not its port. -1, the
		// value internal/opencanary already uses for "not reported",
		// rather than 0, which is a real if unusual port number.
		SrcPort: noPort,
		UTCTime: stamp,
	}

	body, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode smb audit event: %w", err)
	}
	return body, nil
}

// noPort is the same -1 convention internal/opencanary.NoDestPort sets
// for a port OpenCanary did not report. Written out here rather than
// imported because it is used for the *source* port, which that constant
// does not name -- the convention is shared, the constant is not.
const noPort = -1
