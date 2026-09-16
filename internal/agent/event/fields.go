package event

import (
	"encoding/json"
	"fmt"
)

// Fields is the subset of one OpenCanary event that birdcage's ingest
// endpoint needs (internal/ingest/batch.go's ingestEvent: source_ip,
// dest_port, service; the raw string is the message bytes ExtractFields
// was given, which the caller already holds from IDFromLogLine or
// IDFromWebhookBody).
type Fields struct {
	// SourceIP is "" when OpenCanary reported none, matching
	// internal/ingest/parse.go's convention (its ParseOpenCanaryMessage
	// leaves SourceIP empty when src_host is absent) that
	// internal/ingest/batch.go's validateEvent already accepts.
	SourceIP string
	// DestPort is -1 when OpenCanary reported none, matching
	// internal/ingest/parse.go's convention (carried by the alerts table
	// since its first migration) that validateEvent already accepts.
	DestPort int
	// LogType is OpenCanary's own logtype value, nil when absent. It is
	// exposed as-is rather than mapped to a service name: the mapping
	// (internal/ingest/parse.go's serviceForLogType and its
	// logTypeRanges table) is unexported, internal/ingest is out of this
	// package's scope to modify, and the table is deliberately not
	// copied here -- see this change's report. Service is left "" until
	// that mapping is reachable from this package; an empty service is
	// not a new failure mode, since internal/ingest/batch.go's handleBatch
	// already treats one as "unknown" (issue #53), the same value
	// serviceForLogType returns for a logtype outside every range.
	LogType *int
	// Service is always "" from ExtractFields today; see LogType above.
	Service string
}

// eventPayload is the subset of OpenCanary's emitted JSON this package
// reads. It mirrors internal/ingest/parse.go's openCanaryPayload field
// for field (same wire shape -- both packages decode the same
// json.dumps(logdata, sort_keys=True) string), not a copy of any table:
// only the service-name mapping is off limits to duplicate, not ordinary
// field extraction.
type eventPayload struct {
	SrcHost string `json:"src_host"`
	DstPort *int   `json:"dst_port"`
	LogType *int   `json:"logtype"`
}

// ExtractFields decodes message -- the verbatim bytes IDFromLogLine or
// IDFromWebhookBody returned -- into the fields birdcage's ingest endpoint
// needs. message is hostile input (issue #48 threat model: "everything
// typed at an emulated service lands inside logdata, in both the log line
// and the webhook body"); this only ever decodes it into fixed-shape
// fields, never interprets or re-serialises it.
func ExtractFields(message []byte) (Fields, error) {
	var payload eventPayload
	if err := json.Unmarshal(message, &payload); err != nil {
		return Fields{}, fmt.Errorf("decode event JSON: %w", err)
	}

	f := Fields{
		SourceIP: payload.SrcHost,
		DestPort: -1,
		LogType:  payload.LogType,
	}
	if payload.DstPort != nil {
		f.DestPort = *payload.DstPort
	}
	return f, nil
}
