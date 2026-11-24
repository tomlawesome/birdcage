package event

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/tomlawesome/birdcage/internal/opencanary"
)

// Fields is the subset of one OpenCanary event that birdcage's ingest
// endpoint needs (internal/ingest/batch.go's ingestEvent: source_ip,
// dest_port, service; the raw string is the message bytes ExtractFields
// was given, which the caller already holds from IDFromLogLine or
// IDFromWebhookBody).
type Fields struct {
	// SourceIP is "" when OpenCanary reported none (opencanary.NoSourceAddress),
	// matching internal/ingest/parse.go's convention (its
	// ParseOpenCanaryMessage leaves SourceIP empty when src_host is
	// absent) that internal/ingest/batch.go's validateEvent already
	// accepts.
	SourceIP string
	// DestPort is -1 when OpenCanary reported none (opencanary.NoDestPort),
	// matching internal/ingest/parse.go's convention (carried by the
	// alerts table since its first migration) that validateEvent already
	// accepts.
	DestPort int
	// LogType is OpenCanary's own logtype value, nil when absent. It is
	// kept alongside the derived Service below so a caller that wants the
	// raw value (for example to log an unmapped logtype) still has it.
	LogType *int
	// Service is the log-type -> service-name mapping from
	// internal/opencanary, the same mapping internal/ingest/parse.go
	// uses, shared between the two without this package importing
	// internal/ingest (which would pull internal/db, internal/store,
	// internal/api and internal/stream into the agent binary). It is
	// "unknown" (opencanary.UnknownService) when LogType is nil or
	// unmapped, matching internal/ingest/batch.go's own "" -> "unknown"
	// fallback (issue #53).
	Service string
	// SourcePort is the event's src_port, 0 when absent. With SourceIP it
	// identifies the TCP connection that produced the event (#239).
	SourcePort int
}

// eventPayload is the subset of OpenCanary's emitted JSON this package
// reads. It mirrors internal/ingest/parse.go's openCanaryPayload field
// for field (same wire shape -- both packages decode the same
// json.dumps(logdata, sort_keys=True) string), except that the integer
// fields here also accept numeric strings (see lenientInt). The service-name mapping
// itself is not duplicated here: both packages call internal/opencanary.
type eventPayload struct {
	SrcHost string     `json:"src_host"`
	SrcPort lenientInt `json:"src_port"`
	DstPort lenientInt `json:"dst_port"`
	LogType lenientInt `json:"logtype"`
}

// lenientInt reads a JSON number or a numeric string; any other value
// leaves it nil (absent) rather than failing the whole decode, because
// OpenCanary's smb module sends the port as a string ("src_port": "-1").
type lenientInt struct{ v *int }

func (l *lenientInt) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) != nil {
		s = string(b)
	}
	if n, err := strconv.Atoi(s); err == nil {
		l.v = &n
	}
	return nil
}

// port returns the value as a port, nil when absent or negative.
func (l lenientInt) port() *int {
	if l.v == nil || *l.v < 0 {
		return nil
	}
	return l.v
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
		DestPort: opencanary.NoDestPort,
		LogType:  payload.LogType.v,
		Service:  opencanary.ServiceForLogType(payload.LogType.v),
	}
	if p := payload.SrcPort.port(); p != nil {
		f.SourcePort = *p
	}
	if p := payload.DstPort.port(); p != nil {
		f.DestPort = *p
	}
	return f, nil
}
