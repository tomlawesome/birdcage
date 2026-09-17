package event

import (
	"encoding/json"
	"fmt"

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
}

// eventPayload is the subset of OpenCanary's emitted JSON this package
// reads. It mirrors internal/ingest/parse.go's openCanaryPayload field
// for field (same wire shape -- both packages decode the same
// json.dumps(logdata, sort_keys=True) string). The service-name mapping
// itself is not duplicated here: both packages call internal/opencanary.
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
		DestPort: opencanary.NoDestPort,
		LogType:  payload.LogType,
		Service:  opencanary.ServiceForLogType(payload.LogType),
	}
	if payload.DstPort != nil {
		f.DestPort = *payload.DstPort
	}
	return f, nil
}
