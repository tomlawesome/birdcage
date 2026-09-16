package event

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// mustMarshal JSON-encodes v (typically a string) for splicing into a
// hand-built JSON fixture, so a fixture that needs to embed arbitrary text
// as a JSON value never hand-escapes it and risks building invalid JSON.
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal(%v): %v", v, err)
	}
	return b
}

// emittedEvent is a realistic OpenCanary json.dumps(logdata, sort_keys=True)
// string: three microsecond timestamps, a logtype, and a nested logdata
// object, matching the shape "The event id" describes.
const emittedEvent = `{"dst_host": "203.0.113.9", "dst_port": 22, "logdata": {"attempted_username": "root"}, "logtype": 4002, "local_time": "2026-09-15 10:00:00.123456", "local_time_adjusted": "2026-09-15 12:00:00.123456", "node_id": "canary-1", "src_host": "198.51.100.5", "src_port": 44123, "utc_time": "2026-09-15 10:00:00.123456"}`

func TestIDFromLogLine(t *testing.T) {
	tests := []struct {
		name    string
		line    []byte
		wantErr bool
	}{
		{
			name: "plain emitted JSON, no prefix",
			line: []byte(emittedEvent),
		},
		{
			name: "operator formatter prefix tolerated",
			line: []byte("2026-09-15T10:00:00Z canary-1 WARNING " + emittedEvent),
		},
		{
			name:    "no JSON object at all",
			line:    []byte("this line has no brace in it"),
			wantErr: true,
		},
		{
			name:    "truncated JSON is still hashed verbatim -- no parse happens here",
			line:    []byte(`{"logtype": 4002, "node_id": "canary-1`),
			wantErr: false,
		},
		{
			name:    "line over the cap is rejected before the brace scan",
			line:    append([]byte("{"), bytes.Repeat([]byte("x"), MaxLogLineBytes)...), // contains '{'; only the cap should fail it
			wantErr: true,
		},
		{
			name: "invalid UTF-8 bytes after the brace are hashed as-is",
			line: append([]byte(`{"src_host": "`), append([]byte{0xff, 0xfe}, []byte(`"}`)...)...),
		},
		{
			name: "duplicate-looking content is just bytes to this function",
			line: []byte(`{"a": 1, "a": 2}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, msg, err := IDFromLogLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("IDFromLogLine(%q) succeeded, want error", tt.line)
				}
				return
			}
			if err != nil {
				t.Fatalf("IDFromLogLine(%q) returned error: %v", tt.line, err)
			}
			if len(id) != 64 {
				t.Errorf("id = %q, want 64 lowercase hex characters", id)
			}
			if !bytes.HasPrefix(msg, []byte("{")) {
				t.Errorf("message = %q, want it to start with '{'", msg)
			}
			// Same input must always produce the same id -- the property
			// the whole durable-store design (issue #48, "Identifies") is
			// built on.
			id2, _, err2 := IDFromLogLine(tt.line)
			if err2 != nil || id2 != id {
				t.Errorf("IDFromLogLine is not deterministic: %q vs %q (err=%v)", id, id2, err2)
			}
		})
	}
}

func TestIDFromWebhookBody(t *testing.T) {
	// wrap builds a webhook body the way OpenCanary's WebhookHandler does:
	// the emitted string placed verbatim as the "message" field, which
	// Go's own JSON encoder escapes exactly as a spec-compliant encoder
	// (Python's included) must.
	wrap := func(message string) []byte {
		body, err := json.Marshal(map[string]string{"message": message})
		if err != nil {
			t.Fatalf("json.Marshal wrapper: %v", err)
		}
		return body
	}

	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{
			name: "well-formed wrapper",
			body: wrap(emittedEvent),
		},
		{
			name: "message contains characters that need escaping",
			body: wrap(`{"logdata": {"path": "/etc/passwd\n\t\"quoted\""}}`),
		},
		{
			name:    "no message field",
			body:    []byte(`{"other": "field"}`),
			wantErr: true,
		},
		{
			name:    "malformed wrapper JSON",
			body:    []byte(`{"message": "truncated`),
			wantErr: true,
		},
		{
			name:    "wrapper is not a JSON object",
			body:    []byte(`[1, 2, 3]`),
			wantErr: true,
		},
		{
			name:    "body over the cap is rejected without decoding",
			body:    append([]byte(`{"message": "`), bytes.Repeat([]byte("x"), MaxWebhookBodyBytes)...),
			wantErr: true,
		},
		{
			// The second value must itself be a validly-escaped JSON
			// string, so it is built with json.Marshal rather than
			// spliced in as raw text.
			name: "duplicate message key: last one wins, matching Go's own json decoder",
			body: []byte(`{"message": "first", "message": ` + string(mustMarshal(t, emittedEvent)) + `}`),
		},
		{
			name: "invalid UTF-8 inside the message string decodes without error",
			body: []byte(`{"message": "a\ud800b"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, msg, err := IDFromWebhookBody(tt.body)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("IDFromWebhookBody(%q) succeeded, want error", tt.body)
				}
				return
			}
			if err != nil {
				t.Fatalf("IDFromWebhookBody(%q) returned error: %v", tt.body, err)
			}
			if len(id) != 64 {
				t.Errorf("id = %q, want 64 lowercase hex characters", id)
			}
			if len(msg) == 0 {
				t.Errorf("message is empty")
			}
		})
	}
}

// TestTwoRoadsSameID proves issue #48's central property: the same
// OpenCanary hit, delivered by the webhook and read from the log file,
// resolves to the same event id -- "so the same hit arriving by both
// roads, or replayed after a restart, resolves to one stored alert."
func TestTwoRoadsSameID(t *testing.T) {
	logLine := emittedEvent // the log file carries the emitted string verbatim
	webhookBody, err := json.Marshal(map[string]string{"message": emittedEvent})
	if err != nil {
		t.Fatalf("json.Marshal webhook wrapper: %v", err)
	}

	logID, logMsg, err := IDFromLogLine([]byte(logLine))
	if err != nil {
		t.Fatalf("IDFromLogLine: %v", err)
	}
	webhookID, webhookMsg, err := IDFromWebhookBody(webhookBody)
	if err != nil {
		t.Fatalf("IDFromWebhookBody: %v", err)
	}

	if logID != webhookID {
		t.Errorf("log road id %q != webhook road id %q, want equal", logID, webhookID)
	}
	if !bytes.Equal(logMsg, webhookMsg) {
		t.Errorf("log road message %q != webhook road message %q, want equal", logMsg, webhookMsg)
	}
}

// TestTwoRoadsSameIDWithFormatterPrefixAndEscaping repeats the property
// with a realistic operator log formatter prefix on the log road, and a
// message that forces every JSON escape class (quote, backslash, control
// character, newline) on the webhook road, so the property is proven
// against content that actually exercises the escaping this package's
// doc comments describe rather than a clean fixture.
func TestTwoRoadsSameIDWithFormatterPrefixAndEscaping(t *testing.T) {
	message := `{"dst_port": 445, "logdata": {"note": "quote \" backslash \\ tab\ttail"}, "logtype": 5000, "node_id": "canary-2", "src_host": "192.0.2.1"}`
	logLine := "2026-09-15T10:00:00Z canary-2 WARNING " + message
	webhookBody, err := json.Marshal(map[string]string{"message": message})
	if err != nil {
		t.Fatalf("json.Marshal webhook wrapper: %v", err)
	}

	logID, _, err := IDFromLogLine([]byte(logLine))
	if err != nil {
		t.Fatalf("IDFromLogLine: %v", err)
	}
	webhookID, _, err := IDFromWebhookBody(webhookBody)
	if err != nil {
		t.Fatalf("IDFromWebhookBody: %v", err)
	}
	if logID != webhookID {
		t.Errorf("log road id %q != webhook road id %q, want equal", logID, webhookID)
	}

	// Sanity: the fixture actually forced escaping, or this test would
	// pass trivially without exercising the property it claims to.
	if !strings.Contains(string(webhookBody), `\"`) || !strings.Contains(string(webhookBody), `\\`) {
		t.Fatalf("webhook body %q does not contain the expected escapes; fixture is not exercising escaping", webhookBody)
	}
}
