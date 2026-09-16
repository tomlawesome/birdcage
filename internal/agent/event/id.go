package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// IDFromLogLine computes the event id from one line tailed out of
// OpenCanary's log file, and returns the verbatim message bytes the id
// was computed over -- the caller needs those same bytes again to extract
// fields and to store as the alert's raw value, and re-locating the same
// substring a second time would just duplicate this work.
//
// line must not include its trailing line terminator (bufio.Scanner's
// default split function already strips it); the id is SHA-256, lowercase
// hex, of line from the first '{' byte to the end, taken verbatim -- never
// parsed and re-serialised (issue #48, "The event id").
func IDFromLogLine(line []byte) (id string, message []byte, err error) {
	if len(line) > MaxLogLineBytes {
		return "", nil, fmt.Errorf("log line of %d bytes exceeds the %d-byte cap", len(line), MaxLogLineBytes)
	}
	start := bytes.IndexByte(line, '{')
	if start < 0 {
		return "", nil, errors.New("log line contains no JSON object")
	}
	message = line[start:]
	return hashHex(message), message, nil
}

// IDFromWebhookBody computes the event id from one webhook POST body
// OpenCanary's WebhookHandler sent, and returns the verbatim message
// bytes the id was computed over -- the same bytes IDFromLogLine returns
// for the same event once unwrapped, which is the property this
// package's tests prove (issue #48, "The event id").
//
// The wrapper JSON-string-escapes the message. encoding/json is used to
// decode only that one field: decoding a JSON string literal recovers its
// original text exactly, so this is not the parse-and-reserialise the
// spec forbids -- nothing is re-encoded, and every other field in the
// wrapper is ignored rather than round-tripped.
func IDFromWebhookBody(body []byte) (id string, message []byte, err error) {
	if len(body) > MaxWebhookBodyBytes {
		return "", nil, fmt.Errorf("webhook body of %d bytes exceeds the %d-byte cap", len(body), MaxWebhookBodyBytes)
	}
	var wrapper struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return "", nil, fmt.Errorf("decode webhook wrapper: %w", err)
	}
	if wrapper.Message == "" {
		return "", nil, errors.New("webhook wrapper has no message field")
	}
	message = []byte(wrapper.Message)
	return hashHex(message), message, nil
}

// hashHex returns the lowercase hex SHA-256 digest of b -- the event id
// format issue #32 already validates on the way in
// (internal/ingest/batch.go's eventIDPattern: "exactly 64 lowercase hex
// characters").
func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
