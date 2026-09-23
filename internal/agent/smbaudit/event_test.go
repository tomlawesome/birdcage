package smbaudit

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/event"
	"github.com/tomlawesome/birdcage/internal/opencanary"
)

func TestEncodeProducesAnSMBAlert(t *testing.T) {
	ev, ok := Parse([]byte(`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`))
	if !ok {
		t.Fatal("Parse returned no event")
	}

	body, err := Encode(ev, "mockingbird")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// The fields birdcage's ingest endpoint actually reads, read the way
	// the agent reads them -- so this asserts the whole contract, not
	// just that some JSON came out.
	fields, err := event.ExtractFields(body)
	if err != nil {
		t.Fatalf("ExtractFields on the encoded event: %v", err)
	}
	if fields.Service != "smb" {
		t.Errorf("service = %q, want %q -- logtype %d must map to smb", fields.Service, "smb", LogTypeSMBFileOpen)
	}
	if fields.SourceIP != "172.21.0.3" {
		t.Errorf("src_host = %q, want the client address from the audit line", fields.SourceIP)
	}
	if fields.DestPort != SMBPort {
		t.Errorf("dst_port = %d, want %d", fields.DestPort, SMBPort)
	}

	var decoded struct {
		LogData map[string]string `json:"logdata"`
		SrcPort int               `json:"src_port"`
		DstHost string            `json:"dst_host"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode logdata: %v", err)
	}
	// SHARENAME and FILENAME by name: internal/store/visitor.go's
	// triedFor and scripts/e2e/smb.sh both read these exact keys.
	if got := decoded.LogData["SHARENAME"]; got != "public" {
		t.Errorf("logdata.SHARENAME = %q, want %q", got, "public")
	}
	if got := decoded.LogData["FILENAME"]; got != "/srv/shares/public/IT/vpn-setup.pdf" {
		t.Errorf("logdata.FILENAME = %q, want the audited path", got)
	}
	if got := decoded.LogData["AUDITEVENT"]; got != "file access" {
		t.Errorf("logdata.AUDITEVENT = %q, want %q", got, "file access")
	}
	if got := decoded.LogData["AUDITACTION"]; got != "close" {
		t.Errorf("logdata.AUDITACTION = %q, want %q", got, "close")
	}
	if got := decoded.LogData["USER"]; got != "root" {
		t.Errorf("logdata.USER = %q, want %q", got, "root")
	}
	if decoded.SrcPort != opencanary.NoDestPort {
		t.Errorf("src_port = %d, want %d (not reported)", decoded.SrcPort, opencanary.NoDestPort)
	}
	if decoded.DstHost != "" {
		t.Errorf("dst_host = %q, want empty -- the audit line does not carry it", decoded.DstHost)
	}
}

// TestEncodeKeysAreSorted: the id is the SHA-256 of these bytes verbatim,
// so the key order is part of the wire format and not a detail. Upstream
// OpenCanary emits json.dumps(..., sort_keys=True); a Go struct only
// matches that while its fields are declared in sorted order, which is
// the thing this checks and which nothing else would notice breaking.
func TestEncodeKeysAreSorted(t *testing.T) {
	body, err := Encode(Event{Kind: KindAccess}, "mockingbird")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	text := string(body)

	for _, group := range [][]string{
		{"dst_host", "dst_port", "local_time", "logdata", "logtype", "node_id", "src_host", "src_port", "utc_time"},
		{"AUDITACTION", "AUDITEVENT", "AUDITRESULT", "FILENAME", "NOTE", "SHARENAME", "USER"},
	} {
		if !sort.StringsAreSorted(group) {
			t.Fatalf("test bug: %v is not itself in sorted order", group)
		}
		prev := -1
		for _, key := range group {
			at := strings.Index(text, `"`+key+`":`)
			if at < 0 {
				t.Fatalf("key %q is missing from the encoded event:\n%s", key, text)
			}
			if at < prev {
				t.Errorf("key %q appears before the key that should precede it:\n%s", key, text)
			}
			prev = at
		}
	}
}

func TestEncodeEveryKind(t *testing.T) {
	lines := map[Kind]string{
		KindAccess:              `[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/x`,
		KindUnexpectedOperation: `[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|unlinkat|ok|/srv/shares/public/x`,
		KindUnparseable:         `[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|openat|ok|r|/srv/shares/public/x`,
		KindPanic:               `[2026/09/23 22:06:57.659891,  0]   PANIC (pid 1): sys_setgroups failed in 4.23.8`,
	}
	for kind, line := range lines {
		ev, ok := Parse([]byte(line))
		if !ok {
			t.Fatalf("%q: Parse returned no event", kind.Wording())
		}
		if ev.Kind != kind {
			t.Fatalf("%q: Parse gave kind %q", kind.Wording(), ev.Kind.Wording())
		}
		body, err := Encode(ev, "mockingbird")
		if err != nil {
			t.Fatalf("%q: Encode: %v", kind.Wording(), err)
		}
		// Every kind has to land as an smb alert: the wording is how the
		// four are told apart, never the logtype.
		fields, err := event.ExtractFields(body)
		if err != nil {
			t.Fatalf("%q: ExtractFields: %v", kind.Wording(), err)
		}
		if fields.Service != "smb" {
			t.Errorf("%q: service = %q, want smb", kind.Wording(), fields.Service)
		}
		var decoded struct {
			LogData map[string]string `json:"logdata"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("%q: decode: %v", kind.Wording(), err)
		}
		if got := decoded.LogData["AUDITEVENT"]; got != kind.Wording() {
			t.Errorf("%q: logdata.AUDITEVENT = %q", kind.Wording(), got)
		}
	}
}

// TestEncodeIsStableForTheSameEvent: the event id is the SHA-256 of these
// bytes, so two encodes of one Event at one instant have to be the same
// bytes or the queue would hold the same line twice under two ids.
func TestEncodeIsStableForTheSameEvent(t *testing.T) {
	ev, _ := Parse([]byte(`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/x`))
	first, err := Encode(ev, "mockingbird")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	second, err := Encode(ev, "mockingbird")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("two encodes differ:\n%s\n%s", first, second)
	}
	// And the id minting the agent uses has to accept them.
	if _, err := event.IDFromEmittedMessage(first); err != nil {
		t.Errorf("IDFromEmittedMessage on an encoded event: %v", err)
	}
}

// TestEncodeEscapesHostileContent: a user name is whatever the client
// sent. json.Marshal is what escapes it, and this is the test that says
// so out loud rather than leaving it to be assumed.
func TestEncodeEscapesHostileContent(t *testing.T) {
	ev := Event{
		Kind:     KindAccess,
		User:     "a\"b\\c\nd</script>",
		SourceIP: "172.21.0.3",
		Share:    "public",
		Path:     "/srv/shares/public/\x01",
	}
	body, err := Encode(ev, "mockingbird")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var decoded struct {
		LogData map[string]string `json:"logdata"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the encoded event is not valid JSON: %v\n%s", err, body)
	}
	if decoded.LogData["USER"] != ev.User {
		t.Errorf("USER did not survive the round trip: %q", decoded.LogData["USER"])
	}
	if decoded.LogData["FILENAME"] != ev.Path {
		t.Errorf("FILENAME did not survive the round trip: %q", decoded.LogData["FILENAME"])
	}
}

// TestEncodeIsStableAcrossReReads is the guarantee the saved position
// rests on: a line read a second time -- after a restart, or because the
// position was behind what had actually been sent -- has to produce the
// same bytes, so it produces the same id and the queue drops the second
// copy instead of birdcage storing the access twice.
func TestEncodeIsStableAcrossReReads(t *testing.T) {
	line := []byte(`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`)

	var ids []string
	for i := 0; i < 2; i++ {
		ev, ok := Parse(line)
		if !ok {
			t.Fatal("Parse returned no event")
		}
		body, err := Encode(ev, "mockingbird")
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		id, err := event.IDFromEmittedMessage(body)
		if err != nil {
			t.Fatalf("IDFromEmittedMessage: %v", err)
		}
		ids = append(ids, id)
	}
	if ids[0] != ids[1] {
		t.Errorf("the same line minted two ids: %s and %s", ids[0], ids[1])
	}
}
