package poisoner

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/opencanary"
)

// stamp is a fixed instant with a non-zero microsecond field, so the
// timestamp format is actually exercised.
var stamp = time.Date(2026, 9, 23, 14, 5, 6, 123456000, time.UTC)

// TestEncodeEventBytes pins the emitted JSON exactly. The bytes matter twice
// over: they are what the event id is the SHA-256 of, so any change to them
// changes every id, and they are what internal/ingest parses.
func TestEncodeEventBytes(t *testing.T) {
	got, err := encode(Answer{
		Source:     "10.0.0.66",
		SourcePort: 5355,
		Protocol:   ProtocolLLMNR,
		Name:       "fs-lon-02",
		MAC:        "aa:bb:cc:dd:ee:ff",
		Local:      "10.0.0.5",
		LocalPort:  49876,
	}, "fs-lon-05", stamp)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Keys in sorted order, the way OpenCanary's json.dumps(sort_keys=True)
	// emits them -- the whole reason wireEvent declares its fields sorted.
	want := `{"dst_host":"10.0.0.5","dst_port":49876,` +
		`"local_time":"2026-09-23 14:05:06.123456",` +
		`"logdata":{"MAC":"aa:bb:cc:dd:ee:ff","NAME":"fs-lon-02","PROTOCOL":"llmnr"},` +
		`"logtype":30001,"node_id":"fs-lon-05","src_host":"10.0.0.66","src_port":5355,` +
		`"utc_time":"2026-09-23 14:05:06.123456"}`
	if string(got) != want {
		t.Errorf("bytes differ\n got %s\nwant %s", got, want)
	}
}

// TestEncodeEventCarriesEveryFactTheAlertNeeds is issue #86 decision 34's
// list: the answering IP, the protocol, the name it claimed, and the MAC.
func TestEncodeEventCarriesEveryFactTheAlertNeeds(t *testing.T) {
	raw, err := encode(Answer{
		Source:     "192.168.7.13",
		SourcePort: 137,
		Protocol:   ProtocolNBNS,
		Name:       "wpad",
		MAC:        "00:11:22:33:44:55",
		Local:      "192.168.7.4",
		LocalPort:  137,
	}, "canary", stamp)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var out struct {
		SrcHost string `json:"src_host"`
		LogType int    `json:"logtype"`
		LogData struct {
			MAC      string `json:"MAC"`
			NAME     string `json:"NAME"`
			PROTOCOL string `json:"PROTOCOL"`
		} `json:"logdata"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the emitted event does not parse: %v", err)
	}
	if out.SrcHost != "192.168.7.13" {
		t.Errorf("src_host = %q, want the answering address", out.SrcHost)
	}
	if out.LogData.PROTOCOL != string(ProtocolNBNS) {
		t.Errorf("PROTOCOL = %q, want %q", out.LogData.PROTOCOL, ProtocolNBNS)
	}
	if out.LogData.NAME != "wpad" {
		t.Errorf("NAME = %q, want the bait name", out.LogData.NAME)
	}
	if out.LogData.MAC != "00:11:22:33:44:55" {
		t.Errorf("MAC = %q, want the neighbour-table address", out.LogData.MAC)
	}
	if out.LogType != LogTypePoisonerAnswer {
		t.Errorf("logtype = %d, want %d", out.LogType, LogTypePoisonerAnswer)
	}

	// And nothing about the address the poisoner offered. That is the one
	// piece of a reply this agent must never use, so it is never decoded
	// and must never appear in an event either.
	for _, field := range []string{"answer", "offered", "address", "rdata", "ANSWER"} {
		if strings.Contains(string(raw), field) {
			t.Errorf("the event carries a %q field: the offered address must never be recorded", field)
		}
	}
}

// TestEncodeEventEmptyMAC is the ordinary case for an answer over IPv6, or
// from something more than one hop away: the field is present and empty, so
// a consumer never has to tell "no MAC" from "an older agent".
func TestEncodeEventEmptyMAC(t *testing.T) {
	raw, err := encode(Answer{Source: "fe80::1", Protocol: ProtocolMDNS, Name: "wpad"}, "canary", stamp)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(string(raw), `"MAC":""`) {
		t.Errorf("an answer with no MAC omitted the field: %s", raw)
	}
}

// TestServiceNameIsPoisoner ties the agent's logtype to the service name
// decision 34 settled, through the mapping the ingest side actually uses --
// so this fails if either end changes without the other.
func TestServiceNameIsPoisoner(t *testing.T) {
	if got := Service(); got != "poisoner" {
		t.Errorf("Service() = %q, want %q", got, "poisoner")
	}
	logType := LogTypePoisonerAnswer
	if got := opencanary.ServiceForLogType(&logType); got != "poisoner" {
		t.Errorf("ServiceForLogType(%d) = %q, want %q", logType, got, "poisoner")
	}
	// Not OpenCanary's own llmnr service: the alert is about a poisoner on
	// the segment, not about one of the three protocols used to find it.
	if got := Service(); got == "llmnr" {
		t.Error("the alert would appear as an llmnr hit")
	}
}
