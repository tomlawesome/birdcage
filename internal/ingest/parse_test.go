package ingest

import (
	"bytes"
	"testing"
)

// datagram builds a realistic OpenCanary wire-format message: <PRI>
// byte sequence, default formatter prefix, JSON payload, trailing NUL.
func datagram(pri, node, jsonBody string) []byte {
	var b bytes.Buffer
	b.WriteString("<" + pri + ">")
	b.WriteString("opencanaryd[12345:987654]: " + node + " WARNING ")
	b.WriteString(jsonBody)
	b.WriteByte(0)
	return b.Bytes()
}

func TestParseOpenCanaryMessage(t *testing.T) {
	tests := []struct {
		name       string
		raw        []byte
		instanceID string
		sourceIP   string
		destPort   int
		service    string
	}{
		{
			name: "ssh login attempt (logtype 4002)",
			raw: datagram("14", "opencanary-1",
				`{"dst_host": "", "dst_port": 22, "logdata": {"attempted_username": "root"}, `+
					`"logtype": 4002, "local_time": "2026-08-27 10:00:00.000000", "local_time_adjusted": "2026-08-27 12:00:00.000000", `+
					`"node_id": "opencanary-1", "src_host": "203.0.113.5", "src_port": 44123, "utc_time": "2026-08-27 10:00:00.000000"}`),
			instanceID: "opencanary-1",
			sourceIP:   "203.0.113.5",
			destPort:   22,
			service:    "ssh",
		},
		{
			name: "http get (logtype 3000)",
			raw: datagram("30", "canary-b",
				`{"dst_host": "canary-b", "dst_port": 80, "logdata": {"url_path": "/.env"}, `+
					`"logtype": 3000, "node_id": "canary-b", "src_host": "198.51.100.7"}`),
			instanceID: "canary-b",
			sourceIP:   "198.51.100.7",
			destPort:   80,
			service:    "http",
		},
		{
			name: "base ping (logtype 1004)",
			raw: datagram("14", "canary-c",
				`{"dst_host": "", "dst_port": -1, "logdata": {}, "logtype": 1004, "node_id": "canary-c"}`),
			instanceID: "canary-c",
			sourceIP:   "",
			destPort:   -1,
			service:    "base",
		},
		{
			name: "unmapped logtype maps to unknown, alert not dropped",
			raw: datagram("14", "canary-d",
				`{"dst_port": 1234, "logtype": 424242, "node_id": "canary-d", "src_host": "203.0.113.9"}`),
			instanceID: "canary-d",
			sourceIP:   "203.0.113.9",
			destPort:   1234,
			service:    "unknown",
		},
		{
			name: "mysql login attempt (single-value logtype 8001)",
			raw: datagram("14", "canary-e",
				`{"dst_port": 3306, "logtype": 8001, "node_id": "canary-e", "src_host": "192.0.2.4"}`),
			instanceID: "canary-e",
			sourceIP:   "192.0.2.4",
			destPort:   3306,
			service:    "mysql",
		},
		{
			name: "empty node_id falls back to unknown",
			raw: datagram("14", "",
				`{"dst_port": 23, "logtype": 6001, "node_id": "", "src_host": "198.51.100.20"}`),
			instanceID: "unknown",
			sourceIP:   "198.51.100.20",
			destPort:   23,
			service:    "telnet",
		},
		{
			name: "absent dst_port defaults to -1",
			raw: datagram("14", "canary-f",
				`{"logtype": 11001, "node_id": "canary-f", "src_host": "192.0.2.50"}`),
			instanceID: "canary-f",
			sourceIP:   "192.0.2.50",
			destPort:   -1,
			service:    "ntp",
		},
		{
			name:       "custom operator formatter prefix is tolerated",
			raw:        []byte("2026-08-27T10:00:00Z my-canary INFO {\"dst_port\": 445, \"logtype\": 5000, \"node_id\": \"canary-g\", \"src_host\": \"198.51.100.30\"}\n"),
			instanceID: "canary-g",
			sourceIP:   "198.51.100.30",
			destPort:   445,
			service:    "smb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alert, err := ParseOpenCanaryMessage(tt.raw)
			if err != nil {
				t.Fatalf("ParseOpenCanaryMessage returned error: %v", err)
			}
			if alert.InstanceID != tt.instanceID {
				t.Errorf("InstanceID = %q, want %q", alert.InstanceID, tt.instanceID)
			}
			if alert.SourceIP != tt.sourceIP {
				t.Errorf("SourceIP = %q, want %q", alert.SourceIP, tt.sourceIP)
			}
			if alert.DestPort != tt.destPort {
				t.Errorf("DestPort = %d, want %d", alert.DestPort, tt.destPort)
			}
			if alert.Service != tt.service {
				t.Errorf("Service = %q, want %q", alert.Service, tt.service)
			}
			if alert.Raw != string(tt.raw) {
				t.Errorf("Raw = %q, want the full original datagram unchanged", alert.Raw)
			}
			if !alert.ReceivedAt.IsZero() {
				t.Errorf("ReceivedAt = %v, want zero (set by the Server, not the parser)", alert.ReceivedAt)
			}
		})
	}
}

func TestParseOpenCanaryMessageRejections(t *testing.T) {
	oversized := make([]byte, MaxDatagramSize+1)
	for i := range oversized {
		oversized[i] = 'x'
	}

	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "no JSON object present",
			raw:  []byte("<14>opencanaryd[1:2]: canary WARNING this is not json at all\x00"),
		},
		{
			name: "truncated JSON",
			raw:  []byte("<14>opencanaryd[1:2]: canary WARNING {\"node_id\": \"canary\", \"logtype\": 400"),
		},
		{
			name: "JSON payload that is not an object",
			raw:  []byte("<14>prefix [1, 2, 3]"),
		},
		{
			name: "payload over the size cap",
			raw:  oversized,
		},
		{
			name: "empty input",
			raw:  []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseOpenCanaryMessage(tt.raw)
			if err == nil {
				t.Fatal("ParseOpenCanaryMessage succeeded, want an error")
			}
		})
	}
}

func TestServiceForLogType(t *testing.T) {
	tests := []struct {
		logType int
		service string
	}{
		{1000, "base"},
		{1006, "base"},
		{1007, "unknown"},
		{2000, "ftp"},
		{2001, "ftp"},
		{3000, "http"},
		{3003, "http"},
		{4000, "ssh"},
		{4002, "ssh"},
		{5000, "smb"},
		{5001, "portscan"},
		{5005, "portscan"},
		{6001, "telnet"},
		{6002, "telnet"},
		{7001, "httpproxy"},
		{8001, "mysql"},
		{9001, "mssql"},
		{9002, "mssql"},
		{9003, "mysql"},
		{10001, "tftp"},
		{11001, "ntp"},
		{12001, "vnc"},
		{13001, "snmp"},
		{14001, "rdp"},
		{15001, "sip"},
		{16001, "git"},
		{17001, "redis"},
		{18001, "tcpbanner"},
		{18005, "tcpbanner"},
		{19001, "llmnr"},
		{20001, "mongodb"},
		{99000, "user"},
		{99009, "user"},
		{0, "unknown"},
		{-1, "unknown"},
		{99999, "unknown"},
		{100000, "unknown"},
	}
	for _, tt := range tests {
		lt := tt.logType
		if got := serviceForLogType(&lt); got != tt.service {
			t.Errorf("serviceForLogType(%d) = %q, want %q", tt.logType, got, tt.service)
		}
	}
	var missing *int
	if got := serviceForLogType(missing); got != "unknown" {
		t.Errorf("serviceForLogType(nil) = %q, want %q", got, "unknown")
	}
}
