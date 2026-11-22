package event

import "testing"

func intPtr(i int) *int { return &i }

func TestExtractFields(t *testing.T) {
	tests := []struct {
		name       string
		message    []byte
		wantFields Fields
		wantErr    bool
	}{
		{
			name:    "ssh login attempt",
			message: []byte(`{"dst_host": "203.0.113.9", "dst_port": 22, "logdata": {"attempted_username": "root"}, "logtype": 4002, "node_id": "canary-1", "src_host": "198.51.100.5"}`),
			wantFields: Fields{
				SourceIP: "198.51.100.5",
				DestPort: 22,
				LogType:  intPtr(4002),
				Service:  "ssh",
			},
		},
		{
			name:    "absent dst_port defaults to -1, matching parse.go's convention",
			message: []byte(`{"logtype": 11001, "node_id": "canary-2", "src_host": "192.0.2.50"}`),
			wantFields: Fields{
				SourceIP: "192.0.2.50",
				DestPort: -1,
				LogType:  intPtr(11001),
				Service:  "ntp",
			},
		},
		{
			name:    "absent src_host defaults to empty, matching parse.go's convention",
			message: []byte(`{"dst_port": -1, "logdata": {}, "logtype": 1004, "node_id": "canary-3"}`),
			wantFields: Fields{
				SourceIP: "",
				DestPort: -1,
				LogType:  intPtr(1004),
				Service:  "base",
			},
		},
		{
			name:    "port 0 is a real port, not treated as absent",
			message: []byte(`{"dst_port": 0, "logtype": 5001, "node_id": "canary-4", "src_host": "203.0.113.1"}`),
			wantFields: Fields{
				SourceIP: "203.0.113.1",
				DestPort: 0,
				LogType:  intPtr(5001),
				Service:  "portscan",
			},
		},
		{
			name:    "no JSON object at all",
			message: []byte("not json"),
			wantErr: true,
		},
		{
			name:    "truncated JSON",
			message: []byte(`{"dst_port": 22, "logtype": 400`),
			wantErr: true,
		},
		{
			name:    "duplicate keys: last one wins, matching Go's own json decoder",
			message: []byte(`{"src_host": "203.0.113.1", "src_host": "203.0.113.2", "logtype": 1000}`),
			wantFields: Fields{
				SourceIP: "203.0.113.2",
				DestPort: -1,
				LogType:  intPtr(1000),
				Service:  "base",
			},
		},
		{
			name:    "invalid UTF-8 in a string field decodes without error",
			message: []byte(`{"src_host": "bad-` + "\xff\xfe" + `-host", "logtype": 1000}`),
			wantFields: Fields{
				SourceIP: "bad-��-host",
				DestPort: -1,
				LogType:  intPtr(1000),
				Service:  "base",
			},
		},
		{
			name:    "JSON payload that is not an object",
			message: []byte(`[1, 2, 3]`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractFields(tt.message)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ExtractFields(%q) succeeded, want error", tt.message)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractFields(%q) returned error: %v", tt.message, err)
			}
			if got.SourceIP != tt.wantFields.SourceIP {
				t.Errorf("SourceIP = %q, want %q", got.SourceIP, tt.wantFields.SourceIP)
			}
			if got.DestPort != tt.wantFields.DestPort {
				t.Errorf("DestPort = %d, want %d", got.DestPort, tt.wantFields.DestPort)
			}
			if (got.LogType == nil) != (tt.wantFields.LogType == nil) {
				t.Fatalf("LogType = %v, want %v", got.LogType, tt.wantFields.LogType)
			}
			if got.LogType != nil && *got.LogType != *tt.wantFields.LogType {
				t.Errorf("LogType = %d, want %d", *got.LogType, *tt.wantFields.LogType)
			}
			if got.Service != tt.wantFields.Service {
				t.Errorf("Service = %q, want %q", got.Service, tt.wantFields.Service)
			}
		})
	}
}

// TestExtractFieldsAcceptsNumbersAndNumericStrings is #251's spec: src_port,
// dst_port and logtype are each accepted as a JSON number or a numeric
// string; a value that is neither, or a negative port, is absent for that
// field only and never discards the other fields.
func TestExtractFieldsAcceptsNumbersAndNumericStrings(t *testing.T) {
	tests := []struct {
		name        string
		message     string
		wantSrcPort int
		wantDstPort int
		wantLogType *int
		wantService string
		wantSource  string
	}{
		{"src_port number", `{"dst_port": 22, "logtype": 4002, "src_host": "198.51.100.5", "src_port": 40000}`, 40000, 22, intPtr(4002), "ssh", "198.51.100.5"},
		{"src_port numeric string", `{"dst_port": 22, "logtype": 4002, "src_host": "198.51.100.5", "src_port": "40000"}`, 40000, 22, intPtr(4002), "ssh", "198.51.100.5"},
		{"dst_port numeric string", `{"dst_port": "22", "logtype": 4002, "src_host": "198.51.100.5", "src_port": 40000}`, 40000, 22, intPtr(4002), "ssh", "198.51.100.5"},
		{"logtype numeric string", `{"dst_port": 22, "logtype": "4002", "src_host": "198.51.100.5", "src_port": 40000}`, 40000, 22, intPtr(4002), "ssh", "198.51.100.5"},
		{"all three numeric strings", `{"dst_port": "22", "logtype": "4002", "src_host": "198.51.100.5", "src_port": "40000"}`, 40000, 22, intPtr(4002), "ssh", "198.51.100.5"},
		{"non-numeric src_port is absent only", `{"dst_port": 22, "logtype": 4002, "src_host": "198.51.100.5", "src_port": "abc"}`, 0, 22, intPtr(4002), "ssh", "198.51.100.5"},
		{"negative src_port string is absent only", `{"dst_port": 22, "logtype": 4002, "src_host": "198.51.100.5", "src_port": "-1"}`, 0, 22, intPtr(4002), "ssh", "198.51.100.5"},
		{"negative src_port number is absent only", `{"dst_port": 22, "logtype": 4002, "src_host": "198.51.100.5", "src_port": -1}`, 0, 22, intPtr(4002), "ssh", "198.51.100.5"},
		{"non-numeric dst_port is absent only", `{"dst_port": "abc", "logtype": 4002, "src_host": "198.51.100.5", "src_port": 40000}`, 40000, -1, intPtr(4002), "ssh", "198.51.100.5"},
		{"negative dst_port is absent only", `{"dst_port": "-5", "logtype": 4002, "src_host": "198.51.100.5", "src_port": 40000}`, 40000, -1, intPtr(4002), "ssh", "198.51.100.5"},
		{"non-numeric logtype is absent only", `{"dst_port": 22, "logtype": "abc", "src_host": "198.51.100.5", "src_port": 40000}`, 40000, 22, nil, "unknown", "198.51.100.5"},
		{"object logtype is absent only", `{"dst_port": 22, "logtype": {"a": 1}, "src_host": "198.51.100.5", "src_port": 40000}`, 40000, 22, nil, "unknown", "198.51.100.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractFields([]byte(tt.message))
			if err != nil {
				t.Fatalf("ExtractFields(%s) returned error: %v", tt.message, err)
			}
			if got.SourcePort != tt.wantSrcPort {
				t.Errorf("SourcePort = %d, want %d", got.SourcePort, tt.wantSrcPort)
			}
			if got.DestPort != tt.wantDstPort {
				t.Errorf("DestPort = %d, want %d", got.DestPort, tt.wantDstPort)
			}
			if (got.LogType == nil) != (tt.wantLogType == nil) || (got.LogType != nil && *got.LogType != *tt.wantLogType) {
				t.Errorf("LogType = %v, want %v", got.LogType, tt.wantLogType)
			}
			if got.Service != tt.wantService {
				t.Errorf("Service = %q, want %q", got.Service, tt.wantService)
			}
			if got.SourceIP != tt.wantSource {
				t.Errorf("SourceIP = %q, want %q", got.SourceIP, tt.wantSource)
			}
		})
	}
}

// TestExtractFieldsSMBAuditEventAsOpenCanaryEmits is #251's real case: the
// smb event has logtype 5000, dst_port 445 and "src_port": "-1", a string.
// It must still yield service smb, dest port 445 and the visitor's address.
func TestExtractFieldsSMBAuditEventAsOpenCanaryEmits(t *testing.T) {
	message := []byte(`{"dst_host": "", "dst_port": 445, "local_time": "2026-11-21 14:21:10.000000", "local_time_adjusted": "2026-11-21 14:21:10.000100", "logdata": {"AUDIT_ACTION": "openat", "AUDIT_EVENT": "file open", "AUDIT_RESULT": "ok", "FILENAME": "e2e-smb-marker.txt", "SHARENAME": "share", "USER": "nobody"}, "logtype": 5000, "node_id": "mockingbird", "src_host": "192.0.2.77", "src_port": "-1", "utc_time": "2026-11-21 14:21:10.000000"}`)
	got, err := ExtractFields(message)
	if err != nil {
		t.Fatalf("ExtractFields returned error: %v", err)
	}
	if got.Service != "smb" {
		t.Errorf("Service = %q, want smb", got.Service)
	}
	if got.DestPort != 445 {
		t.Errorf("DestPort = %d, want 445", got.DestPort)
	}
	if got.SourceIP != "192.0.2.77" {
		t.Errorf("SourceIP = %q, want 192.0.2.77", got.SourceIP)
	}
	if got.LogType == nil || *got.LogType != 5000 {
		t.Errorf("LogType = %v, want 5000", got.LogType)
	}
}
