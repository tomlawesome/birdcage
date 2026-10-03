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
