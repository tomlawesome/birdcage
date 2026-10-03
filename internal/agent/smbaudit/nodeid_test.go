package smbaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadNodeID(t *testing.T) {
	tests := []struct {
		name    string
		content string
		write   bool
		want    string
		wantErr string
	}{
		{
			name:    "the node id out of a real configuration",
			content: `{"device.node_id": "canary-07", "smb.enabled": false}`,
			write:   true,
			want:    "canary-07",
		},
		{
			name:    "no file at all",
			write:   false,
			wantErr: "read OpenCanary configuration",
		},
		{
			name:    "not JSON",
			content: "node_id = canary-07\n",
			write:   true,
			wantErr: "parse OpenCanary configuration",
		},
		{
			name:    "no node id in it",
			content: `{"smb.enabled": false}`,
			write:   true,
			wantErr: "has no device.node_id",
		},
		{
			name:    "an empty node id",
			content: `{"device.node_id": ""}`,
			write:   true,
			wantErr: "unusable device.node_id",
		},
		{
			name:    "a node id that is not a string",
			content: `{"device.node_id": 7}`,
			write:   true,
			wantErr: "unusable device.node_id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "opencanary.conf")
			if tc.write {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatalf("write configuration: %v", err)
				}
			}

			got, err := ReadNodeID(path)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ReadNodeID returned %q, want an error naming %q", got, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %q, want it to name %q", err, tc.wantErr)
				}
				if got != "" {
					t.Errorf("a failed read returned %q, want the empty string so a caller cannot use it by accident", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadNodeID: %v", err)
			}
			if got != tc.want {
				t.Errorf("node id = %q, want %q", got, tc.want)
			}
		})
	}
}
