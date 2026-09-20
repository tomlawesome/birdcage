package tlsconfig

import (
	"os"
	"slices"
	"testing"
)

func TestDashboardHostsExplicit(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     []string
		wantErr  bool
	}{
		{
			name:     "a single host",
			envValue: "dashboard.example.com",
			want:     []string{"dashboard.example.com"},
		},
		{
			name:     "several hosts and IPs, comma separated",
			envValue: "dashboard.example.com,192.168.11.30,10.0.0.5",
			want:     []string{"dashboard.example.com", "192.168.11.30", "10.0.0.5"},
		},
		{
			name:     "surrounding whitespace is trimmed",
			envValue: " dashboard.example.com , 192.168.11.30 ",
			want:     []string{"dashboard.example.com", "192.168.11.30"},
		},
		{
			name:     "blank entries from stray commas are dropped",
			envValue: "dashboard.example.com,,192.168.11.30,",
			want:     []string{"dashboard.example.com", "192.168.11.30"},
		},
		{
			name:     "only commas and whitespace is a configuration error, not an empty list",
			envValue: " , , ",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DashboardHosts(tt.envValue)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("DashboardHosts(%q) = %v, nil; want an error", tt.envValue, got)
				}
				if got != nil {
					t.Fatalf("DashboardHosts(%q) returned hosts %v alongside a fatal error; want nil so the caller can tell this apart from the best-effort case", tt.envValue, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DashboardHosts(%q): %v", tt.envValue, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("DashboardHosts(%q) = %v, want %v", tt.envValue, got, tt.want)
			}
		})
	}
}

// TestDashboardHostsDefaultIncludesLoopbackAndHostname exercises the
// unset-env-var path against the real machine (this package has no
// seam to fake os.Hostname/net.InterfaceAddrs, and injecting one for a
// three-line stdlib call is not worth the indirection) -- so it only
// asserts the parts that are true on any machine: the fixed loopback
// trio is always present, nothing is duplicated, and a real hostname,
// when the platform has one, is included too.
func TestDashboardHostsDefaultIncludesLoopbackAndHostname(t *testing.T) {
	got, err := DashboardHosts("")
	if err != nil {
		// Best-effort: net.InterfaceAddrs failing is reported, not fatal.
		// The loopback trio must still be there.
		t.Logf("DashboardHosts(\"\") returned a non-fatal error (environment-dependent): %v", err)
	}

	for _, want := range []string{"localhost", "127.0.0.1", "::1"} {
		if !slices.Contains(got, want) {
			t.Errorf("DashboardHosts(\"\") = %v, missing default %q", got, want)
		}
	}

	if hostname, hostErr := os.Hostname(); hostErr == nil && hostname != "" {
		if !slices.Contains(got, hostname) {
			t.Errorf("DashboardHosts(\"\") = %v, missing this machine's hostname %q", got, hostname)
		}
	}

	seen := map[string]bool{}
	for _, h := range got {
		if seen[h] {
			t.Errorf("DashboardHosts(\"\") = %v, contains duplicate %q", got, h)
		}
		seen[h] = true
	}
}

func TestDashboardHostsExplicitNeverConsultsTheMachine(t *testing.T) {
	// A regression guard for the "nothing is guessed" half of the
	// contract: an explicit value never gains the machine's hostname or
	// loopback trio, even though the unset path always includes them.
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		t.Skip("this machine has no hostname to use as a negative check")
	}

	got, err := DashboardHosts("dashboard.example.com")
	if err != nil {
		t.Fatalf("DashboardHosts: %v", err)
	}
	if slices.Contains(got, hostname) {
		t.Errorf("DashboardHosts(\"dashboard.example.com\") = %v; an explicit value must not also gain the machine hostname %q", got, hostname)
	}
	if slices.Contains(got, "127.0.0.1") {
		t.Errorf("DashboardHosts(\"dashboard.example.com\") = %v; an explicit value must not also gain the default loopback trio", got)
	}
}
