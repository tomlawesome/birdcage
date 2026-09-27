package store

import "testing"

// TestAgentBehindBirdcage is issue #54's own table: dev/empty/garbage on
// either side must never read as behind, an agent strictly older than
// birdcage's release core is behind, a newer or equal agent is not, and
// build metadata (the "+<commit>" half) never affects the answer.
func TestAgentBehindBirdcage(t *testing.T) {
	cases := []struct {
		name            string
		agentVersion    string
		birdcageVersion string
		want            bool
	}{
		{"agent older major", "1.2.3", "2.0.0", true},
		{"agent older minor", "1.2.3", "1.3.0", true},
		{"agent older patch", "1.2.3", "1.2.4", true},
		{"agent newer major", "2.0.0", "1.2.3", false},
		{"agent newer minor", "1.3.0", "1.2.3", false},
		{"agent newer patch", "1.2.4", "1.2.3", false},
		{"equal core", "1.2.3", "1.2.3", false},
		{"equal core, different commit", "1.2.3+aaaaaaaa", "1.2.3+bbbbbbbb", false},
		{"older core, build metadata on both sides", "1.2.3+aaaaaaaa", "1.3.0+bbbbbbbb", true},
		{"agent dev", "dev", "1.2.3", false},
		{"birdcage dev", "1.2.3", "dev", false},
		{"both dev", "dev", "dev", false},
		{"agent empty", "", "1.2.3", false},
		{"birdcage empty", "1.2.3", "", false},
		{"both empty", "", "", false},
		{"agent garbage", "not-a-version", "1.2.3", false},
		{"birdcage garbage", "1.2.3", "not-a-version", false},
		{"agent missing patch", "1.2", "1.3.0", false},
		{"agent has pre-release suffix", "1.2.3-rc1", "1.3.0", false},
		{"agent has leading plus in a part", "1.+2.3", "1.3.0", false},
		{"agent negative", "-1.2.3", "1.2.3", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentBehindBirdcage(tc.agentVersion, tc.birdcageVersion); got != tc.want {
				t.Errorf("agentBehindBirdcage(%q, %q) = %v, want %v", tc.agentVersion, tc.birdcageVersion, got, tc.want)
			}
		})
	}
}

// TestParseReleaseVersionStripsBuildMetadata proves the "+<commit>" half
// -- scripts/release-version.sh's own stamp format -- never reaches the
// parsed core.
func TestParseReleaseVersionStripsBuildMetadata(t *testing.T) {
	v, ok := parseReleaseVersion("1.2.3+1a2b3c4d")
	if !ok {
		t.Fatal("parseReleaseVersion(1.2.3+1a2b3c4d) ok = false, want true")
	}
	if v != (releaseVersion{1, 2, 3}) {
		t.Errorf("parseReleaseVersion(1.2.3+1a2b3c4d) = %+v, want {1 2 3}", v)
	}
}
