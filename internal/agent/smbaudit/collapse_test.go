package smbaudit

import (
	"testing"
	"time"
)

// wall is the agent's own clock in these tests. Only Due reads it, so
// every test that is about grouping passes the same value throughout and
// the grouping is decided entirely by the timestamps in the lines.
var wall = time.Date(2026, 9, 23, 22, 0, 0, 0, time.UTC)

// capturedVisit is the five lines the real image wrote while a real
// smbclient fetched one file on 2026-09-23 -- the sequence issue #123 is
// about. Copied verbatim from /audit/smb.log.
var capturedVisit = []string{
	`[2026/09/23 22:01:53.984095,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
	`[2026/09/23 22:01:53.984907,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT`,
	`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
	`[2026/09/23 22:01:53.987460,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT`,
	`[2026/09/23 22:01:53.999607,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
}

// offerAll feeds every line through a fresh Collapser and returns the
// paths of every event that came out, in order -- including what was
// still held when the lines ran out, so a test never has to care whether
// the last window was closed by a later line or by the flush.
func offerAll(t *testing.T, c *Collapser, lines []string) []string {
	t.Helper()
	var out []Event
	for _, line := range lines {
		ev, ok := Parse([]byte(line))
		if !ok {
			t.Fatalf("Parse returned no event for %q", line)
		}
		out = append(out, c.Offer(ev, wall)...)
	}
	out = append(out, c.Flush()...)

	paths := make([]string, 0, len(out))
	for _, ev := range out {
		if ev.Kind == KindAccess {
			paths = append(paths, ev.Path)
		} else {
			paths = append(paths, ev.Kind.Wording())
		}
	}
	return paths
}

func TestCollapse(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name:  "captured: one file fetched is one alert naming the file",
			lines: capturedVisit,
			want:  []string{"/srv/shares/public/IT/vpn-setup.pdf"},
		},
		{
			name: "a directory listed and nothing opened is one alert naming the directory",
			lines: []string{
				`[2026/09/23 22:01:53.984095,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
				`[2026/09/23 22:01:53.984907,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT`,
			},
			want: []string{"/srv/shares/public/IT"},
		},
		{
			name: "two files opened in one second stay two alerts",
			lines: []string{
				`[2026/09/23 22:01:53.100000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
				`[2026/09/23 22:01:53.200000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT`,
				`[2026/09/23 22:01:53.300000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
				`[2026/09/23 22:01:53.400000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/HR`,
				`[2026/09/23 22:01:53.500000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/HR/salaries-2025.xlsx`,
			},
			want: []string{
				"/srv/shares/public/IT/vpn-setup.pdf",
				"/srv/shares/public/HR/salaries-2025.xlsx",
			},
		},
		{
			name: "the same file two seconds later is a second visit",
			lines: []string{
				`[2026/09/23 22:01:53.000000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
				`[2026/09/23 22:01:55.000000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
			},
			want: []string{
				"/srv/shares/public/IT/vpn-setup.pdf",
				"/srv/shares/public/IT/vpn-setup.pdf",
			},
		},
		{
			name: "the same second from two addresses is two visits",
			lines: []string{
				`[2026/09/23 22:01:53.100000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
				`[2026/09/23 22:01:53.200000,  1]   root|198.51.100.7|public|close|ok|/srv/shares/public`,
			},
			want: []string{"/srv/shares/public", "/srv/shares/public"},
		},
		{
			name: "the same second on two shares is two visits",
			lines: []string{
				`[2026/09/23 22:01:53.100000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
				`[2026/09/23 22:01:53.200000,  1]   root|172.21.0.3|backup|close|ok|/srv/shares/backup/router-config.txt`,
			},
			want: []string{
				"/srv/shares/public/IT/vpn-setup.pdf",
				"/srv/shares/backup/router-config.txt",
			},
		},
		{
			name: "the same second under two user names is two visits",
			lines: []string{
				`[2026/09/23 22:01:53.100000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
				`[2026/09/23 22:01:53.200000,  1]   admin|172.21.0.3|public|close|ok|/srv/shares/public`,
			},
			want: []string{"/srv/shares/public", "/srv/shares/public"},
		},
		{
			name: "a prefix is only a prefix at a path boundary",
			// A share directory called `pub` must not swallow `public`.
			lines: []string{
				`[2026/09/23 22:01:53.100000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/pub`,
				`[2026/09/23 22:01:53.200000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
			},
			want: []string{"/srv/shares/pub", "/srv/shares/public"},
		},
		{
			name: "an unexpected operation is never collapsed",
			lines: []string{
				`[2026/09/23 22:01:53.100000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
				`[2026/09/23 22:01:53.200000,  1]   root|172.21.0.3|public|unlinkat|ok|/srv/shares/public/IT/vpn-setup.pdf`,
				`[2026/09/23 22:01:53.300000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT`,
			},
			want: []string{"unexpected operation", "/srv/shares/public/IT"},
		},
		{
			name: "a panic is never collapsed, however many arrive",
			lines: []string{
				`[2026/09/23 22:06:57.659859,  0]   INTERNAL ERROR: sys_setgroups failed in smbd () () pid 1 (4.23.8)`,
				`[2026/09/23 22:06:57.659891,  0]   PANIC (pid 1): sys_setgroups failed in 4.23.8`,
			},
			want: []string{"server panic", "server panic"},
		},
		{
			name: "a line the parse refuses is never collapsed",
			lines: []string{
				`[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|public|openat|ok|r|/srv/shares/public/x`,
				`[2026/09/23 22:02:29.216100,  1]   root|172.21.0.3|public|openat|ok|r|/srv/shares/public/x`,
			},
			want: []string{"unparseable audit line", "unparseable audit line"},
		},
		{
			name: "an access with no readable timestamp cannot be windowed, so it is emitted",
			lines: []string{
				`[not a date,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
				`[not a date,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
			},
			want: []string{
				"/srv/shares/public/IT/vpn-setup.pdf",
				"/srv/shares/public/IT/vpn-setup.pdf",
			},
		},
		{
			name: "a clock that jumps backwards ends the visit rather than reordering it",
			lines: []string{
				`[2026/09/23 22:01:53.500000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
				`[2026/09/23 21:00:00.000000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT`,
			},
			want: []string{"/srv/shares/public/IT/vpn-setup.pdf", "/srv/shares/public/IT"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := offerAll(t, NewCollapser(CollapseConfig{}), tc.lines)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d event(s) %v, want %d %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("event %d = %q, want %q (all: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// TestCollapseIsTheSameOnASecondReading is the property the saved read
// position rests on: re-reading a stretch of the audit file has to group
// it the way the first pass did, or the re-read would mint new ids and
// birdcage would store the same visit twice.
func TestCollapseIsTheSameOnASecondReading(t *testing.T) {
	lines := append(append([]string{}, capturedVisit...),
		`[2026/09/23 22:01:56.000000,  1]   root|172.21.0.3|backup|close|ok|/srv/shares/backup/router-config.txt`,
		`[2026/09/23 22:01:56.100000,  1]   admin|198.51.100.7|scans|close|ok|/srv/shares/scans/x.pdf`,
	)

	first := offerAll(t, NewCollapser(CollapseConfig{}), lines)
	// A different agent clock on the second pass, to prove it plays no
	// part in the grouping.
	wallBefore := wall
	wall = wall.Add(11 * time.Minute)
	defer func() { wall = wallBefore }()
	second := offerAll(t, NewCollapser(CollapseConfig{}), lines)

	if len(first) != len(second) {
		t.Fatalf("the same lines grouped differently: %v then %v", first, second)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("the same lines grouped differently at %d: %v then %v", i, first, second)
		}
	}
}

func TestCollapseDueReleasesAQuietVisit(t *testing.T) {
	c := NewCollapser(CollapseConfig{})
	ev, ok := Parse([]byte(capturedVisit[2]))
	if !ok {
		t.Fatal("Parse returned no event")
	}
	if got := c.Offer(ev, wall); len(got) != 0 {
		t.Fatalf("an access was emitted straight away: %v", got)
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want the one open visit", c.Len())
	}

	// Not yet: the window has not gone quiet.
	if got := c.Due(wall.Add(DefaultCollapseWindow - time.Millisecond)); len(got) != 0 {
		t.Errorf("a visit was released early: %v", got)
	}
	got := c.Due(wall.Add(DefaultCollapseWindow))
	if len(got) != 1 || got[0].Path != "/srv/shares/public/IT/vpn-setup.pdf" {
		t.Fatalf("Due returned %v, want the one held access", got)
	}
	if c.Len() != 0 {
		t.Errorf("Len = %d after the visit was released, want 0", c.Len())
	}
	// And a second Due has nothing left to give.
	if got := c.Due(wall.Add(time.Hour)); len(got) != 0 {
		t.Errorf("Due returned a visit twice: %v", got)
	}
}

func TestCollapseCountsWhatItFoldedAway(t *testing.T) {
	c := NewCollapser(CollapseConfig{})
	offerAll(t, c, capturedVisit)
	// Five lines in, one alert out: four folded away.
	if got := c.Collapsed(); got != 4 {
		t.Errorf("Collapsed() = %d, want 4 of the five captured lines", got)
	}
}

func TestCollapseBoundsWhatItHolds(t *testing.T) {
	t.Run("too many paths in one visit", func(t *testing.T) {
		c := NewCollapser(CollapseConfig{MaxPathsPerGroup: 3})
		var emitted int
		for i := 0; i < 7; i++ {
			// Sibling paths, so none is a prefix of another and every
			// one of them is a real alert.
			line := `[2026/09/23 22:01:53.10000` + string(rune('0'+i)) +
				`,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/f` + string(rune('0'+i))
			ev, ok := Parse([]byte(line))
			if !ok {
				t.Fatalf("Parse returned no event for %q", line)
			}
			emitted += len(c.Offer(ev, wall))
		}
		emitted += len(c.Flush())
		if emitted != 7 {
			t.Errorf("%d events for 7 distinct files, want 7 -- the cap must flush, never drop", emitted)
		}
	})

	t.Run("too many visits at once", func(t *testing.T) {
		c := NewCollapser(CollapseConfig{MaxGroups: 2})
		var emitted int
		for i := 0; i < 5; i++ {
			line := `[2026/09/23 22:01:53.10000` + string(rune('0'+i)) +
				`,  1]   root|198.51.100.` + string(rune('1'+i)) + `|public|close|ok|/srv/shares/public/x`
			ev, ok := Parse([]byte(line))
			if !ok {
				t.Fatalf("Parse returned no event for %q", line)
			}
			emitted += len(c.Offer(ev, wall))
		}
		if c.Len() > 2 {
			t.Errorf("Len = %d, over the cap of 2", c.Len())
		}
		emitted += len(c.Flush())
		if emitted != 5 {
			t.Errorf("%d events for 5 separate visitors, want 5 -- the cap must flush the oldest, never drop it", emitted)
		}
	})
}

func TestNewCollapserRefusesNegativeConfiguration(t *testing.T) {
	for _, cfg := range []CollapseConfig{
		{Window: -time.Second},
		{MaxGroups: -1},
		{MaxPathsPerGroup: -1},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewCollapser(%+v) did not panic", cfg)
				}
			}()
			NewCollapser(cfg)
		}()
	}
}

func TestIsPathPrefix(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"/srv/shares/public", "/srv/shares/public/IT", true},
		{"/srv/shares/public", "/srv/shares/public/IT/vpn-setup.pdf", true},
		{"/srv/shares/pub", "/srv/shares/public", false},
		{"/srv/shares/public", "/srv/shares/public", false},
		{"/srv/shares/public/IT", "/srv/shares/public", false},
		{"/", "/srv", true},
		{"", "/srv", false},
		{"/srv/shares/public/", "/srv/shares/public/IT", true},
	}
	for _, tc := range tests {
		if got := isPathPrefix(tc.a, tc.b); got != tc.want {
			t.Errorf("isPathPrefix(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
