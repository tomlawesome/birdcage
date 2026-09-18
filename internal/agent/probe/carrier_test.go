package probe

import "testing"

// TestCarriers_CoversTheDocumentedTable pins the carrier table against
// #46's brief: every service it lists a carrier for (other than vnc,
// deliberately excluded -- see carrier.go's comment) must resolve to a
// carrier here, so a future edit can't silently drop one.
func TestCarriers_CoversTheDocumentedTable(t *testing.T) {
	want := []string{
		"ssh", "ftp", "http", "telnet", "snmp", "tftp", "sip",
		"mysql", "mssql", "postgres", "redis", "rdp",
	}
	for _, svc := range want {
		if _, ok := carriers[svc]; !ok {
			t.Errorf("carriers[%q] missing", svc)
		}
	}
}

// TestCarriers_VNCHasNoCarrier documents, as a test rather than only a
// comment, that vnc is deliberately absent: classic RFB carries a
// credential only as a password-keyed challenge response, which cannot
// carry an arbitrary attacker-chosen marker.
func TestCarriers_VNCHasNoCarrier(t *testing.T) {
	if _, ok := carriers["vnc"]; ok {
		t.Error(`carriers["vnc"] exists; update this test and the comment in carrier.go if that is now intentional and correct`)
	}
}

// TestNotProbeable_MatchesTheOutOfScopeList pins #46's explicit
// exclusions: smb, portscan, llmnr and ntp must classify as
// StatusNotProbeable, never StatusNoCarrier, so a log reader can tell
// "ruled out" apart from "this build doesn't know how yet."
func TestNotProbeable_MatchesTheOutOfScopeList(t *testing.T) {
	want := []string{"smb", "portscan", "llmnr", "ntp"}
	for _, svc := range want {
		if !notProbeable[svc] {
			t.Errorf("notProbeable[%q] = false, want true", svc)
		}
		if _, ok := carriers[svc]; ok {
			t.Errorf("carriers[%q] exists for a service #46 rules out of scope", svc)
		}
	}
}
