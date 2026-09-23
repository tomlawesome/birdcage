package probe

import "testing"

// TestCarriers_CoversTheDocumentedTable pins the carrier table against
// #46's brief: every service it lists a carrier for -- including vnc
// (challenge-marked), ntp and portscan (attributed), slice 2's addition
// -- must resolve to a carrier here, so a future edit can't silently
// drop one.
func TestCarriers_CoversTheDocumentedTable(t *testing.T) {
	want := []string{
		"ssh", "ftp", "http", "telnet", "snmp", "tftp", "sip",
		"mysql", "mssql", "postgres", "redis", "rdp",
		"vnc", "ntp", "portscan",
	}
	for _, svc := range want {
		if _, ok := carriers[svc]; !ok {
			t.Errorf("carriers[%q] missing", svc)
		}
	}
}

// TestNotProbeable_MatchesTheOutOfScopeList pins #46 slice 2's remaining
// exclusions: smb and llmnr must classify as StatusNotProbeable, never
// StatusNoCarrier, so a log reader can tell "ruled out" apart from "this
// build doesn't know how yet." vnc, ntp and portscan moved out of this
// set in slice 2 -- see carrier_test.go's other test.
func TestNotProbeable_MatchesTheOutOfScopeList(t *testing.T) {
	want := []string{"smb", "llmnr"}
	for _, svc := range want {
		if !notProbeable[svc] {
			t.Errorf("notProbeable[%q] = false, want true", svc)
		}
		if _, ok := carriers[svc]; ok {
			t.Errorf("carriers[%q] exists for a service #46 rules out of scope", svc)
		}
	}
}
