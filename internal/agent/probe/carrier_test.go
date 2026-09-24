package probe

import "testing"

// TestCarriers_CoversTheDocumentedTable pins the carrier table against
// #46's brief: every marker-planting service it lists -- including vnc
// (challenge-marked) -- must resolve to a carrier here, so a future edit
// can't silently drop one. ntp and portscan (attributed) moved to their
// own table in slice 3; see TestAttributionCarriers_CoversTheDocumentedTable.
func TestCarriers_CoversTheDocumentedTable(t *testing.T) {
	want := []string{
		"ssh", "ftp", "http", "telnet", "snmp", "tftp", "sip",
		"mysql", "mssql", "postgres", "redis", "rdp",
		"vnc",
	}
	for _, svc := range want {
		if _, ok := carriers[svc]; !ok {
			t.Errorf("carriers[%q] missing", svc)
		}
	}
	for _, svc := range []string{"ntp", "portscan"} {
		if _, ok := carriers[svc]; ok {
			t.Errorf("carriers[%q] exists -- attributed services belong in attributionCarriers, not here", svc)
		}
	}
}

// TestAttributionCarriers_CoversTheDocumentedTable pins the two
// attributed-grade services (#46 slice 3) to attributionCarriers, the
// table probeOne checks before falling back to carriers.
func TestAttributionCarriers_CoversTheDocumentedTable(t *testing.T) {
	for _, svc := range []string{"ntp", "portscan"} {
		if _, ok := attributionCarriers[svc]; !ok {
			t.Errorf("attributionCarriers[%q] missing", svc)
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

// TestAgentHandled_IsThePoisonerAndNothingElse pins the other exclusion
// (#86 slice C): a poisoner target is not this package's to run, because
// the bait lookup is made by the live internal/agent/poisoner detector and
// this package may import internal/selftest only (see doc.go). It must
// classify as StatusAgentHandled rather than StatusNoCarrier, so a log
// reader can tell "the caller runs this" apart from "this build doesn't
// know how yet" -- the same distinction notProbeable exists for.
func TestAgentHandled_IsThePoisonerAndNothingElse(t *testing.T) {
	if !agentHandled["poisoner"] {
		t.Error(`agentHandled["poisoner"] = false, want true`)
	}
	if !AgentHandled("poisoner") {
		t.Error(`AgentHandled("poisoner") = false, want true`)
	}
	// Not also a carrier or ruled out: exactly one of the three tables may
	// claim a service, or probeOne's ordering decides it silently.
	if _, ok := carriers["poisoner"]; ok {
		t.Error(`carriers["poisoner"] exists for a service cmd/mockingbird runs itself`)
	}
	if notProbeable["poisoner"] {
		t.Error(`notProbeable["poisoner"] = true: the poisoner is probeable, just not here`)
	}
	// And nothing else is agent-handled, so a future addition has to be
	// deliberate.
	for svc := range carriers {
		if AgentHandled(svc) {
			t.Errorf("AgentHandled(%q) = true for a service with a carrier here", svc)
		}
	}
	for svc := range notProbeable {
		if AgentHandled(svc) {
			t.Errorf("AgentHandled(%q) = true for a service ruled out of scope", svc)
		}
	}
	if AgentHandled("made-up-service") {
		t.Error(`AgentHandled("made-up-service") = true`)
	}
}
