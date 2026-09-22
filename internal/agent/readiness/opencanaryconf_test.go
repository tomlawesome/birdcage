package readiness

import (
	"os"
	"path/filepath"
	"testing"
)

// shippedConf is the configuration the Mockingbird image actually
// carries -- the same fixture internal/agent/portscan's own conf test
// reads, for the same reason: a future change that enables a module, or
// renames a key, should show up here rather than as a readiness check
// that silently stops covering it.
const shippedConf = "../../../build/mockingbird/opencanary.conf"

func TestModulePortsReadsTheShippedOpenCanaryConf(t *testing.T) {
	t.Parallel()

	ports, err := ModulePorts(shippedConf)
	if err != nil {
		t.Fatalf("ModulePorts: %v", err)
	}

	want := map[string]int{
		"ftp": 21, "ssh": 22, "telnet": 23, "tftp": 69, "http": 80,
		"mssql": 1433, "mysql": 3306, "rdp": 3389, "sip": 5060, "redis": 6379,
	}
	for module, port := range want {
		got, ok := ports[module]
		if !ok {
			t.Errorf("module %q is enabled in the shipped config but was not read", module)
			continue
		}
		if got != port {
			t.Errorf("module %q port = %d, want %d", module, got, port)
		}
	}

	// Disabled modules must not appear at all.
	for _, module := range []string{"https", "snmp", "ntp", "smb", "httpproxy", "git", "llmnr", "vnc", "tcpbanner", "tcpbanner_1"} {
		if _, ok := ports[module]; ok {
			t.Errorf("module %q is disabled in the shipped config but was read as enabled", module)
		}
	}
}

func TestModulePortsHandlesHostileValues(t *testing.T) {
	t.Parallel()

	// Same threat model as internal/agent/portscan's own conf parsing:
	// this file is operator-supplied and bind-mountable, so nothing in it
	// is trusted.
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.conf")
	body := `{
	  "good.enabled": true, "good.port": 4242,
	  "negative.enabled": true, "negative.port": -1,
	  "toobig.enabled": true, "toobig.port": 70000,
	  "zero.enabled": true, "zero.port": 0,
	  "stringport.enabled": true, "stringport.port": "22",
	  "stringenabled.enabled": "yes", "stringenabled.port": 9999,
	  "noflag.port": 8888,
	  "disabled.enabled": false, "disabled.port": 1111,
	  "float.enabled": true, "float.port": 12.5
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ports, err := ModulePorts(path)
	if err != nil {
		t.Fatalf("ModulePorts: %v", err)
	}
	if got, ok := ports["good"]; !ok || got != 4242 {
		t.Errorf("ports[good] = %d, %v; want 4242, true", got, ok)
	}
	if len(ports) != 1 {
		t.Errorf("read %d modules (%v), want only the one valid, enabled one", len(ports), ports)
	}
}

func TestModulePortsSurvivesAMissingFile(t *testing.T) {
	t.Parallel()

	_, err := ModulePorts(filepath.Join(t.TempDir(), "absent.conf"))
	if err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}
