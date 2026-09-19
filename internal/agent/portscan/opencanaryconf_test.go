package portscan

import (
	"os"
	"path/filepath"
	"testing"
)

// shippedConf is the configuration the Mockingbird image actually
// carries. Reading the real file rather than a fixture is the point of
// this test: the listening-port set is derived from it at runtime, so a
// future change that enables a module -- or renames a key -- should show
// up here rather than as a canary alerting on its own services.
const shippedConf = "../../../build/mockingbird/opencanary.conf"

func TestReadsTheShippedOpenCanaryConf(t *testing.T) {
	t.Parallel()

	conf, err := readOpenCanaryConf(shippedConf)
	if err != nil {
		t.Fatalf("readOpenCanaryConf: %v", err)
	}
	if conf.NodeID != "mockingbird" {
		t.Errorf("node id = %q, want mockingbird (device.node_id in the shipped config)", conf.NodeID)
	}

	// Every port the image's own EXPOSE line names must be treated as
	// listening, or the canary alerts on its own honeypot traffic.
	for _, port := range []uint16{21, 22, 23, 69, 80, 1433, 3306, 3389, 5060, 6379} {
		if _, ok := conf.Ports[port]; !ok {
			t.Errorf("port %d is enabled in the shipped config but was not read as listening", port)
		}
	}

	// Disabled modules must not be: a SYN to 443, which nothing answers,
	// is a scan hit like any other.
	for _, port := range []uint16{443, 161, 123, 5000, 8080, 9418, 5355, 8001} {
		if _, ok := conf.Ports[port]; ok {
			t.Errorf("port %d belongs to a disabled module but was read as listening", port)
		}
	}
}

func TestReadOpenCanaryConfHandlesHostileValues(t *testing.T) {
	t.Parallel()

	// The file is operator-supplied and bind-mountable, so nothing in it
	// is trusted: a port outside the valid range, a wrong type, a
	// missing enabled flag. None of these may panic, and none may end up
	// in the listening set -- an attacker who could get port 9999 into
	// that set would have a port to scan from for free.
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.conf")
	body := `{
	  "device.node_id": "",
	  "good.enabled": true, "good.port": 4242,
	  "negative.enabled": true, "negative.port": -1,
	  "toobig.enabled": true, "toobig.port": 70000,
	  "zero.enabled": true, "zero.port": 0,
	  "stringport.enabled": true, "stringport.port": "22",
	  "stringenabled.enabled": "yes", "stringenabled.port": 9999,
	  "noflag.port": 8888,
	  "float.enabled": true, "float.port": 12.5
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	conf, err := readOpenCanaryConf(path)
	if err != nil {
		t.Fatalf("readOpenCanaryConf: %v", err)
	}
	if conf.NodeID != DefaultNodeID {
		t.Errorf("node id = %q, want the fallback %q for an empty device.node_id", conf.NodeID, DefaultNodeID)
	}
	if _, ok := conf.Ports[4242]; !ok {
		t.Error("the one valid enabled port was not read")
	}
	if len(conf.Ports) != 1 {
		t.Errorf("read %d ports (%v), want only the valid one", len(conf.Ports), conf.Ports)
	}
}

// TestReadOpenCanaryConfSurvivesAMissingFile: the detector carries on
// with an empty listening set rather than refusing to watch for scans,
// so this must return a usable config alongside its error.
func TestReadOpenCanaryConfSurvivesAMissingFile(t *testing.T) {
	t.Parallel()

	conf, err := readOpenCanaryConf(filepath.Join(t.TempDir(), "absent.conf"))
	if err == nil {
		t.Fatal("expected an error for a missing config file")
	}
	if conf.NodeID != DefaultNodeID {
		t.Errorf("node id = %q, want %q", conf.NodeID, DefaultNodeID)
	}
	if conf.Ports == nil {
		t.Error("Ports is nil; the caller must be able to range over it regardless")
	}
}
