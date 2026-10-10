package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Sign-in settings of loadStartupConfig (issue #8, ADR-0016 decisions 3, 8
// and 12). The setting names are written out in full, not taken from
// constants, so the tests do not depend on what the code calls them.
const (
	testEnvAuthKeyFile        = "BIRDCAGE_AUTH_KEY_FILE"
	testEnvIPinfoTokenFile    = "BIRDCAGE_GEOIP_IPINFO_TOKEN_FILE"
	testEnvMaxMindAccountID   = "BIRDCAGE_GEOIP_MAXMIND_ACCOUNT_ID"
	testEnvMaxMindLicenceFile = "BIRDCAGE_GEOIP_MAXMIND_LICENCE_KEY_FILE"
)

// writeKeyFile writes n bytes of obviously fake key material to a new
// file and returns its path.
func writeKeyFile(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'k'}, n), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

// startupEnv is envMap plus a valid BIRDCAGE_AUTH_KEY_FILE, unless the
// caller's map sets that variable itself: start-up now refuses to run
// without a key, so every test of some other setting needs one.
func startupEnv(t *testing.T, m map[string]string) func(string) string {
	t.Helper()
	env := map[string]string{}
	for k, v := range m {
		env[k] = v
	}
	if _, set := env[testEnvAuthKeyFile]; !set {
		env[testEnvAuthKeyFile] = writeKeyFile(t, 32)
	}
	return envMap(env)
}

// TestLoadStartupConfigRefusesWithoutAuthKeyFile: with BIRDCAGE_AUTH_KEY_FILE
// unset, start-up refuses and the error names the setting.
func TestLoadStartupConfigRefusesWithoutAuthKeyFile(t *testing.T) {
	_, err := loadStartupConfig(envMap(map[string]string{}), discardLog(), discardLog(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("loadStartupConfig with BIRDCAGE_AUTH_KEY_FILE unset = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), testEnvAuthKeyFile) {
		t.Errorf("error = %q, want it to name %s", err.Error(), testEnvAuthKeyFile)
	}
}

// TestLoadStartupConfigRefusesMissingAuthKeyFile: a key file that does not
// exist is refused, and the error names the setting.
func TestLoadStartupConfigRefusesMissingAuthKeyFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such.key")
	_, err := loadStartupConfig(envMap(map[string]string{testEnvAuthKeyFile: missing}), discardLog(), discardLog(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("loadStartupConfig with a missing key file = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), testEnvAuthKeyFile) {
		t.Errorf("error = %q, want it to name %s", err.Error(), testEnvAuthKeyFile)
	}
}

// TestLoadStartupConfigRefusesShortAuthKeyFile: a key file under 32 bytes
// is refused (31 is the edge), and the error names the setting.
func TestLoadStartupConfigRefusesShortAuthKeyFile(t *testing.T) {
	for _, n := range []int{0, 1, 31} {
		path := writeKeyFile(t, n)
		_, err := loadStartupConfig(envMap(map[string]string{testEnvAuthKeyFile: path}), discardLog(), discardLog(), discardLog(), discardLog())
		if err == nil {
			t.Fatalf("loadStartupConfig with a %d-byte key file = nil error, want a refusal", n)
		}
		if !strings.Contains(err.Error(), testEnvAuthKeyFile) {
			t.Errorf("%d-byte key file: error = %q, want it to name %s", n, err.Error(), testEnvAuthKeyFile)
		}
	}
}

// TestLoadStartupConfigAcceptsAuthKeyFileOf32Bytes: a 32-byte key file is
// the shortest accepted; a longer one is accepted too.
func TestLoadStartupConfigAcceptsAuthKeyFileOf32Bytes(t *testing.T) {
	for _, n := range []int{32, 64} {
		path := writeKeyFile(t, n)
		if _, err := loadStartupConfig(envMap(map[string]string{testEnvAuthKeyFile: path}), discardLog(), discardLog(), discardLog(), discardLog()); err != nil {
			t.Errorf("loadStartupConfig with a %d-byte key file: %v", n, err)
		}
	}
}

// TestLoadStartupConfigCountryOffWithoutProvider: with no country provider
// configured, start-up succeeds (country is simply off).
func TestLoadStartupConfigCountryOffWithoutProvider(t *testing.T) {
	if _, err := loadStartupConfig(startupEnv(t, nil), discardLog(), discardLog(), discardLog(), discardLog()); err != nil {
		t.Fatalf("loadStartupConfig with no country provider: %v", err)
	}
}

// TestLoadStartupConfigMaxMindAccountWithoutLicenceKey: a MaxMind account
// ID with no licence-key file is refused, naming the missing setting.
func TestLoadStartupConfigMaxMindAccountWithoutLicenceKey(t *testing.T) {
	_, err := loadStartupConfig(startupEnv(t, map[string]string{
		testEnvMaxMindAccountID: "123456",
	}), discardLog(), discardLog(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("loadStartupConfig with a MaxMind account ID but no licence key file = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), testEnvMaxMindLicenceFile) {
		t.Errorf("error = %q, want it to name %s", err.Error(), testEnvMaxMindLicenceFile)
	}
}

// TestLoadStartupConfigMaxMindLicenceKeyWithoutAccount: a MaxMind
// licence-key file with no account ID is refused, naming the missing
// setting.
func TestLoadStartupConfigMaxMindLicenceKeyWithoutAccount(t *testing.T) {
	licence := filepath.Join(t.TempDir(), "maxmind.licence")
	if err := os.WriteFile(licence, []byte("fake-licence-key-for-tests\n"), 0o600); err != nil {
		t.Fatalf("write licence file: %v", err)
	}
	_, err := loadStartupConfig(startupEnv(t, map[string]string{
		testEnvMaxMindLicenceFile: licence,
	}), discardLog(), discardLog(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("loadStartupConfig with a MaxMind licence key file but no account ID = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), testEnvMaxMindAccountID) {
		t.Errorf("error = %q, want it to name %s", err.Error(), testEnvMaxMindAccountID)
	}
}

// TestLoadStartupConfigAcceptsCompleteCountryProviders: a complete provider
// (IPinfo token file, or MaxMind account ID with licence-key file) is
// accepted.
func TestLoadStartupConfigAcceptsCompleteCountryProviders(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "ipinfo.token")
	licence := filepath.Join(dir, "maxmind.licence")
	for _, p := range []string{token, licence} {
		if err := os.WriteFile(p, []byte("fake-secret-for-tests\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	cases := map[string]map[string]string{
		"ipinfo":  {testEnvIPinfoTokenFile: token},
		"maxmind": {testEnvMaxMindAccountID: "123456", testEnvMaxMindLicenceFile: licence},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadStartupConfig(startupEnv(t, env), discardLog(), discardLog(), discardLog(), discardLog()); err != nil {
				t.Errorf("loadStartupConfig with a complete %s provider: %v", name, err)
			}
		})
	}
}
