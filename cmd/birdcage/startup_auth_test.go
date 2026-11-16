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

// TestLoadStartupConfigPassesAuthKeyFileBytesOn: the key file's bytes
// reach the sign-in layer's Config.Key exactly as written -- not empty,
// not trimmed, not altered. The key has a leading space and a trailing
// newline, as a key made from /dev/urandom can, and every byte differs
// from its neighbour so a shifted or truncated copy shows.
func TestLoadStartupConfigPassesAuthKeyFileBytesOn(t *testing.T) {
	want := []byte{' '}
	for b := byte(1); len(want) < 39; b++ {
		want = append(want, b)
	}
	want = append(want, '\n')
	path := filepath.Join(t.TempDir(), "auth.key")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	cfg, err := loadStartupConfig(envMap(map[string]string{testEnvAuthKeyFile: path}), discardLog(), discardLog(), discardLog(), discardLog())
	if err != nil {
		t.Fatalf("loadStartupConfig with a 40-byte key file: %v", err)
	}
	if !bytes.Equal(cfg.auth.Key, want) {
		t.Errorf("cfg.auth.Key = %q, want the key file's bytes %q", cfg.auth.Key, want)
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

// Setting names for the passkey rule (issue #8 review fix 9, ADR-0016
// decision 5), written out in full like the ones above.
const (
	testEnvPublicURL        = "BIRDCAGE_PUBLIC_URL"
	testEnvAdminPasskeyRule = "BIRDCAGE_AUTH_ADMIN_PASSKEY"
)

// TestLoadStartupConfigRefusesRequiredPasskeyWhereBrowsersCannotMakeOne is
// review fix 9: BIRDCAGE_AUTH_ADMIN_PASSKEY=required with a
// BIRDCAGE_PUBLIC_URL that browsers cannot make passkeys for (an IP address,
// or plain http on a name other than localhost) is refused at start-up, and
// the error names both settings.
func TestLoadStartupConfigRefusesRequiredPasskeyWhereBrowsersCannotMakeOne(t *testing.T) {
	for _, publicURL := range []string{
		"https://192.0.2.10",
		"https://192.0.2.10:8443",
		"https://[2001:db8::1]",
		"http://127.0.0.1:8080",
		"http://192.0.2.10",
		"http://birdcage.example.net",
		"http://birdcage.example.net:8080",
	} {
		t.Run(publicURL, func(t *testing.T) {
			_, err := loadStartupConfig(startupEnv(t, map[string]string{
				testEnvPublicURL:        publicURL,
				testEnvAdminPasskeyRule: "required",
			}), discardLog(), discardLog(), discardLog(), discardLog())
			if err == nil {
				t.Fatalf("loadStartupConfig with %s=required and %s=%s = nil error, want a refusal", testEnvAdminPasskeyRule, testEnvPublicURL, publicURL)
			}
			for _, name := range []string{testEnvAdminPasskeyRule, testEnvPublicURL} {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("error = %q, want it to name %s", err.Error(), name)
				}
			}
		})
	}
}

// TestLoadStartupConfigAcceptsPasskeyRuleWhereBrowsersCanMakeOne: the
// refusal above is narrow. "required" is accepted on an https domain name
// and on localhost; "optional", or no setting, is accepted on any address.
func TestLoadStartupConfigAcceptsPasskeyRuleWhereBrowsersCanMakeOne(t *testing.T) {
	cases := []struct {
		name     string
		override string
		url      string
	}{
		{"required on an https domain name", "required", "https://birdcage.example.net"},
		{"required on an https domain name with a port", "required", "https://birdcage.example.net:8443"},
		{"required on plain http localhost", "required", "http://localhost:8080"},
		{"optional on an IP address", "optional", "https://192.0.2.10"},
		{"optional on plain http", "optional", "http://birdcage.example.net"},
		{"no setting on an IP address", "", "https://192.0.2.10"},
		{"no setting on plain http", "", "http://birdcage.example.net"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{testEnvPublicURL: tc.url}
			if tc.override != "" {
				env[testEnvAdminPasskeyRule] = tc.override
			}
			if _, err := loadStartupConfig(startupEnv(t, env), discardLog(), discardLog(), discardLog(), discardLog()); err != nil {
				t.Errorf("loadStartupConfig with %s=%q and %s=%s: %v", testEnvAdminPasskeyRule, tc.override, testEnvPublicURL, tc.url, err)
			}
		})
	}
}

// TestLoadStartupConfigMissingAuthKeyFileSaysHowToMakeAndMountOne is review
// fix 12: a key file that does not exist is refused with the same help the
// unset and too-short cases give. That is how to make one
// (`head -c 32 /dev/urandom > key`) and that it must be mounted, and the
// error still names the setting.
func TestLoadStartupConfigMissingAuthKeyFileSaysHowToMakeAndMountOne(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such.key")
	_, err := loadStartupConfig(envMap(map[string]string{testEnvAuthKeyFile: missing}), discardLog(), discardLog(), discardLog(), discardLog())
	if err == nil {
		t.Fatal("loadStartupConfig with a missing key file = nil error, want a refusal")
	}
	// The path is taken out first: a temp directory named after this test
	// would otherwise supply the word "mount" by itself.
	msg := strings.ReplaceAll(err.Error(), missing, "<path>")
	if !strings.Contains(msg, testEnvAuthKeyFile) {
		t.Errorf("error = %q, want it to name %s", msg, testEnvAuthKeyFile)
	}
	if !strings.Contains(msg, "head -c 32 /dev/urandom") {
		t.Errorf("error = %q, want it to say how to make a key file (head -c 32 /dev/urandom)", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "mount") {
		t.Errorf("error = %q, want it to say the key file must be mounted", msg)
	}
}
