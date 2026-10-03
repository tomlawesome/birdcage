package mail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every credential in this file is a literal, obviously-fake
// placeholder written inline in the test. Nothing here is read from the
// environment, and nothing here resembles a working credential.
const (
	testUsername = "birdcage@example.invalid"
	testPassword = "not-a-real-password"
	testFrom     = "birdcage@example.invalid"
	testTo       = "admin@example.invalid"
	testHostPort = "smtp.example.invalid:465"
)

// env builds a getenv function over a map, so a test never touches the
// real process environment (and so two tests can run in parallel with
// different configurations).
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func validEnv() map[string]string {
	return map[string]string{
		EnvHost:     testHostPort,
		EnvUsername: testUsername,
		EnvPassword: testPassword,
		EnvFrom:     testFrom,
		EnvTo:       testTo,
	}
}

func TestLoadOffWhenNothingIsSet(t *testing.T) {
	loaded, err := Load(env(map[string]string{}))
	if err != nil {
		t.Fatalf("Load with nothing set: %v", err)
	}
	if loaded.Enabled {
		t.Errorf("Enabled = true with no mail variables set, want false")
	}
	if loaded.Config != (Config{}) {
		t.Errorf("Config = %+v with nothing set, want the zero value", loaded.Config)
	}
}

func TestLoadAcceptsAValidConfiguration(t *testing.T) {
	loaded, err := Load(env(validEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Enabled {
		t.Fatal("Enabled = false for a complete configuration")
	}
	if loaded.Config.Host != testHostPort {
		t.Errorf("Host = %q, want %q", loaded.Config.Host, testHostPort)
	}
	if loaded.Config.Hostname() != "smtp.example.invalid" {
		t.Errorf("Hostname() = %q, want %q", loaded.Config.Hostname(), "smtp.example.invalid")
	}
	if loaded.Config.STARTTLS {
		t.Error("STARTTLS = true with the variable unset, want false (implicit TLS)")
	}
	if loaded.Config.Password != testPassword {
		t.Error("Password did not round-trip from the environment")
	}
	if len(loaded.Warnings) != 0 {
		t.Errorf("Warnings = %v for a clean configuration, want none", loaded.Warnings)
	}
}

// All-or-nothing: each required field, missing on its own, must refuse
// and must name itself. Naming the field is the whole point -- issue
// #55's refusal has to tell the operator which variable to go and set.
func TestLoadRefusesEachMissingRequiredField(t *testing.T) {
	for _, name := range requiredEnvNames {
		t.Run(name, func(t *testing.T) {
			m := validEnv()
			delete(m, name)
			_, err := Load(env(m))
			if err == nil {
				t.Fatalf("Load without %s succeeded, want a refusal", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("refusal %q does not name %s", err, name)
			}
		})
	}
}

func TestLoadRefusesWithNoPasswordAtAll(t *testing.T) {
	m := validEnv()
	delete(m, EnvPassword)
	_, err := Load(env(m))
	if err == nil {
		t.Fatal("Load with no password succeeded, want a refusal")
	}
	for _, want := range []string{EnvPassword, EnvPasswordFile} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %s", err, want)
		}
	}
}

// The file wins over the variable, and says so. Silently preferring one
// would leave an operator who rotated only the variable convinced they
// had changed the password.
func TestLoadPrefersThePasswordFileAndWarns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "smtp-password")
	if err := os.WriteFile(path, []byte("from-the-file-not-real\n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	m := validEnv()
	m[EnvPasswordFile] = path
	loaded, err := Load(env(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Config.Password != "from-the-file-not-real" {
		t.Errorf("Password came from the variable, want the file's contents (trailing newline trimmed)")
	}
	if len(loaded.Warnings) != 1 || !strings.Contains(loaded.Warnings[0], EnvPasswordFile) {
		t.Errorf("Warnings = %v, want one naming %s", loaded.Warnings, EnvPasswordFile)
	}
}

func TestLoadRefusesAnEmptyPasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	m := validEnv()
	delete(m, EnvPassword)
	m[EnvPasswordFile] = path
	if _, err := Load(env(m)); err == nil {
		t.Fatal("Load with an empty password file succeeded, want a refusal")
	}
}

func TestLoadRefusesAnUnreadablePasswordFile(t *testing.T) {
	m := validEnv()
	delete(m, EnvPassword)
	m[EnvPasswordFile] = filepath.Join(t.TempDir(), "does-not-exist")
	_, err := Load(env(m))
	if err == nil {
		t.Fatal("Load with a missing password file succeeded, want a refusal")
	}
	if !strings.Contains(err.Error(), "startcheck:") {
		t.Errorf("refusal %q does not carry startcheck's message", err)
	}
}

// CR/LF in any value is refused at start, not at send time: issue #55's
// header-injection gate applies to what the operator configured exactly
// as much as to what a canary is called.
func TestLoadRefusesControlCharactersInAnyField(t *testing.T) {
	cases := map[string]string{
		EnvHost:     "smtp.example.invalid:465\r\nDATA",
		EnvUsername: "user\nname",
		EnvPassword: "pass\rword",
		EnvFrom:     "birdcage@example.invalid\r\nBcc: someone@example.invalid",
		EnvTo:       "admin@example.invalid\nSubject: injected",
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			m := validEnv()
			m[name] = bad
			_, err := Load(env(m))
			if err == nil {
				t.Fatalf("Load with a line break in %s succeeded, want a refusal", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Errorf("refusal %q does not name %s", err, name)
			}
		})
	}
}

func TestLoadValidatesHostPort(t *testing.T) {
	for _, bad := range []string{"smtp.example.invalid", "smtp.example.invalid:", ":465", "smtp.example.invalid:0", "smtp.example.invalid:70000", "smtp.example.invalid:smtps"} {
		t.Run(bad, func(t *testing.T) {
			m := validEnv()
			m[EnvHost] = bad
			if _, err := Load(env(m)); err == nil {
				t.Fatalf("Load with %s=%q succeeded, want a refusal", EnvHost, bad)
			}
		})
	}
}

func TestLoadValidatesAddresses(t *testing.T) {
	for _, name := range []string{EnvFrom, EnvTo} {
		t.Run(name, func(t *testing.T) {
			m := validEnv()
			m[name] = "not an address"
			if _, err := Load(env(m)); err == nil {
				t.Fatalf("Load with %s=%q succeeded, want a refusal", name, m[name])
			}
		})
	}
}

// A display-name form is accepted and reduced to the bare address: the
// headers this package writes are assembled by hand, so there is never
// a display name with its own quoting rules to get wrong.
func TestLoadReducesADisplayNameToTheAddress(t *testing.T) {
	m := validEnv()
	m[EnvFrom] = "Birdcage Alerts <birdcage@example.invalid>"
	loaded, err := Load(env(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Config.From != "birdcage@example.invalid" {
		t.Errorf("From = %q, want the bare address", loaded.Config.From)
	}
}

func TestLoadSTARTTLSIsStrict(t *testing.T) {
	for value, want := range map[string]bool{"1": true, "0": false, "": false} {
		m := validEnv()
		if value != "" {
			m[EnvSTARTTLS] = value
		}
		loaded, err := Load(env(m))
		if err != nil {
			t.Fatalf("Load with %s=%q: %v", EnvSTARTTLS, value, err)
		}
		if loaded.Config.STARTTLS != want {
			t.Errorf("%s=%q gave STARTTLS=%v, want %v", EnvSTARTTLS, value, loaded.Config.STARTTLS, want)
		}
	}
	for _, bad := range []string{"true", "yes", "TRUE", "2"} {
		m := validEnv()
		m[EnvSTARTTLS] = bad
		if _, err := Load(env(m)); err == nil {
			t.Errorf("Load with %s=%q succeeded, want a refusal", EnvSTARTTLS, bad)
		}
	}
}

func TestLoadWarnsOnAPortTransportMismatch(t *testing.T) {
	m := validEnv()
	m[EnvHost] = "smtp.example.invalid:587"
	loaded, err := Load(env(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Warnings) != 1 || !strings.Contains(loaded.Warnings[0], EnvSTARTTLS) {
		t.Errorf("Warnings = %v for :587 without STARTTLS, want one naming %s", loaded.Warnings, EnvSTARTTLS)
	}
}
