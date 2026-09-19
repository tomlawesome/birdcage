package mailbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// env turns a map into the getenv Load takes, so a test names only the
// variables it cares about.
func env(pairs map[string]string) func(string) string {
	return func(name string) string { return pairs[name] }
}

func fullEnv() map[string]string {
	return map[string]string{
		EnvHost:     "imap.example.net:993",
		EnvUsername: "birdcage@example.net",
		EnvPassword: "hunter2",
	}
}

// With none of the variables set, the approval mailbox is simply off.
func TestLoadIsOffWhenNothingIsSet(t *testing.T) {
	loaded, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load with an empty environment: %v", err)
	}
	if loaded.Enabled {
		t.Error("Load enabled the mailbox with nothing configured")
	}
}

func TestLoadAcceptsACompleteConfiguration(t *testing.T) {
	loaded, err := Load(env(fullEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Enabled {
		t.Fatal("Load did not enable the mailbox")
	}
	if loaded.Config.Host != "imap.example.net:993" {
		t.Errorf("Host = %q", loaded.Config.Host)
	}
	if loaded.Config.Hostname() != "imap.example.net" {
		t.Errorf("Hostname() = %q", loaded.Config.Hostname())
	}
	if loaded.Config.Mailbox != DefaultMailbox {
		t.Errorf("Mailbox = %q, want the %s default", loaded.Config.Mailbox, DefaultMailbox)
	}
	if len(loaded.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", loaded.Warnings)
	}
}

// Set one and you must set the rest: a half-configured mailbox only
// discovers it has no password at the moment an approval arrives.
func TestLoadIsAllOrNothing(t *testing.T) {
	cases := map[string]map[string]string{
		"no username":         {EnvHost: "imap.example.net"},
		"no host":             {EnvUsername: "birdcage@example.net", EnvPassword: "hunter2"},
		"no password":         {EnvHost: "imap.example.net", EnvUsername: "birdcage@example.net"},
		"only a mailbox name": {EnvMailbox: "Approvals"},
	}
	for name, pairs := range cases {
		if _, err := Load(env(pairs)); err == nil {
			t.Errorf("Load accepted a half-configured mailbox (%s)", name)
		}
	}
}

// A refusal names both the missing variable and one that is set, so an
// operator can see which half of the configuration they have.
func TestLoadNamesWhatIsMissingAndWhatIsSet(t *testing.T) {
	_, err := Load(env(map[string]string{EnvHost: "imap.example.net"}))
	if err == nil {
		t.Fatal("Load accepted a host with no username")
	}
	if !strings.Contains(err.Error(), EnvUsername) || !strings.Contains(err.Error(), EnvHost) {
		t.Errorf("the refusal does not name both variables: %v", err)
	}
}

// Implicit TLS IMAP is only ever on 993, so a bare host gets the port
// filled in -- unlike submission, where 465 and 587 mean different
// transports and the operator has to say which.
func TestLoadDefaultsThePort(t *testing.T) {
	pairs := fullEnv()
	pairs[EnvHost] = "imap.example.net"
	loaded, err := Load(env(pairs))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Config.Host != "imap.example.net:"+DefaultPort {
		t.Errorf("Host = %q, want the %s default port filled in", loaded.Config.Host, DefaultPort)
	}
}

func TestLoadKeepsAnExplicitPort(t *testing.T) {
	pairs := fullEnv()
	pairs[EnvHost] = "imap.example.net:1993"
	loaded, err := Load(env(pairs))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Config.Host != "imap.example.net:1993" {
		t.Errorf("Host = %q", loaded.Config.Host)
	}
}

// Only a genuinely missing port is defaulted. Anything else is a typo
// worth refusing rather than quietly turning into port 993.
func TestLoadRejectsABadHost(t *testing.T) {
	for _, host := range []string{"imap.example.net:", "imap.example.net:notaport", "imap.example.net:0", "imap.example.net:70000", ":993"} {
		pairs := fullEnv()
		pairs[EnvHost] = host
		if _, err := Load(env(pairs)); err == nil {
			t.Errorf("Load accepted %s=%q", EnvHost, host)
		}
	}
}

func TestLoadCarriesAMailboxName(t *testing.T) {
	pairs := fullEnv()
	pairs[EnvMailbox] = "Approvals"
	loaded, err := Load(env(pairs))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Config.Mailbox != "Approvals" {
		t.Errorf("Mailbox = %q", loaded.Config.Mailbox)
	}
}

// IMAP is a line protocol, so a newline in a value would be a command
// of whoever chose it.
func TestLoadRejectsControlCharacters(t *testing.T) {
	for _, name := range []string{EnvHost, EnvUsername, EnvPassword, EnvMailbox} {
		pairs := fullEnv()
		pairs[name] = "value\r\nA001 LOGOUT"
		_, err := Load(env(pairs))
		if err == nil {
			t.Errorf("Load accepted a line break in %s", name)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("the refusal for %s does not name it: %v", name, err)
		}
	}
}

func TestLoadReadsThePasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "imap-password")
	if err := os.WriteFile(path, []byte("from-the-file\n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	pairs := fullEnv()
	delete(pairs, EnvPassword)
	pairs[EnvPasswordFile] = path

	loaded, err := Load(env(pairs))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// One trailing newline is trimmed: every text editor adds one, and
	// a password with a newline welded on fails authentication in a way
	// that looks like a wrong password.
	if loaded.Config.Password != "from-the-file" {
		t.Errorf("Password = %q, want the file's contents with the trailing newline trimmed", loaded.Config.Password)
	}
}

// Both set is not a silent choice: the file wins and Load says so, so
// nobody is left convinced they rotated a password they had not.
func TestLoadPrefersThePasswordFileAndWarns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "imap-password")
	if err := os.WriteFile(path, []byte("from-the-file"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	pairs := fullEnv()
	pairs[EnvPasswordFile] = path

	loaded, err := Load(env(pairs))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Config.Password != "from-the-file" {
		t.Errorf("Password = %q, want the file to win", loaded.Config.Password)
	}
	if len(loaded.Warnings) != 1 || !strings.Contains(loaded.Warnings[0], EnvPasswordFile) {
		t.Errorf("Warnings = %v, want one naming the file variable", loaded.Warnings)
	}
}

// An unreadable or empty password file is a start-time refusal naming
// the path, not a permission error surfacing later inside a poll.
func TestLoadRefusesAnUnusablePasswordFile(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	for name, path := range map[string]string{
		"missing": filepath.Join(dir, "does-not-exist"),
		"empty":   empty,
	} {
		pairs := fullEnv()
		delete(pairs, EnvPassword)
		pairs[EnvPasswordFile] = path
		_, err := Load(env(pairs))
		if err == nil {
			t.Errorf("Load accepted a %s password file", name)
			continue
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("the refusal for the %s file does not name the path: %v", name, err)
		}
	}
}
