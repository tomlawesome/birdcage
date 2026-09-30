// Package mailbox is issue #54's inbound half: the IMAP mailbox
// birdcage reads an administrator's approval replies out of.
//
// It is the counterpart of internal/mail, and the two are deliberately
// shaped the same way -- same all-or-nothing configuration, same
// preference for a password file over an environment variable, same
// refusal to start on a half-finished configuration, same fully
// verified TLS with no skip-verify knob anywhere.
//
// Three rules shape it, each a security control rather than a
// preference:
//
//   - This package decides nothing. It fetches bytes and hands them to
//     a handler. Whether a message is a real approval is
//     internal/agent/approval's question, and the agent asks it again
//     for itself on the same bytes -- ADR-0007's whole point is that
//     birdcage couriers an approval it cannot forge. A bug here can
//     waste a poll; it cannot approve an upgrade.
//   - The connection is TLS from the first byte and the certificate is
//     fully verified against the system roots. There is no plaintext
//     mode, no STARTTLS path and no way to turn verification off: this
//     credential reads the mailbox that authorises upgrades, and
//     handing it to anything on the network path would hand over the
//     approval channel with it.
//   - Every size and count is bounded before it is read. A mailbox is
//     attacker-reachable input: anyone who learns the address can put a
//     message in it. maxMessagesPerPoll, MaxMessageSize and the poll
//     deadline are what stop a mailbox full of rubbish from becoming
//     birdcage's problem.
//
// See docs/configuration.md, "Approval mailbox".
package mailbox

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/tomlawesome/birdcage/internal/startcheck"
)

// The environment variables cmd/birdcage reads for the approval
// mailbox. Named here, next to the rules that validate them, for the
// reason internal/mail's EnvHost gives: a refusal that cannot name the
// variable an operator has to go and fix is not much of a refusal.
const (
	// EnvHost is the IMAP server, as "host:port" or as a bare host. The
	// connection is implicit TLS, so a bare host means port 993 -- the
	// only port implicit-TLS IMAP is ever on, unlike submission's
	// 465/587 split, which is why this one has a default and
	// BIRDCAGE_MAIL_HOST does not.
	EnvHost = "BIRDCAGE_APPROVAL_IMAP_HOST"
	// EnvUsername is the IMAP username.
	EnvUsername = "BIRDCAGE_APPROVAL_IMAP_USERNAME"
	// EnvPasswordFile is the preferred way to supply the password: a
	// file birdcage reads once at startup. Preferred over EnvPassword
	// because an environment variable is visible to anything that can
	// read /proc/<pid>/environ and is inherited by every child process,
	// while a file can be mounted read-only and owned by the birdcage
	// uid alone.
	EnvPasswordFile = "BIRDCAGE_APPROVAL_IMAP_PASSWORD_FILE"
	// EnvPassword is the fallback. If both it and EnvPasswordFile are
	// set the file wins, and Load says so in a warning rather than
	// choosing silently.
	EnvPassword = "BIRDCAGE_APPROVAL_IMAP_PASSWORD"
	// EnvMailbox is the mailbox to read, defaulting to INBOX. An
	// operator who files approvals into a folder with a server-side
	// rule names it here.
	EnvMailbox = "BIRDCAGE_APPROVAL_IMAP_MAILBOX"
)

// DefaultPort is the implicit-TLS IMAP port, used when EnvHost names no
// port.
const DefaultPort = "993"

// DefaultMailbox is what EnvMailbox defaults to.
const DefaultMailbox = "INBOX"

// envNames is every variable this package reads, in the order Load
// reports them, so the all-or-nothing refusal lists them the same way
// every time.
var envNames = []string{EnvHost, EnvUsername, EnvPasswordFile, EnvPassword, EnvMailbox}

// requiredEnvNames is the subset that must be set once any of envNames
// is. EnvMailbox has a default, and the two password variables are
// required as a pair of alternatives rather than individually -- see
// Load.
var requiredEnvNames = []string{EnvHost, EnvUsername}

// Config is a validated approval-mailbox configuration. By the time one
// of these exists the host parses as host:port, no value contains a
// control character, and the password has been read.
//
// Password is a credential. It is never logged and never stored.
type Config struct {
	// Host is "host:port", with DefaultPort filled in if the operator
	// gave a bare host. Hostname returns just the host part, which is
	// what certificate verification and LOGIN are scoped to.
	Host     string
	Username string
	Password string
	Mailbox  string
}

// Hostname is Host without the port -- the name the server's
// certificate must match. Host has already parsed by the time a Config
// exists, so this cannot fail.
func (c Config) Hostname() string {
	host, _, err := net.SplitHostPort(c.Host)
	if err != nil {
		return c.Host
	}
	return host
}

// Loaded is what Load returns: the configuration, whether the mailbox is
// configured at all, and any warnings the caller should log. Warnings
// are returned rather than logged here so this package needs no logger
// and so a test can assert on them directly -- the same shape
// internal/mail.Loaded has.
type Loaded struct {
	Config   Config
	Enabled  bool
	Warnings []string
}

// Load reads and validates the whole approval-mailbox configuration
// from getenv (os.Getenv in production; a map lookup in tests).
//
// All-or-nothing, for the reason internal/mail.Load gives: with none of
// the variables set the mailbox is simply off, and with any of them set
// every required one must be set and valid or cmd/birdcage refuses to
// start. A half-configured mailbox that only discovers it has no
// password at the moment an approval arrives has failed at exactly the
// moment it was the point.
//
// The password file is read here, through startcheck, so an unreadable
// or empty one is a start-time refusal naming the path and this
// process's uid.
func Load(getenv func(string) string) (Loaded, error) {
	raw := map[string]string{}
	anySet := false
	for _, name := range envNames {
		v := getenv(name)
		raw[name] = v
		if v != "" {
			anySet = true
		}
	}
	if !anySet {
		return Loaded{}, nil
	}

	// Control characters first, before anything else looks at a value.
	// A CR or LF in the username or the mailbox name ends up in an IMAP
	// command if it gets that far, and IMAP is a line protocol: a
	// newline in either would be a command of the operator's choosing,
	// which is the injection this check exists to stop.
	for _, name := range envNames {
		if !safeValue(raw[name]) {
			return Loaded{}, fmt.Errorf("mailbox: %s contains a control character or a line break; no value may contain one", name)
		}
	}

	for _, name := range requiredEnvNames {
		if raw[name] == "" {
			return Loaded{}, missingField(name, raw)
		}
	}

	host, err := normalizeHost(raw[EnvHost])
	if err != nil {
		return Loaded{}, err
	}

	cfg := Config{
		Host:     host,
		Username: raw[EnvUsername],
		Mailbox:  raw[EnvMailbox],
	}
	if cfg.Mailbox == "" {
		cfg.Mailbox = DefaultMailbox
	}

	var warnings []string
	switch {
	case raw[EnvPasswordFile] != "":
		if raw[EnvPassword] != "" {
			warnings = append(warnings, fmt.Sprintf(
				"both %s and %s are set; using the file and ignoring the variable",
				EnvPasswordFile, EnvPassword))
		}
		secret, err := startcheck.SecretFile(raw[EnvPasswordFile])
		if err != nil {
			return Loaded{}, fmt.Errorf("mailbox: %s: %w", EnvPasswordFile, err)
		}
		cfg.Password = secret
	case raw[EnvPassword] != "":
		cfg.Password = raw[EnvPassword]
	default:
		return Loaded{}, fmt.Errorf(
			"mailbox: neither %s nor %s is set, but the rest of the approval-mailbox configuration is. Set %s to a file birdcage can read (preferred), or %s to the password itself",
			EnvPasswordFile, EnvPassword, EnvPasswordFile, EnvPassword)
	}
	if !safeValue(cfg.Password) {
		return Loaded{}, fmt.Errorf("mailbox: the password read from %s contains a control character or a line break", EnvPasswordFile)
	}

	return Loaded{Config: cfg, Enabled: true, Warnings: warnings}, nil
}

// missingField is Load's all-or-nothing refusal: it names the field that
// is missing and the one that is set, so the operator can see which half
// of the configuration they actually have.
func missingField(missing string, raw map[string]string) error {
	var present string
	for _, name := range envNames {
		if raw[name] != "" {
			present = name
			break
		}
	}
	return fmt.Errorf(
		"mailbox: %s is not set, but %s is. The approval mailbox is all-or-nothing: set %s, %s and one of %s/%s, or none of them (which turns the approval mailbox off)",
		missing, present, EnvHost, EnvUsername, EnvPasswordFile, EnvPassword)
}

// normalizeHost returns value as "host:port", adding DefaultPort when
// value names no port. Only a genuinely missing port is defaulted: any
// other parse failure is reported, so "smtp.example.net:" or
// "host:notaport" is a refusal rather than something quietly turned
// into port 993.
func normalizeHost(value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" {
			host, port = value, DefaultPort
		} else {
			return "", fmt.Errorf("mailbox: %s must be \"host\" or \"host:port\" (e.g. \"imap.example.net\" or \"imap.example.net:993\"), got %q: %w", EnvHost, value, err)
		}
	}
	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("mailbox: %s must name a host, got %q", EnvHost, value)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("mailbox: %s must end in a port between 1 and 65535, got %q", EnvHost, value)
	}
	return net.JoinHostPort(host, port), nil
}

// safeValue reports whether s is free of control characters, including
// CR and LF. Same rule and same reason as internal/mail's headerSafe,
// applied to a line protocol of its own.
func safeValue(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
