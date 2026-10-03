// Package mail is issue #55's outbound notification path: the one thing
// birdcage ever sends off the box it runs on. It exists because the
// dashboard cannot wake anybody up -- a token conflict is the one state
// where the right response is "look at that box now", and nobody is
// looking at a tab.
//
// Three rules shape the whole package, and each is a security control
// rather than a preference:
//
//   - The mailbox is outside the trust boundary. Anyone who can read the
//     operator's mail can read what birdcage sent, so a message carries a
//     pointer and nothing else: no link, no token, no event content, not
//     even the source address of the hit. See templates.go.
//   - There is no plaintext mode and no skip-verify knob. The connection
//     is TLS from the first byte (implicit TLS, port 465) or it is
//     STARTTLS the operator asked for by name (port 587) -- and in both
//     cases the server certificate is fully verified. A server that does
//     not offer STARTTLS on the STARTTLS path is an error, never a
//     downgrade to cleartext. See smtp.go.
//   - Configuration is all-or-nothing and is checked before any listener
//     binds. A half-configured mailer that fails at the moment it is
//     first needed -- which is the moment a canary was cloned -- is
//     worse than one that refused to start. See Load below, and
//     cmd/birdcage's use of it.
//
// The sending itself is deliberately not done inline with the event that
// caused it. A mail is written to the mail_outbox table in the same
// transaction as the state period that triggered it (internal/history's
// hook), and a separate tick drains that table. So a dead SMTP server
// cannot roll back birdcage's own record of what happened, and a mail
// that could not be sent is still owed rather than lost.
package mail

import (
	"fmt"
	"net"
	netmail "net/mail"
	"strconv"
	"strings"

	"github.com/tomlawesome/birdcage/internal/startcheck"
)

// The environment variables cmd/birdcage reads for outbound mail. They
// are named here, next to the rules that validate them, rather than in
// cmd/birdcage with the rest: internal/tlsconfig already sets that
// precedent (its refusal message names BIRDCAGE_HTTP_TLS_CERT and
// BIRDCAGE_HTTP_TLS_KEY directly), and a refusal that cannot name the
// variable an operator has to go and fix is not much of a refusal.
//
// See docs/configuration.md, "Outbound mail".
const (
	// EnvHost is the submission server as "host:port". Port 465 is
	// implicit TLS (leave EnvSTARTTLS unset); port 587 is submission
	// with STARTTLS, which must be opted into by name.
	EnvHost = "BIRDCAGE_MAIL_HOST"
	// EnvSTARTTLS set to "1" selects the STARTTLS path. Unset or "0"
	// selects implicit TLS. Any other value is refused rather than
	// guessed at -- the same strictness internal/store's
	// validateSettingBool applies to a stored boolean, for the same
	// reason: a typo here would silently choose the other transport.
	EnvSTARTTLS = "BIRDCAGE_MAIL_STARTTLS"
	// EnvUsername is the SMTP AUTH username.
	EnvUsername = "BIRDCAGE_MAIL_USERNAME"
	// EnvPasswordFile is the preferred way to supply the password: a
	// file birdcage reads once at startup. Preferred over EnvPassword
	// because an environment variable is visible to anything that can
	// read /proc/<pid>/environ and is inherited by every child process,
	// while a file can be mounted read-only and owned by the birdcage
	// uid alone (the global agent instructions' "in containers prefer
	// narrowly mounted secret files over environment variables").
	EnvPasswordFile = "BIRDCAGE_MAIL_PASSWORD_FILE"
	// EnvPassword is the fallback. If both it and EnvPasswordFile are
	// set the file wins, and Load says so in a warning rather than
	// choosing silently.
	EnvPassword = "BIRDCAGE_MAIL_PASSWORD"
	// EnvFrom is the envelope and header From address.
	EnvFrom = "BIRDCAGE_MAIL_FROM"
	// EnvTo is the single administrator address every alert goes to.
	// One address, not a list: birdcage has one operator to wake, and a
	// list would need parsing rules, per-recipient failure handling and
	// a way to stop one bad address suppressing the rest -- none of
	// which issue #55 asks for.
	EnvTo = "BIRDCAGE_MAIL_TO"
)

// envNames is every variable this package reads, in the order Load
// reports them, so the all-or-nothing refusal lists them the same way
// every time.
var envNames = []string{EnvHost, EnvSTARTTLS, EnvUsername, EnvPasswordFile, EnvPassword, EnvFrom, EnvTo}

// requiredEnvNames is the subset that must be set once any of envNames
// is. EnvSTARTTLS is optional (it selects a transport, and unset is a
// real choice), and the two password variables are required as a pair
// of alternatives rather than individually -- see Load.
var requiredEnvNames = []string{EnvHost, EnvUsername, EnvFrom, EnvTo}

// Config is a validated outbound-mail configuration. Every field has
// already passed Load's checks by the time one of these exists: the
// host parses as host:port, the two addresses parse as addresses, and
// no field contains a control character or a CR/LF that could split a
// header (see headerSafe).
//
// Password is a credential. It is never logged, never written to the
// outbox, and never included in a stored error -- see Sender.scrub.
type Config struct {
	// Host is "host:port" as supplied. Hostname returns just the host
	// part, which is what certificate verification and SMTP AUTH use.
	Host string
	// STARTTLS selects the plain-dial-then-upgrade path instead of
	// implicit TLS. It is never a permission to fall back to cleartext:
	// a server that does not advertise STARTTLS is an error.
	STARTTLS bool
	Username string
	Password string
	From     string
	To       string
}

// Hostname is Host without the port -- the name the server's
// certificate must match, and the host SMTP AUTH is scoped to. Host has
// already parsed by the time a Config exists, so this cannot fail.
func (c Config) Hostname() string {
	host, _, err := net.SplitHostPort(c.Host)
	if err != nil {
		return c.Host
	}
	return host
}

// Loaded is what Load returns: the configuration, whether mail is
// configured at all, and any warnings the caller should log. Warnings
// are returned rather than logged here so this package needs no logger
// and so a test can assert on them directly.
type Loaded struct {
	Config   Config
	Enabled  bool
	Warnings []string
}

// Load reads and validates the whole outbound-mail configuration from
// getenv (os.Getenv in production; a map lookup in tests).
//
// All-or-nothing, deliberately: with none of the variables set, mail is
// simply off and GET /api/mail says so. With any of them set, every
// required one must be set and valid, or Load returns an error naming
// the field -- and cmd/birdcage refuses to start. The alternative, a
// mailer that starts anyway and discovers it has no password at the
// moment a canary is cloned, hides the misconfiguration until precisely
// the moment it costs something.
//
// The password file is read here, through startcheck, so an unreadable
// or empty file is a start-time refusal naming the path and this
// process's uid -- the same treatment the data directory and the TLS
// key already get (issue #70), not a permission error surfacing much
// later inside a failed send.
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

	// Control characters first, before anything else looks at a value:
	// a CR or LF in any of these ends up in a header or an SMTP command
	// if it gets that far, and "BIRDCAGE_MAIL_FROM is not a valid
	// address" would be a confusing way to report an embedded newline.
	for _, name := range envNames {
		if !headerSafe(raw[name]) {
			return Loaded{}, fmt.Errorf("mail: %s contains a control character or a line break; no value may contain one", name)
		}
	}

	for _, name := range requiredEnvNames {
		if raw[name] == "" {
			return Loaded{}, missingField(name, raw)
		}
	}

	cfg := Config{
		Host:     raw[EnvHost],
		Username: raw[EnvUsername],
	}

	if err := validateHostPort(cfg.Host); err != nil {
		return Loaded{}, err
	}

	switch raw[EnvSTARTTLS] {
	case "", "0":
		cfg.STARTTLS = false
	case "1":
		cfg.STARTTLS = true
	default:
		return Loaded{}, fmt.Errorf("mail: %s must be \"1\" (STARTTLS, e.g. port 587) or unset/\"0\" (implicit TLS, port 465), got %q", EnvSTARTTLS, raw[EnvSTARTTLS])
	}

	from, err := validateAddress(EnvFrom, raw[EnvFrom])
	if err != nil {
		return Loaded{}, err
	}
	cfg.From = from

	to, err := validateAddress(EnvTo, raw[EnvTo])
	if err != nil {
		return Loaded{}, err
	}
	cfg.To = to

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
			return Loaded{}, fmt.Errorf("mail: %s: %w", EnvPasswordFile, err)
		}
		cfg.Password = secret
	case raw[EnvPassword] != "":
		cfg.Password = raw[EnvPassword]
	default:
		return Loaded{}, fmt.Errorf(
			"mail: neither %s nor %s is set, but the rest of the outbound-mail configuration is. Set %s to a file birdcage can read (preferred), or %s to the password itself",
			EnvPasswordFile, EnvPassword, EnvPasswordFile, EnvPassword)
	}
	if !headerSafe(cfg.Password) {
		return Loaded{}, fmt.Errorf("mail: the password read from %s contains a control character or a line break", EnvPasswordFile)
	}

	// A wrong port is not fatal -- the operator may genuinely be running
	// submission on a non-standard port -- but the two mismatches below
	// otherwise present as a connection that hangs or a handshake that
	// fails with no clue why, so they are worth one line at boot.
	if _, port, err := net.SplitHostPort(cfg.Host); err == nil {
		if port == "587" && !cfg.STARTTLS {
			warnings = append(warnings, fmt.Sprintf("%s ends in :587 (submission) but %s is not set; connecting with implicit TLS", EnvHost, EnvSTARTTLS))
		}
		if port == "465" && cfg.STARTTLS {
			warnings = append(warnings, fmt.Sprintf("%s ends in :465 (implicit TLS) but %s is set; connecting with STARTTLS", EnvHost, EnvSTARTTLS))
		}
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
		"mail: %s is not set, but %s is. Outbound mail is all-or-nothing: set %s, %s, %s, %s and one of %s/%s, or none of them (which turns mail off)",
		missing, present, EnvHost, EnvUsername, EnvFrom, EnvTo, EnvPasswordFile, EnvPassword)
}

// validateHostPort proves EnvHost is a usable "host:port": both parts
// present, the port numeric and in range. A bare hostname with no port
// is refused rather than defaulted, since the default would have to
// pick between 465 and 587 -- which is the same choice EnvSTARTTLS
// exists to make explicit.
func validateHostPort(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("mail: %s must be \"host:port\" (e.g. \"smtp.example.net:465\"), got %q: %w", EnvHost, value, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("mail: %s must name a host, got %q", EnvHost, value)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("mail: %s must end in a port between 1 and 65535, got %q", EnvHost, value)
	}
	return nil
}

// validateAddress parses value with net/mail and returns the bare
// address. The display-name form ("Birdcage <alerts@example.net>") is
// accepted as input and reduced to the address alone: the header this
// package writes is assembled byte by byte from that address, so there
// is never a display name carrying quoting or encoding rules of its own
// for us to get wrong.
func validateAddress(name, value string) (string, error) {
	addr, err := netmail.ParseAddress(value)
	if err != nil {
		return "", fmt.Errorf("mail: %s must be an email address (e.g. \"birdcage@example.net\"), got %q: %w", name, value, err)
	}
	if !headerSafe(addr.Address) || strings.TrimSpace(addr.Address) == "" {
		return "", fmt.Errorf("mail: %s is not a usable address: %q", name, value)
	}
	return addr.Address, nil
}
