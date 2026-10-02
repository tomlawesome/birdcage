// Package crowdsec is ADR-0014: birdcage publishes a permanent ban
// decision into a CrowdSec Local API (LAPI) as a registered machine,
// exactly the way `cscli decisions add` does, on an operator's request
// and never on its own. It has no delete, no expiry and no scheduler;
// the one entry point a caller gets is Blocker.Block, which checks the
// never-block floor, asks CrowdSec's own allowlist, posts the decision
// and writes the audit_log row, in that order, each step fail-closed.
//
// Everything on the wire is net/http, crypto/tls and encoding/json. The
// CrowdSec Go modules named on #4 are not approved and not needed: the
// whole client is a login, an allowlist check, an alerts lookup and an
// alerts post.
//
// See docs/adr/0014-crowdsec-permanent-ban-publisher.md for the
// research behind every number and constant here, and
// docs/configuration.md "CrowdSec" for the operator's side.
package crowdsec

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/tomlawesome/birdcage/internal/startcheck"
)

// The environment variables cmd/birdcage reads for the CrowdSec
// connection. Named here, next to the rules that validate them, for the
// reason internal/mail's EnvHost gives: a refusal that cannot name the
// variable an operator has to fix is not much of a refusal.
const (
	// EnvLAPIURL is the Local API's base URL, https only, e.g.
	// "https://crowdsec.lan:8080". A path prefix is allowed (a reverse
	// proxy may mount the LAPI under one); userinfo, a query string
	// and a fragment are refused.
	EnvLAPIURL = "BIRDCAGE_CROWDSEC_LAPI_URL"
	// EnvMachineID is the machine name registered on the CrowdSec host
	// with `cscli machines add <name> --password ... -f /dev/null`.
	EnvMachineID = "BIRDCAGE_CROWDSEC_MACHINE_ID"
	// EnvPasswordFile is the only way to supply the machine password:
	// a mounted file birdcage reads with startcheck.SecretFile. There
	// is deliberately no plain-variable form. An environment variable
	// is visible to anything that can read /proc/<pid>/environ and is
	// inherited by every child process; a file can be mounted
	// read-only and owned by the birdcage uid alone -- and this
	// credential can delete decisions on the CrowdSec side (ADR-0014,
	// decision 3), so it gets the stricter of the two shapes.
	EnvPasswordFile = "BIRDCAGE_CROWDSEC_PASSWORD_FILE"
	// EnvCAFile optionally names a PEM bundle to verify the LAPI's
	// certificate against instead of the system roots -- the usual
	// case for a self-hosted LAPI behind a private CA. There is no
	// skip-verify knob and never will be.
	EnvCAFile = "BIRDCAGE_CROWDSEC_CA_FILE"
)

// requiredEnvNames are the variables that must all be set once any of
// them is.
var requiredEnvNames = []string{EnvLAPIURL, EnvMachineID, EnvPasswordFile}

// envNames is every variable Load reads, required or not.
var envNames = []string{EnvLAPIURL, EnvMachineID, EnvPasswordFile, EnvCAFile}

// maxMachineIDLen bounds the machine id. CrowdSec itself accepts any
// string; the bound here is only so a typo cannot become a kilobyte of
// header.
const maxMachineIDLen = 128

// Config is a validated CrowdSec connection. Build one with Load; the
// zero value is unusable.
type Config struct {
	// LAPIURL is the validated base URL with no trailing slash.
	LAPIURL string
	// MachineID is the registered machine's name.
	MachineID string
	// Password is the credential. It is never logged, never printed
	// and never written to audit_log; see Blocker.
	Password string
	// RootCAs is the pool the LAPI's certificate is verified against,
	// or nil for the system roots.
	RootCAs *x509.CertPool
	// CAFile is the path RootCAs was read from, for the startup log
	// line; empty when the system roots are in use.
	CAFile string
}

// Loaded is Load's result: Enabled is false, and Config zero, when none
// of the variables is set.
type Loaded struct {
	Config  Config
	Enabled bool
}

// Load reads and validates the whole CrowdSec configuration from
// getenv (os.Getenv in production; a map lookup in tests).
//
// All-or-nothing, for the reason internal/mail.Load gives: with none of
// the variables set CrowdSec is simply off, and with any of them set
// every required one must be set and valid or the caller refuses --
// cmd/birdcage at startup, and `birdcage crowdsec add` before it
// contacts anything. A half-configured connection that only discovers
// its missing password at the moment an operator is trying to block an
// attacker is the wrong moment to discover it.
func Load(getenv func(string) string) (Loaded, error) {
	raw := make(map[string]string, len(envNames))
	anySet := false
	for _, name := range envNames {
		raw[name] = strings.TrimSpace(getenv(name))
		if raw[name] != "" {
			anySet = true
		}
	}
	if !anySet {
		return Loaded{}, nil
	}

	for _, name := range envNames {
		if !safeValue(raw[name]) {
			return Loaded{}, fmt.Errorf("crowdsec: %s contains a control character or a line break; no value may contain one", name)
		}
	}
	for _, name := range requiredEnvNames {
		if raw[name] == "" {
			return Loaded{}, missingField(name, raw)
		}
	}

	lapiURL, err := validateLAPIURL(raw[EnvLAPIURL])
	if err != nil {
		return Loaded{}, err
	}
	if len(raw[EnvMachineID]) > maxMachineIDLen {
		return Loaded{}, fmt.Errorf("crowdsec: %s is longer than %d characters", EnvMachineID, maxMachineIDLen)
	}

	secret, err := startcheck.SecretFile(raw[EnvPasswordFile])
	if err != nil {
		return Loaded{}, fmt.Errorf("crowdsec: %s: %w", EnvPasswordFile, err)
	}
	if !safeValue(secret) {
		return Loaded{}, fmt.Errorf("crowdsec: the password read from %s contains a control character or a line break", EnvPasswordFile)
	}

	cfg := Config{LAPIURL: lapiURL, MachineID: raw[EnvMachineID], Password: secret}
	if raw[EnvCAFile] != "" {
		pool, err := loadCAFile(raw[EnvCAFile])
		if err != nil {
			return Loaded{}, err
		}
		cfg.RootCAs = pool
		cfg.CAFile = raw[EnvCAFile]
	}
	return Loaded{Config: cfg, Enabled: true}, nil
}

// validateLAPIURL applies ADR-0014 decision 7's URL rules: https only
// (a machine password crosses the wire on every login, and the
// official image's plain-http default is exactly the shape this
// refuses), a host, no userinfo (a credential in a URL ends up in
// logs), no query or fragment (nothing birdcage sends has one, so one
// here is a mistake). The returned string has no trailing slash, so
// paths can be appended.
func validateLAPIURL(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("crowdsec: %s is not a URL: %w", EnvLAPIURL, err)
	}
	switch {
	case u.Scheme != "https":
		return "", fmt.Errorf("crowdsec: %s must start with https:// (got scheme %q); the LAPI must be behind TLS, there is no plaintext mode", EnvLAPIURL, u.Scheme)
	case u.Host == "" || u.Hostname() == "":
		return "", fmt.Errorf("crowdsec: %s must name a host", EnvLAPIURL)
	case u.User != nil:
		return "", fmt.Errorf("crowdsec: %s must not carry a username or password; the machine credential goes in %s and %s", EnvLAPIURL, EnvMachineID, EnvPasswordFile)
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "":
		return "", fmt.Errorf("crowdsec: %s must not carry a query string or fragment", EnvLAPIURL)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// loadCAFile reads a PEM bundle into a pool, refusing a file that
// yields no certificate at all -- an empty pool would verify nothing
// and read as "configured" in the startup log.
func loadCAFile(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("crowdsec: %s: %w", EnvCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("crowdsec: %s: %s holds no PEM certificate", EnvCAFile, path)
	}
	return pool, nil
}

// missingField is Load's all-or-nothing refusal: it names the variable
// that is missing and the one that is set, so the operator can see
// which half of the configuration they actually have.
func missingField(missing string, raw map[string]string) error {
	var present string
	for _, name := range envNames {
		if raw[name] != "" {
			present = name
			break
		}
	}
	return fmt.Errorf(
		"crowdsec: %s is not set, but %s is. The CrowdSec connection is all-or-nothing: set %s, %s and %s (and optionally %s), or none of them (which turns CrowdSec off)",
		missing, present, EnvLAPIURL, EnvMachineID, EnvPasswordFile, EnvCAFile)
}

// safeValue reports whether s is free of control characters, including
// CR and LF. Same rule as internal/mailbox's safeValue: every one of
// these values ends up in an HTTP header or a JSON body, and a line
// break in a header is a header of the operator's choosing.
func safeValue(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ErrNotConfigured is returned by callers that need a Config when none
// of the variables is set.
var ErrNotConfigured = errors.New("crowdsec: " + EnvLAPIURL + " is not set; see docs/configuration.md, \"CrowdSec\"")
