package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/tomlawesome/gauntlet/persist"

	"github.com/tomlawesome/birdcage/internal/auth"
	"github.com/tomlawesome/birdcage/internal/tlsconfig"
)

// The sign-in settings (issue #8, ADR-0016). Secrets are only ever named
// by a file: no setting here takes a secret as its value, so none can
// reach a process listing, an environment dump or a log line.
const (
	// envAuthKeyFile names a file of at least persist.MinKeyBytes bytes
	// that every sign-in store is sealed under. Required. Losing it loses
	// every account.
	envAuthKeyFile = "BIRDCAGE_AUTH_KEY_FILE"
	// envPublicURL is the address people reach the dashboard on; passkeys
	// and SSO are built from it. Optional.
	envPublicURL = "BIRDCAGE_PUBLIC_URL"
	// envAuthAdminPasskey overrides the admin-passkey rule: required or
	// optional. Optional.
	envAuthAdminPasskey = "BIRDCAGE_AUTH_ADMIN_PASSKEY"

	// Country lookup: one provider, or none.
	envGeoIPIPinfoTokenFile       = "BIRDCAGE_GEOIP_IPINFO_TOKEN_FILE"
	envGeoIPMaxMindAccountID      = "BIRDCAGE_GEOIP_MAXMIND_ACCOUNT_ID"
	envGeoIPMaxMindLicenceKeyFile = "BIRDCAGE_GEOIP_MAXMIND_LICENCE_KEY_FILE"

	// SSO: all three, or none.
	envOIDCIssuer           = "BIRDCAGE_OIDC_ISSUER"
	envOIDCClientID         = "BIRDCAGE_OIDC_CLIENT_ID"
	envOIDCClientSecretFile = "BIRDCAGE_OIDC_CLIENT_SECRET_FILE"

	// maxSecretFileBytes bounds how much of a secret file is read: a
	// mistaken path to a large file is refused, not slurped.
	maxSecretFileBytes = 1 << 20
)

// loadAuthConfig reads and checks the sign-in settings. It refuses, with
// an error that names the setting, on anything missing or inconsistent,
// so a bad configuration stops start-up before the database opens rather
// than at the first sign-in. It logs what is set but never a secret, a
// secret file's contents, or their lengths.
//
// dataDir is where the common-password list and country data are kept;
// servesTLS is whether the dashboard serves TLS itself; the session cookie
// is Secure then, or when the public address is https (a TLS-terminating
// proxy in front).
func loadAuthConfig(getenv func(string) string, dataDir string, servesTLS bool, configLog *slog.Logger) (auth.Config, error) {
	cfg := auth.Config{DataDir: dataDir, SecureCookie: servesTLS}
	refuse := func(format string, args ...any) (auth.Config, error) {
		return auth.Config{}, &startupError{configLog, fmt.Sprintf(format, args...)}
	}

	keyFile := getenv(envAuthKeyFile)
	if keyFile == "" {
		return refuse("%s is not set: birdcage needs a key file (at least %d bytes) to seal its sign-in accounts. "+
			"Make one with `head -c 32 /dev/urandom > key`, mount it read-only, and set %s to its path. "+
			"Back it up apart from the database: losing it loses every account",
			envAuthKeyFile, persist.MinKeyBytes, envAuthKeyFile)
	}
	key, err := readSecretFile(envAuthKeyFile, keyFile, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return refuse("%v. Make one with `head -c 32 /dev/urandom > key`, mount it read-only, and set %s to its path. "+
				"Back it up apart from the database: losing it loses every account", err, envAuthKeyFile)
		}
		return refuse("%v", err)
	}
	if len(key) < persist.MinKeyBytes {
		return refuse("%s=%q holds %d bytes; it must hold at least %d. Make one with `head -c 32 /dev/urandom > key`",
			envAuthKeyFile, keyFile, len(key), persist.MinKeyBytes)
	}
	cfg.Key = key
	configLog.Info(fmt.Sprintf("%s=%s", envAuthKeyFile, keyFile))

	if raw := getenv(envPublicURL); raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
			return refuse("%s=%q is not a usable address; use the full address people type, such as https://birdcage.example.net", envPublicURL, raw)
		}
		cfg.PublicURL = raw
		if u.Scheme == "https" {
			cfg.SecureCookie = true
		}
		configLog.Info(fmt.Sprintf("%s=%s", envPublicURL, raw))
	}

	// Reverse proxy: which peers a forwarding header is believed from, and
	// which header. A bad entry is refused, never skipped, so the operator
	// is not left believing forwarded addresses are honoured.
	if raw := getenv(envTrustedProxies); raw != "" {
		proxies, err := parseTrustedProxies(raw)
		if err != nil {
			return refuse("%s=%q: %v", envTrustedProxies, raw, err)
		}
		cfg.TrustedProxies = proxies
		configLog.Info(fmt.Sprintf("%s=%s", envTrustedProxies, raw))
	}
	cfg.ClientIPHeader = defaultClientIPHeader
	if h := strings.TrimSpace(getenv(envClientIPHeader)); h != "" {
		cfg.ClientIPHeader = h
		configLog.Info(fmt.Sprintf("%s=%s", envClientIPHeader, h))
	}

	cfg.AdminPasskeyOverride = getenv(envAuthAdminPasskey)
	// "required" is refused here, not at the first sign-in, when browsers
	// cannot make a passkey for the public address (an IP address, or
	// plain http on a name other than localhost): no admin could ever
	// satisfy it.
	if _, err := auth.AdminPasskeyRule(cfg.PublicURL, auth.PasskeysUsable(cfg.PublicURL), cfg.AdminPasskeyOverride); err != nil {
		return refuse("%v", err)
	}
	if cfg.AdminPasskeyOverride != "" {
		configLog.Info(fmt.Sprintf("%s=%s", envAuthAdminPasskey, cfg.AdminPasskeyOverride))
	}

	// Country: IPinfo's token file, or MaxMind's account ID with its
	// licence-key file, never both providers and never half of MaxMind.
	ipinfoFile := getenv(envGeoIPIPinfoTokenFile)
	maxmindAccount := getenv(envGeoIPMaxMindAccountID)
	maxmindFile := getenv(envGeoIPMaxMindLicenceKeyFile)
	switch {
	case maxmindAccount != "" && maxmindFile == "":
		return refuse("%s is set but %s is not: MaxMind needs both its account ID and its licence key file", envGeoIPMaxMindAccountID, envGeoIPMaxMindLicenceKeyFile)
	case maxmindAccount == "" && maxmindFile != "":
		return refuse("%s is set but %s is not: MaxMind needs both its account ID and its licence key file", envGeoIPMaxMindLicenceKeyFile, envGeoIPMaxMindAccountID)
	case ipinfoFile != "" && maxmindFile != "":
		return refuse("both %s and %s are set: choose one country provider", envGeoIPIPinfoTokenFile, envGeoIPMaxMindAccountID)
	}
	if ipinfoFile != "" {
		token, err := readSecretFile(envGeoIPIPinfoTokenFile, ipinfoFile, true)
		if err != nil {
			return refuse("%v", err)
		}
		cfg.IPinfoToken = string(token)
		configLog.Info(fmt.Sprintf("%s=%s (country lookup on, IPinfo)", envGeoIPIPinfoTokenFile, ipinfoFile))
	}
	if maxmindFile != "" {
		licence, err := readSecretFile(envGeoIPMaxMindLicenceKeyFile, maxmindFile, true)
		if err != nil {
			return refuse("%v", err)
		}
		cfg.MaxMindAccountID, cfg.MaxMindLicenceKey = maxmindAccount, string(licence)
		configLog.Info(fmt.Sprintf("%s=%s %s=%s (country lookup on, MaxMind)", envGeoIPMaxMindAccountID, maxmindAccount, envGeoIPMaxMindLicenceKeyFile, maxmindFile))
	}

	// SSO: all or none.
	issuer, clientID, secretFile := getenv(envOIDCIssuer), getenv(envOIDCClientID), getenv(envOIDCClientSecretFile)
	if issuer != "" || clientID != "" || secretFile != "" {
		var missing []string
		for _, s := range []struct{ name, value string }{
			{envOIDCIssuer, issuer}, {envOIDCClientID, clientID}, {envOIDCClientSecretFile, secretFile},
		} {
			if s.value == "" {
				missing = append(missing, s.name)
			}
		}
		if len(missing) > 0 {
			return refuse("SSO needs %s, %s and %s together; missing: %s", envOIDCIssuer, envOIDCClientID, envOIDCClientSecretFile, strings.Join(missing, ", "))
		}
		if cfg.PublicURL == "" {
			return refuse("SSO is configured but %s is not set: the sign-in redirect address is built from it", envPublicURL)
		}
		secret, err := readSecretFile(envOIDCClientSecretFile, secretFile, true)
		if err != nil {
			return refuse("%v", err)
		}
		cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCClientSecret = issuer, clientID, string(secret)
		configLog.Info(fmt.Sprintf("%s=%s %s=%s %s=%s (SSO on)", envOIDCIssuer, issuer, envOIDCClientID, clientID, envOIDCClientSecretFile, secretFile))
	}

	return cfg, nil
}

// readSecretFile reads the file the setting names. trim drops surrounding
// whitespace (a token file's trailing newline); the key file is taken
// byte for byte. The error names the setting and the path, never the
// content.
func readSecretFile(setting, path string, trim bool) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s=%q cannot be read: %w", setting, path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s=%q cannot be read: %w", setting, path, err)
	}
	if len(data) > maxSecretFileBytes {
		return nil, fmt.Errorf("%s=%q is larger than %d bytes; it should name a small secret file", setting, path, maxSecretFileBytes)
	}
	if trim {
		data = []byte(strings.TrimSpace(string(data)))
		if len(data) == 0 {
			return nil, fmt.Errorf("%s=%q is empty", setting, path)
		}
	}
	return data, nil
}

// dashboardServesTLS reports whether the dashboard listener terminates
// TLS itself, which is when the session cookie must be Secure.
func dashboardServesTLS(sel tlsconfig.Selection) bool {
	return sel.Mode == tlsconfig.ModeCert || sel.Mode == tlsconfig.ModeMintedCert
}

// authDataDir is the data directory the sign-in layer keeps its fetched
// files under: where the database lives, the directory start-up already
// proves writable.
func authDataDir(dbPath string) string { return filepath.Dir(dbPath) }
