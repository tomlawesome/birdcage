package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Environment variables this agent reads -- the only configuration
// surface it has. #48 decision 6: "No config file ... a local parse
// surface on a hostile box is itself a risk." Named and documented the
// same way cmd/birdcage/main.go's own env consts are, so an operator
// reading either binary's source finds configuration the same way.
const (
	// envBirdcageURL is birdcage's ingest origin, dialled exactly by
	// internal/agent/client -- no proxy, no redirect (#48 "What the
	// research changed" #1).
	envBirdcageURL = "MOCKINGBIRD_BIRDCAGE_URL"
	// envStateDir is the 0700 directory #47 provisions on the canary,
	// holding the enrolment-written CA certificate and mTLS client
	// certificate/key, and the agent-written token and acknowledged
	// position files (#48 decision 6).
	envStateDir = "MOCKINGBIRD_STATE_DIR"
	// envLogPath is OpenCanary's log file -- read by the tailer a later
	// slice adds. Carried through configuration now so that slice is
	// purely additive.
	envLogPath = "MOCKINGBIRD_LOG_PATH"
	// envListen is the loopback address the receiver a later slice adds
	// binds. The concrete port is #47's to pin, since it writes
	// OpenCanary's webhook URL to match; loopback-only is enforced where
	// the receiver actually binds, not duplicated here.
	envListen = "MOCKINGBIRD_LISTEN"
)

// File names inside StateDir. Fixed, not configurable -- #48 decision 6:
// "no parseable local configuration surface beyond the token file and
// the acknowledged position." caFileName, clientCertFileName and
// clientKeyFileName are written once by enrolment (#47) and only ever
// read here; tokenFileName and positionFileName are also written by this
// agent itself (0600 -- #48: "the token file is unreadable by any other
// user on the box", applied identically to the position file by
// queue.PositionStore).
const (
	tokenFileName      = "token"
	positionFileName   = "position"
	caFileName         = "ca.pem"
	clientCertFileName = "client.pem"
	clientKeyFileName  = "client-key.pem"
)

// Config is every input this agent reads at startup. Every field is
// required: loadConfig fails loudly rather than defaulting any of them
// (#48 decision 1: "Any missing or unreadable required input ... is a
// loud non-zero exit ... a half-credentialed agent must never
// half-run").
type Config struct {
	// BirdcageURL is client.Config.BaseURL.
	BirdcageURL string
	// StateDir is the directory documented above.
	StateDir string
	// LogPath is OpenCanary's log file. Deliberately *not* checked for
	// readability here: #48's fail-closed rule treats an unreadable log
	// as a running condition the heartbeat reports (log_read_ok=false),
	// not a startup failure -- the file may not exist yet on a freshly
	// enrolled box, before OpenCanary has logged anything. This field
	// only carries the value through to the tailer a later slice adds.
	LogPath string
	// Listen is the receiver's bind address, carried through the same
	// way as LogPath, for the same reason: the receiver a later slice
	// adds is what validates and uses it.
	Listen string

	// CACert, ClientCert and ClientKey are the PEM bytes read from
	// StateDir at startup -- loaded eagerly here, not lazily by
	// client.New's caller, so a bad enrolment is a startup failure
	// rather than a mysterious first-request TLS error.
	CACert     []byte
	ClientCert []byte
	ClientKey  []byte

	// TokenPath and PositionPath are where this agent persists its own
	// state inside StateDir.
	TokenPath    string
	PositionPath string
}

// loadConfig reads and validates every required input. A missing
// environment variable or an unreadable state-dir file is reported by
// name, so a failed startup's log line says exactly what to fix rather
// than just that something was wrong.
func loadConfig() (Config, error) {
	cfg := Config{
		BirdcageURL: os.Getenv(envBirdcageURL),
		StateDir:    os.Getenv(envStateDir),
		LogPath:     os.Getenv(envLogPath),
		Listen:      os.Getenv(envListen),
	}

	var missing []string
	for _, kv := range []struct {
		name  string
		value string
	}{
		{envBirdcageURL, cfg.BirdcageURL},
		{envStateDir, cfg.StateDir},
		{envLogPath, cfg.LogPath},
		{envListen, cfg.Listen},
	} {
		if kv.value == "" {
			missing = append(missing, kv.name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variable(s): %s", strings.Join(missing, ", "))
	}

	cfg.TokenPath = filepath.Join(cfg.StateDir, tokenFileName)
	cfg.PositionPath = filepath.Join(cfg.StateDir, positionFileName)

	var err error
	if cfg.CACert, err = os.ReadFile(filepath.Join(cfg.StateDir, caFileName)); err != nil {
		return Config{}, fmt.Errorf("read %s: %w", caFileName, err)
	}
	if cfg.ClientCert, err = os.ReadFile(filepath.Join(cfg.StateDir, clientCertFileName)); err != nil {
		return Config{}, fmt.Errorf("read %s: %w", clientCertFileName, err)
	}
	if cfg.ClientKey, err = os.ReadFile(filepath.Join(cfg.StateDir, clientKeyFileName)); err != nil {
		return Config{}, fmt.Errorf("read %s: %w", clientKeyFileName, err)
	}

	return cfg, nil
}
