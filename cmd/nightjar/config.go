package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/renewal"
)

// Environment variables this agent reads -- the only configuration
// surface it has, matching cmd/mockingbird's own #48 decision 6 ("no
// config file ... a local parse surface on a hostile box is itself a
// risk"), applied here even though Nightjar is privileged rather than a
// deliberate lure: the host it runs on is still not somewhere to trust a
// parser with attacker-reachable input.
const (
	// envBirdcageURL is birdcage's ingest origin -- see
	// cmd/mockingbird/config.go's own envBirdcageURL for the identical
	// reasoning, duplicated per agent kind rather than shared.
	envBirdcageURL = "NIGHTJAR_BIRDCAGE_URL"
	// envStateDir holds the enrolment-written CA certificate, mTLS
	// client certificate/key and this agent's own bearer token. Fixed at
	// /var/lib/nightjar by build/nightjar/Dockerfile's ENV, not operator
	// configurable, the same way MOCKINGBIRD_STATE_DIR is.
	envStateDir = "NIGHTJAR_STATE_DIR"
	// envCAPin and envDeployToken are the enrolment pin and one-time
	// token `birdcage agent enrol --kind scanner` prints -- read only at
	// boot, only when the state directory holds none of enrolStateFiles
	// yet.
	envCAPin       = "NIGHTJAR_CA_PIN"
	envDeployToken = "NIGHTJAR_DEPLOY_TOKEN"
	// envScanIntervalS overrides defaultScanIntervalS -- present for
	// operators and CI who want a faster cadence than a fresh vulnerability
	// database and a full host walk justify by default; unset or
	// non-positive falls back to the default.
	envScanIntervalS = "NIGHTJAR_SCAN_INTERVAL_S"
	// envLogLevel selects internal/logging's threshold, named and read
	// the same way cmd/mockingbird's own envLogLevel is.
	envLogLevel = "NIGHTJAR_LOG_LEVEL"
)

// File names inside StateDir -- the same four cmd/mockingbird's
// enrolStateFiles names (#108's shared internal/agent/enrolment
// package), since both agent kinds persist the same enrolment output.
// Nightjar has no position file (no log tailer) and does not persist
// the enrolment response's admin-approval/release addresses -- it has
// no use for either.
const (
	tokenFileName      = "token"
	caFileName         = "ca.pem"
	clientCertFileName = "client.pem"
	clientKeyFileName  = "client-key.pem"
	// ingestURLFileName is written once, at enrolment, from POST
	// /enrol/hello's own response -- the ingest listener's address,
	// which is a different address from envBirdcageURL (the enrolment
	// listener). loadConfig prefers it once it exists, matching
	// cmd/mockingbird/config.go's own rule.
	ingestURLFileName = "ingest-url"
)

// enrolStateFiles are the files whose presence means "already enrolled"
// (internal/agent/enrolment.EnsureEnrolled's own RequiredFiles).
var enrolStateFiles = []string{caFileName, clientCertFileName, clientKeyFileName, tokenFileName}

// hostRoot is where the run command's `-v /:/host:ro` bind lands inside
// the container -- fixed, not configurable: it is load-bearing for
// hostmask.Check (checkMounts.go) and for cmd/birdcage's enrol renderer,
// which must agree on it without either side offering the other a
// competing value.
const hostRoot = "/host"

// grypeBin is the pinned Grype binary's path inside the image
// (build/nightjar/Dockerfile), fixed for the same reason hostRoot is.
const grypeBin = "/usr/local/bin/grype"

// defaultScanIntervalS is how often Nightjar re-scans once its first,
// immediate scan completes. Grype refreshes its vulnerability database
// on every run (ADR-0010's "Engine: Grype" and #108's owner-accepted
// cache decision), and a full host directory walk is not free, so this
// is deliberately hours rather than minutes -- six hours, a cadence
// #108's design left unspecified; revisit with a real deployment's
// signal rather than guessing tighter.
const defaultScanIntervalS = 6 * 60 * 60

// Config is every input this agent reads at startup.
type Config struct {
	BirdcageURL  string
	StateDir     string
	ScanInterval time.Duration

	CACert     []byte
	ClientCert []byte
	ClientKey  []byte

	TokenPath string
}

// loadConfig reads and validates every required input, enrolling first
// if this boot needs to (ensureEnrolled, enrol.go) -- the same shape
// cmd/mockingbird/config.go's loadConfig follows.
func loadConfig() (Config, error) {
	cfg := Config{
		BirdcageURL: os.Getenv(envBirdcageURL),
		StateDir:    os.Getenv(envStateDir),
	}

	var missing []string
	for _, kv := range []struct{ name, value string }{
		{envBirdcageURL, cfg.BirdcageURL},
		{envStateDir, cfg.StateDir},
	} {
		if kv.value == "" {
			missing = append(missing, kv.name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variable(s): %s", strings.Join(missing, ", "))
	}

	if err := ensureEnrolled(cfg.StateDir, cfg.BirdcageURL, os.Getenv(envCAPin), os.Getenv(envDeployToken)); err != nil {
		return Config{}, err
	}

	cfg.TokenPath = filepath.Join(cfg.StateDir, tokenFileName)

	// ADR-0012 B2: finish or discard whatever a certificate renewal left
	// staged before this boot reads clientCertFileName/clientKeyFileName
	// below -- see internal/agent/renewal's own doc comment and
	// cmd/mockingbird/config.go's identical call for why.
	if err := renewal.RecoverPendingSwap(cfg.StateDir, clientKeyFileName, clientCertFileName); err != nil {
		return Config{}, fmt.Errorf("recover pending certificate renewal: %s", safeErr(err))
	}

	// BaseURL prefers whatever enrolment itself learned the ingest
	// listener's address to be, exactly as cmd/mockingbird/config.go's
	// own loadConfig does -- envBirdcageURL names the enrolment
	// listener, a different address.
	if raw, err := os.ReadFile(filepath.Join(cfg.StateDir, ingestURLFileName)); err == nil {
		cfg.BirdcageURL = strings.TrimSpace(string(raw))
	}

	cfg.ScanInterval = time.Duration(defaultScanIntervalS) * time.Second
	if raw := os.Getenv(envScanIntervalS); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("%s=%q is not a positive integer", envScanIntervalS, raw)
		}
		cfg.ScanInterval = time.Duration(n) * time.Second
	}

	var err error
	if cfg.CACert, err = os.ReadFile(filepath.Join(cfg.StateDir, caFileName)); err != nil {
		return Config{}, fmt.Errorf("read %s: %s", caFileName, safeErr(err))
	}
	if cfg.ClientCert, err = os.ReadFile(filepath.Join(cfg.StateDir, clientCertFileName)); err != nil {
		return Config{}, fmt.Errorf("read %s: %s", clientCertFileName, safeErr(err))
	}
	if cfg.ClientKey, err = os.ReadFile(filepath.Join(cfg.StateDir, clientKeyFileName)); err != nil {
		return Config{}, fmt.Errorf("read %s: %s", clientKeyFileName, safeErr(err))
	}

	return cfg, nil
}
