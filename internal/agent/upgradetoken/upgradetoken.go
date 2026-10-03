// Package upgradetoken is the agent side of issue #54's upgrade token:
// the `upgrade-token` subcommand both agent binaries carry (mockingbird
// and nightjar), which the upgrade command birdcage prints runs once,
// in a throwaway container of the new image, after the old agent is
// removed and before the new one starts.
//
// It reads the token from stdin -- never argv, never the environment,
// both of which outlive the moment (argv in a process listing, the
// environment in the container's stored configuration) -- loads the
// agent's own credential from the state volume, presents the token to
// birdcage over that credential, prints one line, and exits. The state
// volume is mounted read-only by the printed command, and nothing here
// writes a file: the token exists in this process's memory and nowhere
// else.
//
// Why before the new agent starts rather than after: ADR-0012 B4
// observes an agent's build on its heartbeat, and a new agent heartbeats
// the moment it starts. A window opened after that first heartbeat would
// open after the old-build/new-build pair had already been flagged.
// Presenting first means no step of the command has to wait for the new
// agent to be up at all.
package upgradetoken

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// State file names inside the agent's state directory -- the same names
// both agents' own config.go use (internal/agent/enrolment writes them).
const (
	tokenFileName      = "token"
	caFileName         = "ca.pem"
	clientCertFileName = "client.pem"
	clientKeyFileName  = "client-key.pem"
	ingestURLFileName  = "ingest-url"
)

// tokenLen is a minted upgrade token's exact length: 32 random bytes,
// hex-encoded (internal/store's upgradeTokenBytes).
const tokenLen = 64

// maxStdinBytes caps what is read from stdin: one token and a newline,
// with room for stray whitespace, and nothing that could make this
// process hold an unbounded paste in memory.
const maxStdinBytes = 256

// DefaultRetryFor is how long Run keeps presenting a token birdcage has
// not answered (unreachable, 429, 5xx). The token is valid for fifteen
// minutes; a minute covers a birdcage restart or a brief network blip
// without holding up the rest of the upgrade for long.
const DefaultRetryFor = 60 * time.Second

// ErrRefused is Run's error when birdcage answered and refused the token
// (or refused the agent's own credential): the caller exits non-zero.
var ErrRefused = errors.New("upgradetoken: refused")

// ErrUsage is Run's error for input that is not a token.
var ErrUsage = errors.New("upgradetoken: usage")

// Options is Run's input.
type Options struct {
	// StateDir is the agent's own state directory (the kind's
	// *_STATE_DIR, fixed by its Dockerfile).
	StateDir string
	// FallbackURL is the kind's *_BIRDCAGE_URL, used only when the state
	// directory has no ingest-url file (a state directory from before
	// enrolment recorded one).
	FallbackURL string
	Stdin       io.Reader
	Stdout      io.Writer
	// RetryFor bounds retries of an unanswered presentation; zero means
	// DefaultRetryFor.
	RetryFor time.Duration
	// Sleep waits between attempts; nil means a context-aware sleep.
	// Tests pass one that returns at once.
	Sleep func(context.Context, time.Duration) error
}

// Run is the whole subcommand. The returned error is ErrUsage, ErrRefused
// (both already explained on Stdout), or something the caller prints.
func Run(ctx context.Context, o Options) error {
	token, err := readToken(o.Stdin)
	if err != nil {
		_, _ = fmt.Fprintf(o.Stdout, "upgrade token: %v\n", err)
		return ErrUsage
	}

	cfg, bearer, err := loadCredential(o.StateDir, o.FallbackURL)
	if err != nil {
		return err
	}
	c, err := client.New(cfg)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	retryFor := o.RetryFor
	if retryFor <= 0 {
		retryFor = DefaultRetryFor
	}
	sleep := o.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}

	deadline := time.Now().Add(retryFor)
	backoff := time.Second
	for {
		answer, err := c.PresentUpgradeToken(ctx, bearer, token)
		switch {
		case err == nil && answer.Accepted:
			_, _ = fmt.Fprintf(o.Stdout, "upgrade token accepted: until %s birdcage will not flag this agent's old build as credential_conflict\n",
				answer.WindowUntil.UTC().Format(time.RFC3339))
			return nil
		case err == nil:
			_, _ = fmt.Fprintf(o.Stdout, "upgrade token refused: %s. The upgrade goes on; the agent may show credential_conflict for about two minutes.\n",
				printable(answer.Reason))
			return ErrRefused
		case client.IsUnauthorized(err):
			_, _ = fmt.Fprintln(o.Stdout, "upgrade token not presented: birdcage refused this agent's own credential (401). The upgrade goes on; see docs/enrolment.md if the agent stays down.")
			return ErrRefused
		case errors.Is(err, client.ErrUpgradeTokenMalformed):
			_, _ = fmt.Fprintln(o.Stdout, "upgrade token not presented: birdcage refused the request as malformed.")
			return ErrRefused
		}
		if !client.IsRetryable(err) || time.Now().Add(backoff).After(deadline) {
			_, _ = fmt.Fprintf(o.Stdout, "upgrade token not presented: birdcage did not answer (%s). The upgrade goes on; the agent may show credential_conflict for about two minutes.\n",
				printable(err.Error()))
			return ErrRefused
		}
		if err := sleep(ctx, backoff); err != nil {
			return err
		}
		if backoff < 8*time.Second {
			backoff *= 2
		}
	}
}

// readToken reads one token from r: at most maxStdinBytes, surrounding
// whitespace trimmed, exactly tokenLen lowercase hex characters. The
// error never repeats what was read.
func readToken(r io.Reader) (string, error) {
	if r == nil {
		return "", errors.New("pipe the token on standard input")
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxStdinBytes+1))
	if err != nil {
		return "", fmt.Errorf("read standard input: %w", err)
	}
	if len(raw) > maxStdinBytes {
		return "", errors.New("standard input is longer than one token")
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("pipe the token on standard input")
	}
	if len(token) != tokenLen {
		return "", fmt.Errorf("not an upgrade token (want %d hex characters)", tokenLen)
	}
	for _, c := range token {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("not an upgrade token (want %d hex characters)", tokenLen)
		}
	}
	return token, nil
}

// loadCredential reads the agent's ingest URL, CA, client certificate
// and key, and bearer token from stateDir, writing nothing -- the same
// files the running agent loads, without its boot-time side effects
// (enrolment, finishing a staged renewal), which both write. Errors
// name a file by its bare name, never the directory: the state path is
// on both agents' never-log list.
func loadCredential(stateDir, fallbackURL string) (client.Config, string, error) {
	if stateDir == "" {
		return client.Config{}, "", errors.New("the agent's state directory is not set")
	}
	read := func(name string) ([]byte, error) {
		b, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil {
			var pe *os.PathError
			if errors.As(err, &pe) {
				err = pe.Err
			}
			return nil, fmt.Errorf("read %s: %v", name, err)
		}
		return b, nil
	}

	baseURL := fallbackURL
	if raw, err := os.ReadFile(filepath.Join(stateDir, ingestURLFileName)); err == nil {
		baseURL = strings.TrimSpace(string(raw))
	}
	if baseURL == "" {
		return client.Config{}, "", fmt.Errorf("no birdcage address: no %s in the state directory and no fallback", ingestURLFileName)
	}

	var cfg client.Config
	var err error
	cfg.BaseURL = baseURL
	if cfg.CACert, err = read(caFileName); err != nil {
		return client.Config{}, "", err
	}
	if cfg.ClientCert, err = read(clientCertFileName); err != nil {
		return client.Config{}, "", err
	}
	if cfg.ClientKey, err = read(clientKeyFileName); err != nil {
		return client.Config{}, "", err
	}
	raw, err := read(tokenFileName)
	if err != nil {
		return client.Config{}, "", err
	}
	bearer := strings.TrimSpace(string(raw))
	if bearer == "" {
		return client.Config{}, "", fmt.Errorf("%s is empty", tokenFileName)
	}
	return cfg, bearer, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// printable drops anything but printable characters from s before it
// reaches the operator's terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}
