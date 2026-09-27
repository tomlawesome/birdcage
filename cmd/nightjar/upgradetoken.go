package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/tomlawesome/birdcage/internal/agent/upgradetoken"
)

// runUpgradeToken is `nightjar upgrade-token` (issue #54): the last-but-one
// step of the upgrade command birdcage prints, run once in a throwaway
// container of the new image with the state volume mounted read-only,
// before the new agent itself starts. It reads the upgrade token from
// stdin and presents it over this agent's own credential; see
// internal/agent/upgradetoken for the whole of what it does and why.
//
// args are whatever followed the subcommand. Any at all is refused: the
// token is read from stdin only, and an argument is where a token would
// be visible in a process listing.
//
// Exit status: 0 accepted, 1 refused or not presented, 2 usage.
func runUpgradeToken(args []string, stdin io.Reader, stdout io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stdout, "usage: echo <token> | nightjar upgrade-token (the token is read from standard input, never from an argument)")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := upgradetoken.Run(ctx, upgradetoken.Options{
		StateDir:    os.Getenv(envStateDir),
		FallbackURL: os.Getenv(envBirdcageURL),
		Stdin:       stdin,
		Stdout:      stdout,
	})
	switch {
	case err == nil:
		return 0
	case errors.Is(err, upgradetoken.ErrUsage):
		return 2
	case errors.Is(err, upgradetoken.ErrRefused):
		return 1
	default:
		// safeErr: a file error here could otherwise carry the state
		// directory, which this agent never prints.
		fmt.Fprintf(stdout, "upgrade token not presented: %s\n", safeErr(err))
		return 1
	}
}
