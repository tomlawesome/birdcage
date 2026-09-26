// Command holder is issue #126's fix for a namespace two other
// containers depend on: it does nothing except own a network address and
// the SMB lure's audit volume, so restarting the canary (Mockingbird) or
// the SMB lure never take the other one's network namespace down with
// them.
//
// The problem this replaces: the SMB lure joins the canary container's
// network namespace with `--network container:<mockingbird>` (#87
// decision 3), so 445 sits on the canary's own address. `docker restart`
// on the canary destroys that namespace -- the lure stays `running` with
// nothing listening on 445, and only restarting the lure too brings it
// back (docs/enrolment.md, "Restarting the canary takes the lure with
// it"). The owner's decision (issue #126, 2026-09-26): a third,
// do-nothing container owns the address instead, and the canary and the
// lure both join *it* with `--network container:<holder>`. Restarting
// either one now leaves the shared namespace alone, because neither of
// them owns it.
//
// It also holds the `smb-audit` volume (`-v smb-audit:/audit:ro` in the
// run command cmd/birdcage/canary_lure.go prints): a tmpfs volume's
// backing memory is freed the moment no container has it mounted, so
// without a permanent holder, a moment where both the canary and the
// lure are down at once would silently lose any audit lines neither had
// read yet.
//
// This is deliberately its own image (issue #126, owner: no unused code
// in it, nothing to patch) rather than a Mockingbird subcommand: it
// imports nothing of birdcage's own code, needs no configuration, and
// its whole job is to sit still. `main` blocks until SIGTERM or SIGINT
// (Docker's own stop signal and an operator's Ctrl-C) and exits 0 --
// `docker restart` on the canary or the lure never touches this
// container at all, so this exit path is only ever hit on purpose:
// `docker stop holder` or shutting the host down.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// version is stamped at build time (-ldflags "-X main.version=..."),
// matching cmd/birdcage, cmd/mockingbird and cmd/nightjar's own
// convention exactly, so the release pipeline can ask this image the
// same question it asks the others (`docker run <image> version`,
// docs/releasing.md's `--expect-stamp`).
var version = "dev"

func main() {
	// `holder version` prints the stamped build version and exits, before
	// anything else runs -- matching every other binary's own `version`
	// argument. Without this check, `docker run <image> version` would
	// just run this file's ordinary wait loop under the argument
	// "version", ignore it, and hang the release job that asked.
	if len(os.Args) > 1 && os.Args[1] == "version" {
		if err := runVersion(os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}

	_, _ = fmt.Fprintf(os.Stdout, "holder %s: waiting for SIGTERM or SIGINT\n", version)
	waitForShutdown(context.Background(), os.Stdout)
}

// waitForShutdown blocks until ctx is done or the process receives
// SIGTERM (Docker's default stop signal) or SIGINT (an operator's own
// Ctrl-C on a foreground run), then returns -- main exits 0 immediately
// after, which is the whole of what this container promises: it goes
// down cleanly when asked, and never on its own.
//
// Split out from main so a test can drive it with a context it controls,
// rather than needing to send this process a real signal.
func waitForShutdown(ctx context.Context, out io.Writer) {
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	<-sigCtx.Done()
	_, _ = fmt.Fprintln(out, "holder: stopping")
}
