# The image's ENTRYPOINT (issue #132). Two jobs:
#
#   1. `docker run <image> version` prints the stamped build version and
#      exits, matching every other shipped image's `version` argument
#      (docs/releasing.md's --expect-stamp) -- checked first, and before
#      twistd ever sees sys.argv, because ENTRYPOINT+CMD both run through
#      this file: `docker run <image> version` replaces the Dockerfile's
#      CMD entirely, so without this check "version" would be handed to
#      twistd as its own argv instead of being answered. distroless has
#      no shell, so this can't be a shell script the way
#      build/smb-lure/entrypoint.sh and build/holder's own Go binary
#      answer the same argument -- this is the equivalent for an image
#      whose only runtime is Python.
#   2. Otherwise, starts twistd from Python itself: pip's --target
#      install carries no console-script for it, and OpenCanary's own
#      opencanaryd launcher is bash plus sudo, neither of which exists in
#      this image. twistd reads its arguments from sys.argv, so the
#      Dockerfile's CMD (the ordinary "-noy <tac file> --pidfile=" run,
#      unchanged since before the split) passes straight through.
import sys

if len(sys.argv) > 1 and sys.argv[1] == "version":
    with open("/etc/image-version", encoding="ascii") as f:
        sys.stdout.write(f.read())
    sys.exit(0)

from twisted.scripts.twistd import run  # noqa: E402

run()
