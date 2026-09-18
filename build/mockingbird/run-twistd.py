# Starts twistd from Python itself. pip's --target install carries no
# console-script for it, and OpenCanary's own opencanaryd launcher is
# bash plus sudo, neither of which exists in the runtime image. twistd
# reads its arguments from sys.argv, so the Dockerfile's CMD passes them
# straight through.
from twisted.scripts.twistd import run

run()
