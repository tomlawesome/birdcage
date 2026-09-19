package tlsconfig

import (
	"fmt"
	"net"
	"os"
)

// unixSocketPerm is the exact mode UnixListener chmods the socket file
// to: group-writable as well as owner-writable (0660), so a reverse
// proxy running as a different uid but the same group -- the same
// namespace or shared-volume case ModePlainUnixSocket exists for -- can
// reach it, and nothing else can.
const unixSocketPerm = 0o660

// UnixListener creates a unix domain socket listener at path, mode
// 0660. Any stale socket file already at path -- left behind by an
// unclean shutdown, since a normal one removes it (see main's shutdown
// path) -- is removed first: net.Listen("unix", ...) otherwise fails
// with "address already in use" even though nothing is actually
// listening on it.
//
// Closing the returned listener (directly, or via http.Server.Shutdown)
// already unlinks path -- net.UnixListener's own Close behavior -- so
// the caller only needs to remove it again defensively, tolerating
// "already gone".
func UnixListener(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("tlsconfig: remove stale unix socket %s: %w", path, err)
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("tlsconfig: listen on unix socket %s: %w", path, err)
	}

	// net.Listen creates the socket file at whatever mode the process
	// umask leaves it -- not trustworthy on its own (the same reasoning
	// internal/ca.go's writeFileExcl gives for chmodding after create),
	// so it's set explicitly here.
	if err := os.Chmod(path, unixSocketPerm); err != nil {
		ln.Close()
		os.Remove(path)
		return nil, fmt.Errorf("tlsconfig: chmod unix socket %s: %w", path, err)
	}

	return ln, nil
}
