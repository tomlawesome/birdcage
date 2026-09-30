// Package startcheck implements issue #70's start-of-day rule: before
// any listener binds, birdcage proves every path it depends on is
// actually usable by the uid/gid it is running as, and refuses to start
// -- never a fallback, never a retry -- naming the path, this process's
// uid/gid, and the fix, if it isn't. A container started against a
// data volume or a mounted certificate owned by the wrong uid used to
// fail confusingly deep inside db.Open or tls.LoadX509KeyPair; this
// package turns that into one clear message at the top of boot.
package startcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// WritableDir proves dir is writable by this process by creating and
// removing a probe file inside it -- the same operation opening the
// database file there is about to need, checked explicitly so a bad
// data directory fails with this package's clear message rather than
// whatever error db.Open happens to surface partway through opening
// the database file itself.
func WritableDir(dir string) error {
	probe := filepath.Join(dir, ".birdcage-startcheck-"+strconv.Itoa(os.Getpid()))
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return unusable(dir, err)
	}
	// A failed Close here is itself evidence dir isn't fully usable (a
	// stale NFS handle, say) -- exactly what this function exists to
	// catch -- so it's worth surfacing rather than silently trying the
	// Remove below anyway.
	if err := f.Close(); err != nil {
		return unusable(dir, err)
	}
	if err := os.Remove(probe); err != nil {
		return unusable(dir, err)
	}
	return nil
}

// ReadableFile proves path can be opened for reading by this process --
// used for the operator-supplied TLS certificate/key files
// (internal/tlsconfig's ModeCert). The CA directory has its own check
// (internal/ca.Load), left as is.
func ReadableFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return unusable(path, err)
	}
	return f.Close()
}

// SecretFile proves path holds a usable secret and returns it: readable
// by this process (ReadableFile's check, with the same message) and not
// empty once a single trailing newline is removed. Used for issue #55's
// BIRDCAGE_MAIL_PASSWORD_FILE, the preferred way to supply the SMTP
// password -- a mounted file that only the birdcage uid can read,
// rather than an environment variable every child process inherits.
//
// One trailing newline is trimmed because `printf` and every text
// editor add one, and a password with a newline welded onto the end
// fails authentication in a way that looks like a wrong password rather
// than like a formatting mistake. Nothing else is trimmed: leading or
// interior whitespace could genuinely be part of a password.
//
// The returned value is a credential. It is never logged, and neither
// is any part of it -- the errors here name the path, never the
// contents.
func SecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", unusable(path, err)
	}
	secret := strings.TrimSuffix(string(b), "\n")
	secret = strings.TrimSuffix(secret, "\r")
	if secret == "" {
		return "", fmt.Errorf("startcheck: %s is empty; it must contain the secret and nothing else", path)
	}
	return secret, nil
}

// unusable formats startcheck's one error shape: the path, this
// process's uid and gid (os.Getuid/os.Getgid -- issue #70's exact
// requirement, so the operator doesn't have to go find them
// separately), the underlying cause, and the fix.
func unusable(path string, cause error) error {
	uid, gid := os.Getuid(), os.Getgid()
	return fmt.Errorf(
		"startcheck: %s is not usable by this process (running as uid %d, gid %d): %w -- fix with `chown %d:%d %s`, or run the container with `--user %d:%d`",
		path, uid, gid, cause, uid, gid, path, uid, gid,
	)
}
