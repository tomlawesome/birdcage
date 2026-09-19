package main

import (
	"errors"
	"io/fs"
	"net"
	"strings"
)

// safeErr renders err's message with any filesystem path or network
// address it names redacted, for a component logger to print.
//
// This package's own doc comment (main.go) says what must never appear
// in this agent's log output: the token, any certificate path or
// content, the receiver's listen address, the log path, and the state
// directory. Every one of those except the token itself is something
// the standard library's own error types embed verbatim in their own
// Error() text -- *fs.PathError carries the exact path an os.Open/
// os.ReadFile/os.WriteFile call failed on (StateDir, LogPath and every
// file under StateDir all reach here this way), and *net.OpError
// carries the exact address a Listen/Dial failed on (the receiver's
// Listen address reaches here this way, from internal/agent/receiver.
// New's net.Listen). A caller that formats err with %v/%w without
// passing it through this first would leak whichever of those the
// error happened to be about, however carefully the surrounding
// message text was chosen.
//
// Substituting a placeholder for exactly the offending path/address
// (found via errors.As, not string matching against cfg's own fields)
// keeps the rest of the error's wrapped context -- "queue: read
// position file: open <path redacted>: permission denied" still says
// which operation and why, just not where.
func safeErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()

	var pathErr *fs.PathError
	if errors.As(err, &pathErr) && pathErr.Path != "" {
		msg = strings.ReplaceAll(msg, pathErr.Path, "<path redacted>")
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Addr != nil {
		msg = strings.ReplaceAll(msg, opErr.Addr.String(), "<address redacted>")
	}

	return msg
}
