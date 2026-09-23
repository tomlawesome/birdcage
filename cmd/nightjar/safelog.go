package main

import (
	"errors"
	"io/fs"
	"net"
	"strings"
)

// safeErr renders err's message with any filesystem path or network
// address it names redacted, for a log line or a startup error. This
// agent must never log the bearer token, any certificate's path or
// content, or the state directory -- the standard library's own error
// types embed exactly the latter verbatim in their own Error() text
// (*fs.PathError for every os.ReadFile call under StateDir), which is
// what this guards against. Duplicated from
// cmd/mockingbird/safelog.go rather than shared: safelog stays private
// to each cmd package, the same choice
// internal/agent/enrolment.redactErr's own doc comment already makes and
// explains.
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
