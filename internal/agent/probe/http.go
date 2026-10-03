package probe

import (
	"context"
	"fmt"
)

// probeHTTP plants marker as the username of a login POST to
// /index.html -- the only request OpenCanary's http module logs with an
// attacker-supplied field in it. opencanary/modules/http.py serves the
// skin's login page at /index.html alone: a GET there logs only the
// path and User-Agent (logtype 3000), any other path is a static 404
// that logs nothing, and only a POST to the login page logs USERNAME
// and PASSWORD (logtype 3001). MR !60 pipeline 1524 showed the earlier
// "marker in the path" shape landing on that silent 404. The header
// carries the marker too, harmlessly, for any skin that logs headers.
//
// This writes a plain HTTP/1.1 request over a raw TCP connection rather
// than using net/http's client, deliberately: internal/selftest's own
// doc comment on Target.DestPort notes that http and https share one
// service name and are told apart only by which port answered, which
// this package has no way to know ahead of the connection. A plaintext
// request against a TLS-only listener will not be understood as HTTP,
// producing no matching event -- an open question for #46 to settle
// (flagged in the build report), not a case this carrier guesses at.
func probeHTTP(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialTCP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	body := "username=" + marker + "&password=" + selfTestPassword
	req := fmt.Sprintf(
		"POST /index.html HTTP/1.1\r\nHost: %s\r\nX-Birdcage-Selftest: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		address, marker, len(body), body,
	)
	_, err = conn.Write([]byte(req))
	return err
}
