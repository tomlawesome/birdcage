package probe

import (
	"context"
	"fmt"
)

// probeHTTP plants marker in both the request path and a header, so it
// lands wherever OpenCanary's http module actually records it (#46
// carrier table: "the request path and/or a header").
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

	req := fmt.Sprintf(
		"GET /%s HTTP/1.1\r\nHost: %s\r\nX-Birdcage-Selftest: %s\r\nConnection: close\r\n\r\n",
		marker, address, marker,
	)
	_, err = conn.Write([]byte(req))
	return err
}
