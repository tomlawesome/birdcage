package main

import "github.com/tomlawesome/birdcage/internal/agent/client"

// authedRetry is the uniform 401 handling #48 decision 4 asks every loop
// that authenticates to birdcage to share: "on ErrUnauthorized, re-check
// the token store in case rotation swapped the token underneath the
// request, and retry once."
//
// call is invoked with ts's current token. If it succeeds, or fails with
// anything other than client.ErrUnauthorized, that result is returned
// unchanged -- authedRetry only ever gets involved on a 401.
//
// On a 401, ts is re-checked: if rotate (the only writer of TokenStore)
// swapped in a different token while call was in flight, call runs once
// more with that new token, and *that* result is returned. If the token
// is unchanged, retrying would only repeat the same 401 -- the current
// token itself is refused, and authedRetry returns the original error
// so the caller can log it and move on. Either way, the agent never
// invents a path back to a token mint; recovery is re-enrolment (#47).
func authedRetry(ts *TokenStore, call func(token string) error) error {
	token := ts.Current()
	err := call(token)
	if err == nil || !client.IsUnauthorized(err) {
		return err
	}

	retryToken := ts.Current()
	if retryToken == token {
		return err
	}
	return call(retryToken)
}
