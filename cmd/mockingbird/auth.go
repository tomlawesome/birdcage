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
	_, err := authedRetryValue(ts, func(token string) (struct{}, error) {
		return struct{}{}, call(token)
	})
	return err
}

// authedRetryValue is authedRetry's counterpart for a call that also
// returns a value -- the sender's client.PushBatch and the command
// poll's client.PollCommand, both added in this slice. Same rule, same
// shape, generalized once with Go's generics rather than copied a
// second and third time: on a 401, re-check the token store in case
// rotate swapped the token underneath the in-flight request, and retry
// exactly once with whatever is current now. A retry that also fails
// returns its own result and error, not the first attempt's -- matching
// authedRetry's own TestAuthedRetryRetryAlsoUnauthorized.
func authedRetryValue[T any](ts *TokenStore, call func(token string) (T, error)) (T, error) {
	token := ts.Current()
	val, err := call(token)
	if err == nil || !client.IsUnauthorized(err) {
		return val, err
	}

	retryToken := ts.Current()
	if retryToken == token {
		return val, err
	}
	return call(retryToken)
}
