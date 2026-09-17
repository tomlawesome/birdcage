package client

import "errors"

// ErrUnauthorized is returned when birdcage answers 401: the presented
// token is missing, unknown or revoked, and #32 makes those three
// indistinguishable on purpose (its own fail-closed rule: "uniform 401,
// identical in status and shape across all three"). #48's fail-closed
// rule: "on persistent 401 ... the agent has no channel to birdcage. It
// says so locally ... recovery is re-enrolment via #47." Deciding what
// "persistent" means, and acting on it, is the caller's job; this
// package reports each 401 as it happens and never treats one as
// retryable on its own.
var ErrUnauthorized = errors.New("client: unauthorized (token missing, unknown or revoked)")

// RetryableError wraps a failure the caller should retry on its own
// cadence -- #32's once-a-minute push retry, or the next poll/heartbeat
// cycle -- and never a permanent per-event rejection. It covers: birdcage
// said try again (429, 5xx -- #32's transport semantics: "429, 5xx,
// timeouts and connection failures mean retry"); birdcage's answer could
// not be trusted (a malformed or oversized response body -- #48's
// fail-closed shape: "uncertainty always resolves toward re-reading,
// retrying or refusing -- never toward skipping, trusting or
// downgrading"); or the call never completed at all (dial, TLS,
// timeout, a refused redirect, a canceled context).
type RetryableError struct {
	err error
}

func (e *RetryableError) Error() string { return "client: retryable: " + e.err.Error() }

func (e *RetryableError) Unwrap() error { return e.err }

// retryable wraps err as a *RetryableError, the one place every
// retryable classification in this package goes through.
func retryable(err error) error {
	return &RetryableError{err: err}
}

// IsRetryable reports whether err (or anything it wraps) is a
// *RetryableError -- the split #48 asks this package to make explicit:
// "An event birdcage permanently rejects is reported to the caller as
// rejected ... an infrastructure failure is reported as retryable and is
// NEVER turned into a rejection."
func IsRetryable(err error) bool {
	var re *RetryableError
	return errors.As(err, &re)
}

// IsUnauthorized reports whether err is ErrUnauthorized.
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrUnauthorized)
}
