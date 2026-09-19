package enrol

import "errors"

// ErrRefused is returned when birdcage answers either enrolment route with
// 401: the deploy token or enrolment secret presented is unknown, expired,
// already used, or otherwise not honoured. internal/enrol's own handler
// makes every refusal reason indistinguishable on purpose (design note
// decision 1), so this package does too -- there is nothing more specific
// for a caller to branch on.
//
// A caller must treat ErrRefused as immediately fatal, never retryable: the
// credential that was refused is exactly as refused a second later.
var ErrRefused = errors.New("enrol: refused")

// RetryableError wraps a failure that never reached birdcage at all -- a
// dial failure, TLS handshake failure, timeout, refused redirect or canceled
// context -- the only class of failure worth retrying here. Anything
// birdcage actually answered (401, a malformed body, an unexpected status)
// is deterministic and wrapping it in a retry loop would only waste the
// enrolment window for no chance of a different outcome.
type RetryableError struct {
	err error
}

func (e *RetryableError) Error() string { return "enrol: retryable: " + e.err.Error() }

func (e *RetryableError) Unwrap() error { return e.err }

// retryable wraps err as a *RetryableError, the one place in this package
// that classification happens.
func retryable(err error) error {
	return &RetryableError{err: err}
}

// IsRetryable reports whether err (or anything it wraps) is a
// *RetryableError.
func IsRetryable(err error) bool {
	var re *RetryableError
	return errors.As(err, &re)
}
