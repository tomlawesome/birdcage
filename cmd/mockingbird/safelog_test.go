package main

import "testing"

// TestSafeErrNilReturnsEmptyString covers safeErr's guard for the
// non-error case: every caller in this package passes whatever a fallible
// operation returned straight through, nil included, and a "<nil>" string
// leaking into a log line would be a small but real regression from
// err.Error() panicking safeErr never gets the chance to redact.
func TestSafeErrNilReturnsEmptyString(t *testing.T) {
	if got := safeErr(nil); got != "" {
		t.Errorf("safeErr(nil) = %q, want empty string", got)
	}
}
