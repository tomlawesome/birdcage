package auth

import (
	"testing"
	"time"
)

// SetSessionIdle shortens the session idle limit for one test.
func SetSessionIdle(t *testing.T, d time.Duration) {
	old := sessionIdle
	sessionIdle = d
	t.Cleanup(func() { sessionIdle = old })
}
