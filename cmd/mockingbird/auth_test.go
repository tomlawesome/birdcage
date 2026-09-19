package main

import (
	"errors"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// TestAuthedRetrySuccessNoRetry proves a call that succeeds outright is
// never retried.
func TestAuthedRetrySuccessNoRetry(t *testing.T) {
	ts := &TokenStore{current: "tok-a"}
	calls := 0
	err := authedRetry(ts, func(token string) error {
		calls++
		if token != "tok-a" {
			t.Errorf("token = %q, want tok-a", token)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("authedRetry: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

// TestAuthedRetryNonUnauthorizedNotRetried proves a non-401 failure is
// returned as-is, with no retry -- only ErrUnauthorized triggers the
// re-check.
func TestAuthedRetryNonUnauthorizedNotRetried(t *testing.T) {
	ts := &TokenStore{current: "tok-a"}
	wantErr := errors.New("boom")
	calls := 0
	err := authedRetry(ts, func(token string) error {
		calls++
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

// TestAuthedRetryRotationSwapRetriesOnce proves #48 decision 4's uniform
// 401 rule: a 401 on the first call, with the token store showing a
// different value on re-check (rotate swapped it mid-flight), retries
// exactly once with the new token.
func TestAuthedRetryRotationSwapRetriesOnce(t *testing.T) {
	ts := &TokenStore{current: "tok-old"}
	var seen []string
	err := authedRetry(ts, func(token string) error {
		seen = append(seen, token)
		if token == "tok-old" {
			// Simulate rotate swapping the token underneath this
			// request while it was in flight.
			ts.set("tok-new")
			return client.ErrUnauthorized
		}
		return nil
	})
	if err != nil {
		t.Fatalf("authedRetry: %v", err)
	}
	if want := []string{"tok-old", "tok-new"}; !equalStrings(seen, want) {
		t.Fatalf("seen = %v, want %v", seen, want)
	}
}

// TestAuthedRetryNoSwapDoesNotRetry proves the other half of the same
// rule: a 401 with the token store unchanged on re-check means the
// current token itself is refused, and authedRetry returns that error
// without a second, pointless call presenting the identical token again.
func TestAuthedRetryNoSwapDoesNotRetry(t *testing.T) {
	ts := &TokenStore{current: "tok-a"}
	calls := 0
	err := authedRetry(ts, func(token string) error {
		calls++
		return client.ErrUnauthorized
	})
	if !client.IsUnauthorized(err) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (no retry with an unchanged token)", calls)
	}
}

// TestAuthedRetryRetryAlsoUnauthorized proves that when the swapped-in
// token is *also* refused, authedRetry reports that final failure
// (still ErrUnauthorized) rather than the first one.
func TestAuthedRetryRetryAlsoUnauthorized(t *testing.T) {
	ts := &TokenStore{current: "tok-old"}
	calls := 0
	err := authedRetry(ts, func(token string) error {
		calls++
		if token == "tok-old" {
			ts.set("tok-new")
		}
		return client.ErrUnauthorized
	})
	if !client.IsUnauthorized(err) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
