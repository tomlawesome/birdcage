package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// TokenStore holds the agent's current bearer token in memory, guarded
// by a mutex, alongside the path it is durably written to (#48 decision
// 4: "Mutex-guarded current token plus its file path"). Current is
// called at request-build time by every loop that authenticates to
// birdcage; no loop may cache a token across requests -- only rotate
// (rotate.go), TokenStore's single writer, ever knows when the value
// underneath has changed, and a cached copy would silently keep
// presenting a token that is about to be, or already has been, revoked.
type TokenStore struct {
	mu      sync.Mutex
	current string
	path    string
}

// loadTokenStore reads the token file at path and returns a TokenStore
// seeded with its contents. A missing or unreadable file, or one that is
// empty after trimming whitespace, is a startup failure: #47's enrolment
// is what writes this file initially, so its absence or corruption means
// enrolment never completed or was tampered with, either of which #48
// decision 1 requires to fail loudly rather than run half-credentialed.
func loadTokenStore(path string) (*TokenStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil, errors.New("token file is empty")
	}
	return &TokenStore{current: token, path: path}, nil
}

// Current returns the token the caller must present on its very next
// request. Callers never cache the result across requests (#48 decision
// 4): rotate can swap the value underneath at any time, and every loop
// calls Current fresh at request-build time so it always presents
// whatever is durably on disk right now.
func (s *TokenStore) Current() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// set updates the in-memory current token. Only rotate (rotate.go) calls
// this, and only after writing the same value durably to s.path first --
// #48's rotation invariant, "never send any request with a token that is
// not durably on disk," depends on set never being called before that
// write succeeds.
func (s *TokenStore) set(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = token
}
