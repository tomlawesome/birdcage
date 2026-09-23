package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// loadToken reads the bearer token enrolment wrote to path. Unlike
// cmd/mockingbird's TokenStore, this is a single read with no rotation:
// #108's slice does not add a rotation loop (out of scope, "no scanner
// heartbeat in slice 1" for the same field-split reason token rotation
// would need), so the token this process starts with is the token it
// uses for its whole lifetime -- rotate.go's rotation loop is honeypot
// infrastructure this binary does not link in (agentkind.Scanner's own
// dependency fence).
func loadToken(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// safeErr, not %w: path is under StateDir, one of the values
		// this agent must never log (safelog.go).
		return "", fmt.Errorf("read token file: %s", safeErr(err))
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("token file is empty")
	}
	return token, nil
}
