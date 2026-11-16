// Package authstore is birdcage's persist.Backend for the shared auth
// module (gauntlet): each of its stores -- accounts, tokens, sign-in
// history -- is one document kept in one row of the auth_documents table
// (migration 0029, ADR-0016 decision 2), so sign-in state lives in
// birdcage's own database, on SQLite or Postgres alike, and moves with
// its backups.
//
// The pattern is optimistic concurrency by compare-and-swap on a version
// column: a write names the version it read and succeeds only while that
// is still the stored one. Two processes over one database (a running
// server and a command-line tool) therefore never write over each other
// unseen; the loser gets persist.ErrConflict and reloads.
//
// The documents arrive already sealed: callers wrap a Backend in
// persist.Encrypt before handing it to gauntlet, so this package only
// ever stores and returns opaque bytes.
package authstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/tomlawesome/gauntlet/persist"

	"github.com/tomlawesome/birdcage/internal/db"
)

// Backend is one store's document, in the auth_documents row named name.
type Backend struct {
	database *db.DB
	name     string
}

var (
	_ persist.Backend       = (*Backend)(nil)
	_ persist.VersionReader = (*Backend)(nil)
)

// NewBackend returns the backend for the store called name. It borrows
// database: Close does not close it, because the one database is shared
// by the whole process.
func NewBackend(database *db.DB, name string) persist.Backend {
	return &Backend{database: database, name: name}
}

// Load reads the current document. A store never written is a zero
// Snapshot and a nil error, the normal first run.
func (b *Backend) Load(ctx context.Context) (persist.Snapshot, error) {
	var payload []byte
	var version int64
	err := b.database.QueryRowContext(ctx,
		`SELECT payload, version FROM auth_documents WHERE name = ?`, b.name,
	).Scan(&payload, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return persist.Snapshot{}, nil
	}
	if err != nil {
		return persist.Snapshot{}, fmt.Errorf("authstore: load %s: %w", b.name, err)
	}
	return persist.Snapshot{Payload: payload, Version: version, Exists: true}, nil
}

// Version reports the stored version without moving the document. It is
// the optional persist.VersionReader capability gauntlet polls for
// staleness, so a request does not pull the whole document.
func (b *Backend) Version(ctx context.Context) (int64, bool, error) {
	var version int64
	err := b.database.QueryRowContext(ctx,
		`SELECT version FROM auth_documents WHERE name = ?`, b.name,
	).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("authstore: read version of %s: %w", b.name, err)
	}
	return version, true, nil
}

// Save writes payload if the stored version is still expect and returns
// the new version. expect == 0 means "create": it inserts only when no
// row exists. Any miss -- a row where there should be none, no row or a
// different version where there should be one -- is persist.ErrConflict,
// reported as a plain refusal to write, never as a failure.
func (b *Backend) Save(ctx context.Context, payload []byte, expect int64) (int64, error) {
	if payload == nil {
		// An empty document is a real stored state; the column is NOT NULL.
		payload = []byte{}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	next := expect + 1

	var res sql.Result
	var err error
	if expect == 0 {
		res, err = b.database.ExecContext(ctx,
			`INSERT INTO auth_documents (name, payload, version, updated_at) VALUES (?, ?, ?, ?)
			 ON CONFLICT (name) DO NOTHING`,
			b.name, payload, next, now)
	} else {
		res, err = b.database.ExecContext(ctx,
			`UPDATE auth_documents SET payload = ?, version = ?, updated_at = ? WHERE name = ? AND version = ?`,
			payload, next, now, b.name, expect)
	}
	if err != nil {
		return 0, fmt.Errorf("authstore: save %s: %w", b.name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("authstore: save %s: %w", b.name, err)
	}
	if n == 0 {
		return 0, persist.ErrConflict
	}
	return next, nil
}

// Close does nothing: the database belongs to the process, not to this
// backend.
func (b *Backend) Close() error { return nil }

// Describe names the store for logs. It carries no address or credential.
func (b *Backend) Describe() string {
	return fmt.Sprintf("birdcage database, auth document %q", b.name)
}
