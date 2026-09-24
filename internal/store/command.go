// Package store: this file is the write/claim path for canary_commands
// (issue #32 slice 5b) -- the queue a canary's agent (#48) drains by
// polling the ingest submux. Birdcage never connects to a canary, so a
// command reaches one only because that canary asked for it.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// commandIDBytes is the random byte length behind a canary_commands.id --
// 128 bits, hex-encoded, matching tokenIDBytes.
const commandIDBytes = 16

// CommandKind is the closed set of things birdcage can ask a canary to
// do. Closed here rather than in a SQL CHECK constraint: the constraint
// would have to be written once per engine and would then disagree with
// this list the moment either side changed (0006's comment).
type CommandKind string

// CommandSelfTest orders the canary to prove it can still trigger (#46).
// With CommandScan below, the only kinds M1 mints.
//
// #32 also names an "upgrade" kind. It is deliberately absent: an
// upgrade must not be orderable without an admin's established authority
// to order one (owner, 2026-09-16), birdcage has no admin accounts yet
// (internal/api/api.go's requireAuth placeholder, #8), and the honest way
// to promise "no unattended upgrades" in the meantime is to have no way
// to express one. Adding the constant is the smallest possible change
// once that gate exists -- which is the point of it not being here now.
const CommandSelfTest CommandKind = "selftest"

// CommandScan orders a scanner to run one scan and answer it with the
// run's id (issue #116, ADR-0012 decision 1). Its params are
// ScanParams -- the run id and nothing else: no target is named, since
// the scanner scans only the host it already mounts. Minted only by
// MintScanCommand, which writes the owning self_test_runs row in the
// same transaction.
const CommandScan CommandKind = "scan"

// mintableCommandKinds is what MintCanaryCommand will accept. A kind
// absent from this map cannot be created at all, so it can never be
// claimed, so no agent ever sees it.
var mintableCommandKinds = map[CommandKind]bool{
	CommandSelfTest: true,
	CommandScan:     true,
}

// CanaryCommand is one canary_commands row.
type CanaryCommand struct {
	ID          string
	CanaryID    string
	Kind        CommandKind
	Params      string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	DeliveredAt *time.Time
}

// ErrCommandNotFound is returned by ClaimNextCanaryCommand when a canary
// is owed nothing -- the ordinary case on almost every poll, not a
// failure -- and by LookupCanaryCommand when id names no row.
var ErrCommandNotFound = errors.New("store: canary command not found")

// ErrCommandKindUnknown is returned by MintCanaryCommand for a kind
// outside mintableCommandKinds.
var ErrCommandKindUnknown = errors.New("store: unknown command kind")

// ErrCommandParamsInvalid is returned by MintCanaryCommand when params
// is neither empty nor a valid JSON document.
var ErrCommandParamsInvalid = errors.New("store: invalid command params")

// MintCanaryCommand queues one command for canaryID. expiresAt is stored
// rather than derived so a queued command keeps the lifetime it was given
// even if the default changes later; the caller sets both timestamps, as
// MintCanaryToken's createdAt does.
//
// params is opaque to this package -- a JSON document the agent
// understands (#48) -- and is stored as NULL when empty, so "no
// parameters" is one value in the column rather than two.
func MintCanaryCommand(ctx context.Context, database db.Conn, canaryID string, kind CommandKind, params string, createdAt, expiresAt time.Time) (CanaryCommand, error) {
	if !mintableCommandKinds[kind] {
		return CanaryCommand{}, fmt.Errorf("%w: %q", ErrCommandKindUnknown, kind)
	}
	if params != "" && !json.Valid([]byte(params)) {
		// Checked at the only door into the column, so a claim can hand
		// the stored bytes straight to the agent as JSON without either
		// re-validating them or risking a malformed response body.
		return CanaryCommand{}, fmt.Errorf("%w: params is not valid JSON", ErrCommandParamsInvalid)
	}
	if createdAt.IsZero() || expiresAt.IsZero() {
		return CanaryCommand{}, fmt.Errorf("store: MintCanaryCommand: createdAt and expiresAt must be set by the caller")
	}
	createdAt, expiresAt = createdAt.UTC(), expiresAt.UTC()
	if !expiresAt.After(createdAt) {
		return CanaryCommand{}, fmt.Errorf("store: MintCanaryCommand: expiresAt %s is not after createdAt %s", expiresAt, createdAt)
	}
	id, err := randomHex(commandIDBytes)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("generate command id: %w", err)
	}

	var storedParams any
	if params != "" {
		storedParams = params
	}
	_, err = database.ExecContext(ctx, `
		INSERT INTO canary_commands (id, canary_id, kind, params, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		id, canaryID, string(kind), storedParams,
		createdAt.Format(receivedAtLayout), expiresAt.Format(receivedAtLayout))
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("insert canary command: %w", err)
	}
	return CanaryCommand{
		ID: id, CanaryID: canaryID, Kind: kind, Params: params,
		CreatedAt: createdAt, ExpiresAt: expiresAt,
	}, nil
}

// ClaimNextCanaryCommand hands back the oldest live command owed to
// canaryID and marks it delivered in the same breath, returning
// ErrCommandNotFound when there is nothing to hand over.
//
// Three properties #32 slice 5b is tested on come from here:
//
// Delivered once, never twice. The claim is an UPDATE guarded by
// "delivered_at IS NULL" whose RowsAffected decides the winner, so two
// concurrent polls for one canary cannot both take the same row -- the
// loser moves to the next candidate rather than returning a duplicate.
// The update commits before the caller can write anything to the wire,
// which is the ordering #32 asks for: "a command is marked delivered
// before it is written to the wire -- a crash between the two loses the
// command rather than doubling it."
//
// Expired commands are never delivered. Expiry is judged here, in Go, on
// parsed timestamps: these columns hold RFC3339Nano, which trims trailing
// zeros, so SQL string comparison sorts "…:00Z" after "…:00.5Z" and would
// quietly mis-order and mis-expire. The same trap produced two rotation
// tests that failed now and then before
// RevokeCanaryTokensSupersededBy moved its comparison into Go.
//
// A canary sees only its own commands: canary_id is a WHERE clause on the
// only statement that can select a row, and the caller passes the id from
// the authenticated token, never from a request body.
func ClaimNextCanaryCommand(ctx context.Context, database *db.DB, canaryID string, now time.Time) (CanaryCommand, error) {
	return ClaimNextCanaryCommandOfKinds(ctx, database, canaryID, nil, now)
}

// ClaimNextCanaryCommandOfKinds is ClaimNextCanaryCommand restricted to
// the command kinds in allowed (issue #116: a scanner may claim only
// scan, a honeypot only selftest). A command of any other kind is left
// undelivered -- never handed over and never marked delivered -- so a
// wrongly queued command expires unseen rather than reaching an agent
// that must not act on it. allowed == nil means every kind (the
// original ClaimNextCanaryCommand); an empty, non-nil map allows none,
// which is how a caller fails closed.
func ClaimNextCanaryCommandOfKinds(ctx context.Context, database *db.DB, canaryID string, allowed map[CommandKind]bool, now time.Time) (CanaryCommand, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT id, canary_id, kind, params, created_at, expires_at
		FROM canary_commands
		WHERE canary_id = ? AND delivered_at IS NULL`, canaryID)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("list pending canary commands: %w", err)
	}
	var pending []CanaryCommand
	for rows.Next() {
		cmd, err := scanPendingCommand(rows)
		if err != nil {
			_ = rows.Close()
			return CanaryCommand{}, err
		}
		pending = append(pending, cmd)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return CanaryCommand{}, fmt.Errorf("iterate canary commands: %w", err)
	}
	if err := rows.Close(); err != nil {
		return CanaryCommand{}, fmt.Errorf("close canary commands: %w", err)
	}

	now = now.UTC()
	live := pending[:0]
	for _, cmd := range pending {
		if allowed != nil && !allowed[cmd.Kind] {
			continue
		}
		if cmd.ExpiresAt.After(now) {
			live = append(live, cmd)
		}
	}
	// Oldest first, so a queue that built up during an outage drains in
	// the order it was created rather than newest-first.
	sort.Slice(live, func(i, j int) bool { return live[i].CreatedAt.Before(live[j].CreatedAt) })

	for _, cmd := range live {
		res, err := database.ExecContext(ctx, `
			UPDATE canary_commands SET delivered_at = ?
			WHERE id = ? AND delivered_at IS NULL`,
			now.Format(receivedAtLayout), cmd.ID)
		if err != nil {
			return CanaryCommand{}, fmt.Errorf("claim canary command: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return CanaryCommand{}, fmt.Errorf("rows affected: %w", err)
		}
		if n == 1 {
			delivered := now
			cmd.DeliveredAt = &delivered
			return cmd, nil
		}
		// n == 0: a concurrent poll claimed it between the select and
		// here. Try the next one rather than reporting it as ours.
	}
	return CanaryCommand{}, ErrCommandNotFound
}

// LookupCanaryCommand resolves id to its row regardless of delivery
// state, so tests and any future operator view can see what happened to a
// command after it was handed over.
func LookupCanaryCommand(ctx context.Context, database db.Conn, id string) (CanaryCommand, error) {
	row := database.QueryRowContext(ctx, `
		SELECT id, canary_id, kind, params, created_at, expires_at, delivered_at
		FROM canary_commands WHERE id = ?`, id)
	var (
		cmd         CanaryCommand
		kind        string
		params      *string
		createdAt   string
		expiresAt   string
		deliveredAt *string
	)
	if err := row.Scan(&cmd.ID, &cmd.CanaryID, &kind, &params, &createdAt, &expiresAt, &deliveredAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CanaryCommand{}, ErrCommandNotFound
		}
		return CanaryCommand{}, fmt.Errorf("scan canary command: %w", err)
	}
	cmd.Kind = CommandKind(kind)
	if params != nil {
		cmd.Params = *params
	}
	var err error
	if cmd.CreatedAt, err = time.Parse(receivedAtLayout, createdAt); err != nil {
		return CanaryCommand{}, fmt.Errorf("parse created_at %q: %w", createdAt, err)
	}
	if cmd.ExpiresAt, err = time.Parse(receivedAtLayout, expiresAt); err != nil {
		return CanaryCommand{}, fmt.Errorf("parse expires_at %q: %w", expiresAt, err)
	}
	if deliveredAt != nil {
		parsed, err := time.Parse(receivedAtLayout, *deliveredAt)
		if err != nil {
			return CanaryCommand{}, fmt.Errorf("parse delivered_at %q: %w", *deliveredAt, err)
		}
		cmd.DeliveredAt = &parsed
	}
	return cmd, nil
}

// scanPendingCommand reads one undelivered row -- delivered_at is known
// NULL from the caller's WHERE clause, so it is not selected.
func scanPendingCommand(row rowScanner) (CanaryCommand, error) {
	var (
		cmd       CanaryCommand
		kind      string
		params    *string
		createdAt string
		expiresAt string
	)
	if err := row.Scan(&cmd.ID, &cmd.CanaryID, &kind, &params, &createdAt, &expiresAt); err != nil {
		return CanaryCommand{}, fmt.Errorf("scan canary command: %w", err)
	}
	cmd.Kind = CommandKind(kind)
	if params != nil {
		cmd.Params = *params
	}
	parsed, err := time.Parse(receivedAtLayout, createdAt)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("parse created_at %q: %w", createdAt, err)
	}
	cmd.CreatedAt = parsed
	parsed, err = time.Parse(receivedAtLayout, expiresAt)
	if err != nil {
		return CanaryCommand{}, fmt.Errorf("parse expires_at %q: %w", expiresAt, err)
	}
	cmd.ExpiresAt = parsed
	return cmd, nil
}
