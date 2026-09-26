// Package store: this file is the per-canary settings mechanism issue
// #124 adds -- the channel that lets an operator change a running
// agent's behaviour (issue #86's segment profile, bait names, pace
// floor/ceiling and working hours, the first user) without a container
// restart, in place of the environment variables that were previously
// the only way.
//
// canary_settings is a closed key set validated in Go, the same shape
// settings.go's own settingDefs uses for the fleet-wide settings table:
// ListCanarySettings and SetCanarySettings are the only door into the
// table, and both reject a key outside canarySettingDefs or a value its
// validate func rejects before either ever reaches SQL. Each row also
// carries a version, incremented on every write to that key, and this
// package's SettingsHash is the sha256 hex of the current row set for a
// canary -- what internal/ingest/heartbeat.go compares against the
// agent's own reported hash to decide whether to push, and what
// internal/api/canary.go compares against agents.settings_hash to
// decide whether the facts column shows a row as confirmed.
//
// internal/agent/client's own SettingsHash function mirrors this
// package's hashSettings byte for byte -- deliberately, since an agent
// binary must never import internal/store (ADR-0008 decision 4). Change
// one, change the other, or the two sides can never agree on a hash.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/poisoner"
	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
)

// CanarySettingKey is the closed set of keys canary_settings can hold.
type CanarySettingKey string

const (
	// CanarySettingSegmentProfile is issue #86's segment profile:
	// "windows" (default), "linux" or "off". Validated with
	// poisoner.ParseProfile -- the exact function `birdcage agent enrol
	// --segment-profile` and the agent's own MOCKINGBIRD_POISONER_PROFILE
	// env var already use, so what this write path accepts and what the
	// agent accepts can never drift.
	CanarySettingSegmentProfile CanarySettingKey = "segment_profile"

	// CanarySettingBaitNames is the operator's own bait names,
	// comma-separated, validated with poisoner.ParseNames -- the same
	// parser `--bait-names` and MOCKINGBIRD_POISONER_NAMES use. Never
	// logged: see poisoner.go's own package comment and this package's
	// SettingsHash, which hashes the value without ever printing it.
	CanarySettingBaitNames CanarySettingKey = "bait_names"

	// CanarySettingPaceFloor and CanarySettingPaceCeiling are the
	// longest/shortest gap between poisoner bursts, a Go duration string
	// such as "2h", validated the same way MOCKINGBIRD_POISONER_FLOOR/
	// _CEILING are: it must parse and be positive.
	CanarySettingPaceFloor   CanarySettingKey = "pace_floor"
	CanarySettingPaceCeiling CanarySettingKey = "pace_ceiling"

	// CanarySettingWorkingHours is the poisoner's working-hours window,
	// validated with poisoner.ParseWorkingHours -- the same parser
	// MOCKINGBIRD_POISONER_HOURS uses.
	CanarySettingWorkingHours CanarySettingKey = "working_hours"
)

// orderedCanarySettingKeys is canarySettingDefs' key order for anything
// that lists every key, the same reason settings.go's
// orderedSettingKeys exists: stable output over a map's inherently
// unordered iteration.
var orderedCanarySettingKeys = []CanarySettingKey{
	CanarySettingSegmentProfile,
	CanarySettingBaitNames,
	CanarySettingPaceFloor,
	CanarySettingPaceCeiling,
	CanarySettingWorkingHours,
}

// canarySettingMaxValueLen bounds a single value: far more than any
// legitimate value here needs (the longest, a working-hours window with
// every day named, is under 60 bytes), and a cap issue #124's own
// security point asks for on an admin write path before it ever reaches
// a validator, let alone SQL.
const canarySettingMaxValueLen = 512

func validateCanarySettingSize(value string) error {
	if len(value) > canarySettingMaxValueLen {
		return fmt.Errorf("value is %d bytes, more than the %d-byte limit", len(value), canarySettingMaxValueLen)
	}
	return nil
}

// canarySettingDef is one entry in canarySettingDefs: how to validate a
// candidate value, and which agent kinds the key applies to (issue #124:
// "validate every key and value against the same rules the env vars/
// enrol flags use today"). Every key here belongs to the honeypot's
// poisoner road (issue #86); a kind mismatch is refused by
// CanarySettingAppliesToKind rather than silently accepted.
type canarySettingDef struct {
	validate func(value string) error
	kinds    map[agentkind.Kind]bool
}

var honeypotOnly = map[agentkind.Kind]bool{agentkind.Honeypot: true}

var canarySettingDefs = map[CanarySettingKey]canarySettingDef{
	CanarySettingSegmentProfile: {
		kinds: honeypotOnly,
		validate: func(value string) error {
			_, err := poisoner.ParseProfile(value)
			return err
		},
	},
	CanarySettingBaitNames: {
		kinds: honeypotOnly,
		validate: func(value string) error {
			if value == "" {
				return nil
			}
			_, refused, err := poisoner.ParseNames(value)
			if err != nil {
				return err
			}
			if refused > 0 {
				return fmt.Errorf("%d entries could not be used: a bait name is 1 to 15 characters of letters, digits and hyphens, not starting or ending with a hyphen, and at most %d are used", refused, poisoner.MaxOperatorNames)
			}
			return nil
		},
	},
	CanarySettingPaceFloor:   {kinds: honeypotOnly, validate: validatePositiveDuration},
	CanarySettingPaceCeiling: {kinds: honeypotOnly, validate: validatePositiveDuration},
	CanarySettingWorkingHours: {
		kinds: honeypotOnly,
		validate: func(value string) error {
			_, err := poisoner.ParseWorkingHours(value)
			return err
		},
	},
}

// validatePositiveDuration accepts a Go duration string such as "2h",
// the same shape cmd/mockingbird's own poisonerDuration requires of
// MOCKINGBIRD_POISONER_FLOOR/_CEILING.
func validatePositiveDuration(value string) error {
	if value == "" {
		return nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("must be a Go duration such as %q: %w", "2h", err)
	}
	if d <= 0 {
		return fmt.Errorf("must be a positive duration, got %q", value)
	}
	return nil
}

// CanarySettingKeys returns every known canary setting key, in a stable
// order. The returned slice is a copy.
func CanarySettingKeys() []CanarySettingKey {
	keys := make([]CanarySettingKey, len(orderedCanarySettingKeys))
	copy(keys, orderedCanarySettingKeys)
	return keys
}

// CanarySettingAppliesToKind reports whether key is meaningful for kind
// -- e.g. the poisoner settings apply only to agentkind.Honeypot. An
// unknown key reports false, the same as a kind mismatch: both are
// refused by the same caller check (SetCanarySettings).
func CanarySettingAppliesToKind(key CanarySettingKey, kind agentkind.Kind) bool {
	def, ok := canarySettingDefs[key]
	return ok && def.kinds[kind]
}

// ErrCanarySettingUnknown is returned for a key outside canarySettingDefs.
var ErrCanarySettingUnknown = errors.New("store: unknown canary setting key")

// ErrCanarySettingInvalidValue is returned when a value fails its key's
// validate func.
var ErrCanarySettingInvalidValue = errors.New("store: invalid canary setting value")

// ErrCanarySettingWrongKind is returned when key does not apply to the
// canary's own kind (e.g. segment_profile for a scanner).
var ErrCanarySettingWrongKind = errors.New("store: setting does not apply to this canary's kind")

// CanarySetting is one canary_settings row.
type CanarySetting struct {
	Key       CanarySettingKey
	Value     string
	Version   int
	UpdatedAt time.Time
}

// ListCanarySettings returns every canary_settings row for canaryID, key
// order, or an empty slice for a canary nothing has ever been pushed to
// -- which is the ordinary state for every canary until an operator or
// an enrolment flag first writes one.
func ListCanarySettings(ctx context.Context, database *db.DB, canaryID string) ([]CanarySetting, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT key, value, version, updated_at FROM canary_settings WHERE agent_id = ? ORDER BY key`, canaryID)
	if err != nil {
		return nil, fmt.Errorf("query canary settings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []CanarySetting{}
	for rows.Next() {
		var (
			s         CanarySetting
			key       string
			updatedAt string
		)
		if err := rows.Scan(&key, &s.Value, &s.Version, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan canary setting: %w", err)
		}
		s.Key = CanarySettingKey(key)
		if s.UpdatedAt, err = time.Parse(receivedAtLayout, updatedAt); err != nil {
			return nil, fmt.Errorf("parse canary setting updated_at %q: %w", updatedAt, err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate canary settings: %w", err)
	}
	return out, nil
}

// upsertCanarySetting validates and writes one row, incrementing version
// (starting at 1 for a key never written before). conn is db.Conn so
// this composes into a caller's own transaction (store.Provision, at
// enrolment) as well as running standalone (SetCanarySettings' write
// path).
func upsertCanarySetting(ctx context.Context, conn db.Conn, canaryID string, key CanarySettingKey, value string, updatedAt time.Time) error {
	def, ok := canarySettingDefs[key]
	if !ok {
		return fmt.Errorf("%w: %q", ErrCanarySettingUnknown, key)
	}
	if err := validateCanarySettingSize(value); err != nil {
		return fmt.Errorf("%w: %s: %s", ErrCanarySettingInvalidValue, key, err)
	}
	if err := def.validate(value); err != nil {
		return fmt.Errorf("%w: %s: %s", ErrCanarySettingInvalidValue, key, err)
	}
	if updatedAt.IsZero() {
		return fmt.Errorf("store: upsertCanarySetting: updatedAt must be set by the caller")
	}
	_, err := conn.ExecContext(ctx, `
		INSERT INTO canary_settings (agent_id, key, value, version, updated_at)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT (agent_id, key) DO UPDATE SET
			value = excluded.value, version = canary_settings.version + 1, updated_at = excluded.updated_at`,
		canaryID, string(key), value, updatedAt.UTC().Format(receivedAtLayout))
	if err != nil {
		return fmt.Errorf("upsert canary setting %q: %w", key, err)
	}
	return nil
}

// SetCanarySettings validates and writes every (key, value) in updates
// for canaryID, in one transaction -- issue #124's "one API write path
// edits them", so a partial write (some keys valid, one not) never
// applies: the whole call fails before anything is stored, and the
// caller's error names the offending key.
//
// kind is the canary's own agentkind.Kind, checked against
// CanarySettingAppliesToKind for every key before anything is validated
// -- the same "only the honeypot has lures" refusal
// cmd/birdcage/canary.go's own enrol command makes for --lure and
// --smb-*, applied here to the dashboard write path instead of a CLI
// flag.
func SetCanarySettings(ctx context.Context, database *db.DB, canaryID string, kind agentkind.Kind, updates map[CanarySettingKey]string, updatedAt time.Time) error {
	if len(updates) == 0 {
		return fmt.Errorf("store: SetCanarySettings: updates is empty")
	}
	if updatedAt.IsZero() {
		return fmt.Errorf("store: SetCanarySettings: updatedAt must be set by the caller")
	}
	for key := range updates {
		if _, ok := canarySettingDefs[key]; !ok {
			return fmt.Errorf("%w: %q", ErrCanarySettingUnknown, key)
		}
		if !CanarySettingAppliesToKind(key, kind) {
			return fmt.Errorf("%w: %q does not apply to kind %q", ErrCanarySettingWrongKind, key, kind)
		}
	}

	tx, err := database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin canary settings transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Sorted so a caller's map iteration order can never make two
	// concurrent multi-key writes apply in a different order against
	// each other -- version increments would still be correct either
	// way, but a stable order makes this function's behaviour
	// reproducible to test against.
	keys := make([]CanarySettingKey, 0, len(updates))
	for key := range updates {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	for _, key := range keys {
		if err := upsertCanarySetting(ctx, tx, canaryID, key, updates[key], updatedAt); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit canary settings transaction: %w", err)
	}
	committed = true
	return nil
}

// SeedCanarySettingsFromEnrolment writes the enrolment flags' own
// values, if any, as canary_id's first canary_settings rows -- called
// from inside store.Provision's own transaction, so a canary row is
// never created without its seeded settings landing atomically with it.
// baitNames/segmentProfile empty means the operator passed neither flag;
// in that case this writes nothing, and the agent falls back to its
// environment variables exactly as it did before issue #124.
//
// Unlike SetCanarySettings, this never checks CanarySettingAppliesToKind
// -- both flags are honeypot-only already, refused by
// cmd/birdcage/canary.go's own enrol command before a session is even
// minted (see runCanaryEnrol's "--lure and the --smb-* flags apply to
// --kind %s only" sibling check) -- and it writes no audit entry of its
// own: Provision's single "enrolment.provisioned" entry already covers
// this canary's creation.
func SeedCanarySettingsFromEnrolment(ctx context.Context, conn db.Conn, canaryID, baitNames, segmentProfile string, now time.Time) error {
	if baitNames != "" {
		if err := upsertCanarySetting(ctx, conn, canaryID, CanarySettingBaitNames, baitNames, now); err != nil {
			return fmt.Errorf("seed bait_names: %w", err)
		}
	}
	if segmentProfile != "" {
		if err := upsertCanarySetting(ctx, conn, canaryID, CanarySettingSegmentProfile, segmentProfile, now); err != nil {
			return fmt.Errorf("seed segment_profile: %w", err)
		}
	}
	return nil
}

// SettingsHash is the sha256 hex of settings' current key/value pairs,
// independent of row order -- what internal/ingest/heartbeat.go compares
// against an agent's own reported hash (client.SettingsHash, computed
// the identical way over the agent's effective settings) to decide
// whether to push, and what internal/api/canary.go compares against
// agents.settings_hash to decide whether a row is confirmed.
//
// An empty settings slice hashes to hashSettingsPairs(nil)'s own fixed
// value; callers with no rows at all (ListCanarySettings returned none)
// should treat that as "nothing to push" rather than computing and
// comparing this hash -- see handleHoneypotHeartbeat's own comment.
func SettingsHash(settings []CanarySetting) string {
	pairs := make(map[string]string, len(settings))
	for _, s := range settings {
		pairs[string(s.Key)] = s.Value
	}
	return hashSettingsPairs(pairs)
}

// hashSettingsPairs canonicalises pairs as sorted "key=value\n" lines and
// returns the sha256 hex digest. internal/agent/client's SettingsHash is
// this exact algorithm, duplicated rather than imported (an agent binary
// must never import internal/store) -- keep the two in lockstep.
func hashSettingsPairs(pairs map[string]string) string {
	keys := make([]string, 0, len(pairs))
	for k := range pairs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(pairs[k])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// GetCanarySettingsHash reads back agents.settings_hash/settings_hash_at
// for canaryID -- what internal/api/canary.go compares against the
// current SettingsHash of ListCanarySettings' rows to decide whether the
// facts column shows a setting as confirmed. Empty hash and nil at mean
// no heartbeat has ever reported one (a canary predating issue #124, or
// one that has never sent a single heartbeat), which is ErrCanaryNotFound
// only when the id itself is unknown.
func GetCanarySettingsHash(ctx context.Context, database *db.DB, canaryID string) (hash string, at *time.Time, err error) {
	var (
		h        *string
		hashedAt *string
	)
	row := database.QueryRowContext(ctx, `SELECT settings_hash, settings_hash_at FROM agents WHERE id = ?`, canaryID)
	if err := row.Scan(&h, &hashedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, ErrCanaryNotFound
		}
		return "", nil, fmt.Errorf("scan canary settings hash: %w", err)
	}
	if h != nil {
		hash = *h
	}
	if hashedAt != nil {
		parsed, err := time.Parse(receivedAtLayout, *hashedAt)
		if err != nil {
			return "", nil, fmt.Errorf("parse settings_hash_at %q: %w", *hashedAt, err)
		}
		at = &parsed
	}
	return hash, at, nil
}

// GetCanaryKind reads back one canary's own kind, for a caller (the
// dashboard settings write path) that needs to check
// CanarySettingAppliesToKind before writing without pulling in
// ListCanaries' whole fleet-status projection.
func GetCanaryKind(ctx context.Context, database *db.DB, canaryID string) (agentkind.Kind, error) {
	var kind string
	row := database.QueryRowContext(ctx, `SELECT kind FROM agents WHERE id = ?`, canaryID)
	if err := row.Scan(&kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrCanaryNotFound
		}
		return "", fmt.Errorf("scan canary kind: %w", err)
	}
	return agentkind.Kind(kind), nil
}

// RecordCanarySettingsHash stores the sha256 hex an agent's heartbeat
// most recently reported (agents.settings_hash/settings_hash_at) --
// best-effort bookkeeping the ingest heartbeat handlers call after a
// heartbeat is otherwise already accepted, mirroring
// SetCanaryLastSeenAddr's own stance (a secondary signal, not part of
// what "accepted" means for the heartbeat itself). An empty hash (an
// agent built before issue #124, which never sends one) is a no-op:
// there is nothing to record, and a stale previously-recorded hash from
// this same agent, if any, is left exactly as it was.
func RecordCanarySettingsHash(ctx context.Context, database *db.DB, canaryID, hash string, at time.Time) error {
	if hash == "" {
		return nil
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE agents SET settings_hash = ?, settings_hash_at = ? WHERE id = ?`,
		hash, at.UTC().Format(receivedAtLayout), canaryID); err != nil {
		return fmt.Errorf("record canary settings hash: %w", err)
	}
	return nil
}
