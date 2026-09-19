// Package store: this file is the read/write path for the settings table
// (issue #46, note 17934: "schedule settings are data, not configuration").
// It carries what an operator decides while using birdcage -- the
// self-test on/off switch, its schedule, the "same schedule as key
// rotation" toggle, and the rotation schedule itself -- as rows a CLI
// command (cmd/birdcage/settings.go) writes today and the dashboard (#8)
// will write later, both through GetSetting/SetSetting rather than a
// second copy that could disagree.
//
// The set of valid keys, and what counts as a valid value for each, is
// closed here in Go rather than left open in the schema -- the same
// reasoning command.go's CommandKind uses (0006_canary_commands.sql's
// comment): a SQL CHECK constraint would have to be written once per
// engine and would then disagree with this list the moment either changed.
// GetSetting and SetSetting are the only door into the settings table:
// SetSetting rejects a key outside settingDefs and a value settingDef.validate
// rejects, both with a message saying what was wrong, before either ever
// reaches SQL.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// SettingKey is the closed set of rows settings can hold. Unlike
// CommandKind, callers construct one from a raw string (a CLI argument),
// so it is validated against settingDefs at the point of use rather than
// only ever assigned from a named constant.
type SettingKey string

// The four settings this slice carries (issue #46's ratified decisions,
// note 17934). Nothing else is mintable: an unrecognized key is rejected by
// GetSetting and SetSetting rather than silently accepted.
const (
	// SettingSelfTestEnabled turns the scheduled self-test (#46) on or
	// off entirely. "false" stops it completely, per #46's "Done when".
	SettingSelfTestEnabled SettingKey = "selftest_enabled"
	// SettingSelfTestSchedule is the 24-hour UTC time of day the
	// self-test runs, when SettingSelfTestUseRotationSchedule is
	// "false". Ignored (but still stored and still validated) while that
	// toggle is "true" -- the dashboard's job (#8) is to grey the field
	// out, not this package's.
	SettingSelfTestSchedule SettingKey = "selftest_schedule"
	// SettingSelfTestUseRotationSchedule is the "same schedule as key
	// rotation" toggle from #46's body: "once a day, immediately after
	// key rotation" is the default, which this being "true" expresses.
	SettingSelfTestUseRotationSchedule SettingKey = "selftest_use_rotation_schedule"
	// SettingRotationSchedule is the 24-hour UTC time of day key
	// rotation runs. Nothing in this slice reads it yet -- minting a
	// scheduled rotation is out of scope here -- but it is stored now so
	// the CLI and the dashboard write the one row a future scheduler
	// reads, rather than that scheduler inventing its own copy.
	SettingRotationSchedule SettingKey = "rotation_schedule"
	// SettingAdminApprovalAddress and SettingReleaseAddress are issue
	// #54's two addresses, carried in POST /enrol/hello's first-contact
	// response (issue #47 slice 1b, "The flow" step 3) so a freshly
	// enrolled canary's operator knows where an admin approval and a
	// release both go. Free-text strings (a mailing address, a chat
	// channel, whatever #54 settles on -- this slice only carries the
	// value, it doesn't interpret it), empty by default: `birdcage
	// canary enrol` refuses to mint a session until both are set (see
	// cmd/birdcage/canary.go), naming the `birdcage settings set`
	// command an operator needs to run first.
	SettingAdminApprovalAddress SettingKey = "admin_approval_address"
	SettingReleaseAddress       SettingKey = "release_address"
	// SettingHistoryLastTick is the last time internal/history's state
	// recorder completed a tick (RFC3339Nano UTC), written by the
	// recorder itself rather than by an operator -- issue #56. It is
	// bookkeeping, not a preference: on the next start, the gap between
	// it and now is the span birdcage was not watching, which is
	// recorded as an "unobserved" state period rather than left looking
	// healthy. It lives here, alongside the operator's own settings,
	// because settings is already the one small key/value table with a
	// validated, closed key set -- a second table for one row would be
	// a second convention. Empty by default: never ticked.
	SettingHistoryLastTick SettingKey = "history_last_tick"
)

// orderedSettingKeys is settingDefs' key order for anything that lists
// every setting (SettingKeys, the CLI's `settings list`), so that output is
// stable across a map's inherently unordered iteration.
var orderedSettingKeys = []SettingKey{
	SettingSelfTestEnabled,
	SettingSelfTestSchedule,
	SettingSelfTestUseRotationSchedule,
	SettingRotationSchedule,
	SettingAdminApprovalAddress,
	SettingReleaseAddress,
	SettingHistoryLastTick,
}

// SettingKeys returns every known setting key, in a stable order. The
// returned slice is a copy: mutating it cannot affect this package's own
// list.
func SettingKeys() []SettingKey {
	keys := make([]SettingKey, len(orderedSettingKeys))
	copy(keys, orderedSettingKeys)
	return keys
}

// settingDef is one entry in settingDefs: how to validate a candidate
// value for a key, and what GetSetting returns when the key has never been
// written.
type settingDef struct {
	validate     func(value string) error
	defaultValue string
}

// settingDefs is the single place a setting's default lives, per #46's
// "the defaults belong in one place in Go, not scattered" -- GetSetting
// reads defaultValue directly rather than each caller carrying its own
// idea of one.
//
// Defaults: self-test is on, using the rotation schedule, matching #46's
// stated default ("once a day, immediately after key rotation"). Both
// schedule fields default to midnight UTC -- an arbitrary but documented
// placeholder, since no rotation-on-a-schedule feature exists yet to have
// its own established default time; an operator (via the CLI now, the
// dashboard once #8 lands) changes it to whatever suits their fleet.
var settingDefs = map[SettingKey]settingDef{
	SettingSelfTestEnabled:             {validate: validateSettingBool, defaultValue: "true"},
	SettingSelfTestSchedule:            {validate: validateSettingScheduleTime, defaultValue: "00:00"},
	SettingSelfTestUseRotationSchedule: {validate: validateSettingBool, defaultValue: "true"},
	SettingRotationSchedule:            {validate: validateSettingScheduleTime, defaultValue: "00:00"},
	SettingAdminApprovalAddress:        {validate: validateSettingAddress, defaultValue: ""},
	SettingReleaseAddress:              {validate: validateSettingAddress, defaultValue: ""},
	SettingHistoryLastTick:             {validate: validateSettingTimestamp, defaultValue: ""},
}

// scheduleTimePattern matches a strict, zero-padded 24-hour "HH:MM", e.g.
// "03:00" or "23:45". time.Parse's numeric fields are lenient about
// padding (it accepts "3:0" as readily as "03:00"), which is exactly the
// ambiguity #46 asks this package to refuse: a typo'd schedule must fail
// loudly, not parse into something else silently.
var scheduleTimePattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// validateSettingBool accepts exactly "true" or "false" -- no "1"/"0",
// "yes"/"no" or mixed case -- so a setting's stored value always has one
// unambiguous spelling.
func validateSettingBool(value string) error {
	if value != "true" && value != "false" {
		return fmt.Errorf(`must be "true" or "false", got %q`, value)
	}
	return nil
}

// validateSettingScheduleTime accepts a strict 24-hour UTC "HH:MM".
func validateSettingScheduleTime(value string) error {
	if !scheduleTimePattern.MatchString(value) {
		return fmt.Errorf(`must be a 24-hour UTC time as "HH:MM" (e.g. "03:00"), got %q`, value)
	}
	return nil
}

// controlCharPattern matches any ASCII control character (0x00-0x1F,
// 0x7F) -- Go's RE2-flavoured regexp supports the POSIX "[[:cntrl:]]"
// class directly, so this needs no per-codepoint enumeration.
var controlCharPattern = regexp.MustCompile(`[[:cntrl:]]`)

// validateSettingAddress accepts SettingAdminApprovalAddress and
// SettingReleaseAddress: a non-empty (after trimming whitespace) string
// with no control characters. It doesn't otherwise constrain the value
// -- issue #54 settles what these addresses actually look like (a
// mailing address, a chat channel, ...); this slice only carries
// whatever #54 decides.
func validateSettingAddress(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("must not be empty")
	}
	if controlCharPattern.MatchString(value) {
		return fmt.Errorf("must not contain control characters")
	}
	return nil
}

// validateSettingTimestamp accepts an RFC3339Nano UTC timestamp, the one
// layout every timestamp in this schema is written in (receivedAtLayout).
// The empty string is rejected like any other unparseable value -- "never
// ticked" is the stored row's absence, read back as the key's empty
// default, never a written empty value.
func validateSettingTimestamp(value string) error {
	if _, err := time.Parse(receivedAtLayout, value); err != nil {
		return fmt.Errorf("must be an RFC3339 timestamp (e.g. %q), got %q", "2026-01-02T15:04:05Z", value)
	}
	return nil
}

// ErrSettingUnknown is returned by GetSetting and SetSetting for a key
// outside settingDefs -- the CLI's (and eventually the dashboard's) way of
// failing loudly on a typo'd setting name rather than silently reading or
// storing nothing.
var ErrSettingUnknown = errors.New("store: unknown setting key")

// ErrSettingInvalidValue is returned by SetSetting when value is not valid
// for key, wrapped with a message describing what was wrong (see the
// settingDef.validate functions above).
var ErrSettingInvalidValue = errors.New("store: invalid setting value")

// GetSetting returns key's current value, or its documented default
// (settingDefs[key].defaultValue) when no row has ever been written for it
// -- a setting that has never been set reads as its default, never as an
// error or an empty string.
func GetSetting(ctx context.Context, database db.Conn, key SettingKey) (string, error) {
	def, ok := settingDefs[key]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrSettingUnknown, key)
	}
	var value string
	err := database.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, string(key)).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return def.defaultValue, nil
	}
	if err != nil {
		return "", fmt.Errorf("scan setting %q: %w", key, err)
	}
	return value, nil
}

// SetSetting validates value against key's rule and, if it passes, writes
// (key, value, updatedAt) as one row -- inserting it if key has never been
// set, overwriting it (value and updatedAt both) otherwise. The upsert is
// one statement rather than a SELECT-then-INSERT-or-UPDATE, so it composes
// correctly under db.Conn without needing a transaction of its own; it
// works identically on both engines, the same "ON CONFLICT ... DO ..."
// shape InsertAlertIfNew already uses in store.go.
//
// updatedAt must be set by the caller (time.Now().UTC()), matching every
// other *At field this package's mint functions take rather than reading
// time.Now() itself.
func SetSetting(ctx context.Context, database db.Conn, key SettingKey, value string, updatedAt time.Time) error {
	def, ok := settingDefs[key]
	if !ok {
		return fmt.Errorf("%w: %q", ErrSettingUnknown, key)
	}
	if err := def.validate(value); err != nil {
		return fmt.Errorf("%w: %s: %s", ErrSettingInvalidValue, key, err)
	}
	if updatedAt.IsZero() {
		return fmt.Errorf("store: SetSetting: updatedAt must be set by the caller")
	}
	_, err := database.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		string(key), value, updatedAt.UTC().Format(receivedAtLayout))
	if err != nil {
		return fmt.Errorf("upsert setting %q: %w", key, err)
	}
	return nil
}
