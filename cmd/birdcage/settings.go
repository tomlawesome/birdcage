package main

import (
	"context"
	"fmt"
	"time"

	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/term"
)

// runSettingsList implements `birdcage settings list` (issue #46): prints
// every known setting and its current value, one per line, falling back to
// the documented default for any key that has never been written --
// store.GetSetting already does that, so this command shows exactly what a
// scheduler reading the same function would see.
func runSettingsList(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: birdcage settings list")
	}

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	ctx := context.Background()
	for _, key := range store.SettingKeys() {
		value, err := store.GetSetting(ctx, database, key)
		if err != nil {
			return fmt.Errorf("get setting %s: %w", key, err)
		}
		// key is one of this package's own constants, never CLI input;
		// value came back from the database exactly as stored (or as the
		// Go default). Escaped here anyway, at the point it reaches this
		// terminal, matching cmd/birdcage/canary.go's rule.
		fmt.Printf("%s=%s\n", key, term.Escape(value))
	}
	return nil
}

// runSettingsGet implements `birdcage settings get <key>` (issue #46), for
// scripting against a single setting without parsing `settings list`'s
// output.
func runSettingsGet(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: birdcage settings get <key>")
	}
	key := store.SettingKey(args[0])

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	value, err := store.GetSetting(context.Background(), database, key)
	if err != nil {
		// store.ErrSettingUnknown is exactly the "typo fails loudly" case
		// #46 asks for; this wraps it with the key so the CLI's own error
		// message names what was typed, not just that something was
		// unknown.
		return fmt.Errorf("get setting %s: %w", term.Escape(args[0]), err)
	}
	fmt.Println(term.Escape(value))
	return nil
}

// runSettingsSet implements `birdcage settings set <key> <value>` (issue
// #46) -- the write half of "written by a CLI command now" (note 17934).
// store.SetSetting is the only validation this command performs: an
// unknown key or a value store.SettingKey's validator rejects returns
// straight through as this command's own error, with the message
// explaining what was wrong intact.
func runSettingsSet(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: birdcage settings set <key> <value>")
	}
	key := store.SettingKey(args[0])

	database, err := openCanaryDB()
	if err != nil {
		return err
	}
	defer closeCanaryDB(database)

	if err := store.SetSetting(context.Background(), database, key, args[1], time.Now().UTC()); err != nil {
		return fmt.Errorf("set setting %s: %w", term.Escape(args[0]), err)
	}
	// args are exactly what the caller typed; escaped here, at the point
	// they reach this terminal, same as runCanaryAdd/Mint/Revoke.
	fmt.Printf("%s=%s\n", term.Escape(args[0]), term.Escape(args[1]))
	return nil
}
