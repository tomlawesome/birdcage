package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// runCanaryAdd implements `birdcage canary add <id> <name> <lane> <ports> [interval_s]`,
// a dev/testing convenience for registering a canary before #1's
// enrollment UI exists (see issue #34's "Not in this slice"). ports is
// the raw comma-separated port list store.Canary.Ports expects before
// display formatting, e.g. "22,80,445".
func runCanaryAdd(args []string) error {
	if len(args) < 4 || len(args) > 5 {
		return fmt.Errorf("usage: birdcage canary add <id> <name> <lane> <ports> [interval_s]")
	}
	interval := store.DefaultHeartbeatIntervalS
	if len(args) == 5 {
		n, err := strconv.Atoi(args[4])
		if err != nil || n <= 0 {
			return fmt.Errorf("interval_s must be a positive integer")
		}
		interval = n
	}

	databaseURL := os.Getenv(envDatabaseURL)
	if databaseURL == "" {
		databaseURL = os.Getenv(envDBPath)
	}
	if databaseURL == "" {
		databaseURL = defaultDBPath
	}
	database, err := db.Open(databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close database: %v\n", err)
		}
	}()

	ctx := context.Background()
	if err := db.Migrate(ctx, database); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	c := store.Canary{
		ID: args[0], Name: args[1], Lane: args[2], Ports: args[3],
		HeartbeatIntervalS: interval, EnrolledAt: time.Now().UTC(),
	}
	if err := store.InsertCanary(ctx, database, c); err != nil {
		return fmt.Errorf("insert canary: %w", err)
	}
	fmt.Printf("canary %s enrolled\n", c.ID)
	return nil
}
