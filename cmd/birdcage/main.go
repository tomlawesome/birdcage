// Command birdcage runs the OpenCanary UDP syslog ingestion bridge: it
// listens for OpenCanary honeypot alerts over UDP syslog and persists
// them to a local SQLite database.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/ingest"
)

const (
	envDBPath     = "BIRDCAGE_DB_PATH"
	envSyslogAddr = "BIRDCAGE_SYSLOG_ADDR"

	defaultDBPath     = "birdcage.db"
	defaultSyslogAddr = ":5514"
)

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("birdcage: ")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbPath := os.Getenv(envDBPath)
	if dbPath == "" {
		dbPath = defaultDBPath
	}
	addr := os.Getenv(envSyslogAddr)
	if addr == "" {
		addr = defaultSyslogAddr
	}

	database, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("open database %s: %v", dbPath, err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.Fatalf("close database %s: %v", dbPath, err)
		}
	}()

	if err := db.Migrate(ctx, database); err != nil {
		log.Fatalf("migrate database %s: %v", dbPath, err)
	}

	// The default listen address is deliberately :5514, an unprivileged
	// port, so birdcage can run as a non-root container. Operators should
	// point each OpenCanary instance's syslog handler "address" at
	// <birdcage-host>:5514 rather than the conventional :514.
	server := ingest.NewServer(addr, database)
	log.Printf("listening for OpenCanary UDP syslog on %s, storing alerts in %s", addr, dbPath)
	if err := server.ListenAndServe(ctx); err != nil {
		log.Fatalf("syslog listener: %v", err)
	}
	log.Print("shutdown complete")
}
