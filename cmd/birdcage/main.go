// Command birdcage runs two things side by side: the OpenCanary UDP
// syslog ingestion bridge, which listens for OpenCanary honeypot alerts
// and persists them to a local SQLite database, and a read-only HTTP
// JSON API (#3) that serves that data to a dashboard.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/ingest"
)

const (
	envDBPath     = "BIRDCAGE_DB_PATH"
	envSyslogAddr = "BIRDCAGE_SYSLOG_ADDR"
	envHTTPAddr   = "BIRDCAGE_HTTP_ADDR"

	defaultDBPath     = "birdcage.db"
	defaultSyslogAddr = ":5514"
	defaultHTTPAddr   = ":8080"

	// httpReadHeaderTimeout bounds how long the HTTP server waits for a
	// client to finish sending request headers, so a slow or stalled
	// client can't tie up a connection indefinitely.
	httpReadHeaderTimeout = 5 * time.Second
	// httpShutdownTimeout bounds Shutdown's wait for in-flight requests
	// to finish once ctx is canceled, so process exit is never blocked
	// on a client that never goes away.
	httpShutdownTimeout = 5 * time.Second
)

// serviceResult is what each of the two services below reports once it
// has stopped -- name identifies which one, for the log line.
type serviceResult struct {
	name string
	err  error
}

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("birdcage: ")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbPath := os.Getenv(envDBPath)
	if dbPath == "" {
		dbPath = defaultDBPath
	}
	syslogAddr := os.Getenv(envSyslogAddr)
	if syslogAddr == "" {
		syslogAddr = defaultSyslogAddr
	}
	httpAddr := os.Getenv(envHTTPAddr)
	if httpAddr == "" {
		httpAddr = defaultHTTPAddr
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
	syslogServer := ingest.NewServer(syslogAddr, database)

	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           api.NewHandler(database),
		ReadHeaderTimeout: httpReadHeaderTimeout,
	}

	// Both servers run concurrently, and both are watched to completion
	// below -- a plain channel rather than a library dependency, since
	// exactly two goroutines are ever in flight and both are collected
	// the same way. Whichever finishes first (from a signal, or from a
	// failure of its own, e.g. "address already in use") triggers stop()
	// below, which cancels ctx and so brings the other one down too:
	// without that, a lone failure in one service would leave main
	// blocked forever waiting on the other's result.
	results := make(chan serviceResult, 2)

	go func() {
		log.Printf("listening for OpenCanary UDP syslog on %s, storing alerts in %s", syslogAddr, dbPath)
		results <- serviceResult{"syslog listener", syslogServer.ListenAndServe(ctx)}
	}()

	go func() {
		log.Printf("serving dashboard HTTP API on %s", httpAddr)
		err := httpServer.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			// The expected return from Shutdown below, not a failure.
			err = nil
		}
		results <- serviceResult{"http server", err}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("http server shutdown: %v", err)
		}
	}()

	first := <-results
	if first.err != nil {
		log.Printf("%s: %v", first.name, first.err)
	}
	stop() // idempotent; ensures the other service is asked to stop too
	second := <-results
	if second.err != nil {
		log.Printf("%s: %v", second.name, second.err)
	}

	if first.err != nil || second.err != nil {
		os.Exit(1)
	}
	log.Print("shutdown complete")
}
