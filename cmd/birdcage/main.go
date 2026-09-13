// Command birdcage runs two things side by side: the OpenCanary UDP
// syslog ingestion bridge, which listens for OpenCanary honeypot alerts
// and persists them to a database (SQLite by default, or Postgres --
// see DATABASE_URL below, and docs/configuration.md), and a read-only
// HTTP JSON API (#3) that serves that data to a dashboard.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/ingest"
	"github.com/tomlawesome/birdcage/web"
)

const (
	// envDatabaseURL selects the storage engine per issue #7: unset, or
	// a bare path / "sqlite:PATH", means SQLite; "postgres://..." or
	// "postgresql://..." means Postgres. Takes priority over
	// envDBPath, which stays as the SQLite-only, pre-Postgres way to
	// pick a path and keeps working unchanged when DATABASE_URL is
	// unset -- see docs/configuration.md.
	envDatabaseURL = "DATABASE_URL"
	envDBPath      = "BIRDCAGE_DB_PATH"
	envSyslogAddr  = "BIRDCAGE_SYSLOG_ADDR"
	envHTTPAddr    = "BIRDCAGE_HTTP_ADDR"

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

	// `birdcage canary add ...` (cmd/birdcage/canary.go) is a standalone
	// dev/testing subcommand -- issue #34's "Not in this slice" -- that
	// exits immediately rather than starting the syslog/HTTP services
	// below.
	if len(os.Args) > 2 && os.Args[1] == "canary" && os.Args[2] == "add" {
		if err := runCanaryAdd(os.Args[3:]); err != nil {
			log.Fatal(err)
		}
		return
	}

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

	// DATABASE_URL, when set, picks the engine (including Postgres);
	// unset, dbPath (BIRDCAGE_DB_PATH or its default) is passed through
	// as a bare path, which db.Open treats as SQLite -- the same
	// behavior as before DATABASE_URL existed.
	databaseURL := os.Getenv(envDatabaseURL)
	if databaseURL == "" {
		databaseURL = dbPath
	}

	database, err := db.Open(databaseURL)
	if err != nil {
		log.Fatalf("open database (%s=%q): %v", envDatabaseURL, databaseURL, err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.Fatalf("close database: %v", err)
		}
	}()

	if err := db.Migrate(ctx, database); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	// The default listen address is deliberately :5514, an unprivileged
	// port, so birdcage can run as a non-root container. Operators should
	// point each OpenCanary instance's syslog handler "address" at
	// <birdcage-host>:5514 rather than the conventional :514.
	syslogServer := ingest.NewServer(syslogAddr, database)

	// /api/* keeps its exact routing (internal/api.NewHandler is
	// untouched); everything else is the dashboard frontend (#36),
	// embedded into this binary by web/embed.go with an SPA fallback to
	// index.html so a client-side route survives a refresh.
	rootMux := http.NewServeMux()
	rootMux.Handle("/api/", api.NewHandler(database))
	if uiHandler, err := web.Handler(); err != nil {
		log.Printf("frontend: %v (serving API only)", err)
	} else {
		if !web.HasUI() {
			log.Print("no frontend was built into this binary (run `npm run build` in frontend/, see README) -- serving API only")
			uiHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "no frontend was built into this binary -- the API is available under /api/", http.StatusServiceUnavailable)
			})
		}
		rootMux.Handle("/", uiHandler)
	}

	httpServer := &http.Server{
		Addr:              httpAddr,
		Handler:           rootMux,
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
		log.Printf("listening for OpenCanary UDP syslog on %s, storing alerts via %s (%s)",
			syslogAddr, database.Engine, redactDatabaseURL(databaseURL))
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

// redactDatabaseURL returns raw with any embedded userinfo (a Postgres
// DATABASE_URL's user:password@) stripped before it goes anywhere near
// a log line -- SECURITY.md's "never logged" rule for credentials
// applies to this exactly as much as to the CrowdSec/RouterOS secrets
// it was written for. A bare SQLite path has no userinfo to strip and
// passes through unchanged; a value url.Parse rejects is logged as a
// fixed placeholder rather than verbatim, since the parse failure
// itself gives no reason to believe it's secret-free.
func redactDatabaseURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable)"
	}
	if u.User != nil {
		u.User = url.User("REDACTED")
	}
	return u.String()
}
