// Command birdcage runs two things side by side: the HTTPS canary ingest
// listener (issue #32), which authenticates a canary's agent by bearer
// token and persists the alert batches it posts to a database (SQLite by
// default, or Postgres -- see DATABASE_URL below, and
// docs/configuration.md), and a read-only HTTP JSON API (#3) that serves
// that data to a dashboard. UDP syslog ingestion (the original bridge)
// was retired in slice 7 of #32 -- pre-alpha, no compatibility to keep.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/ingest"
	"github.com/tomlawesome/birdcage/internal/logging"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/stream"
	"github.com/tomlawesome/birdcage/web"
)

const (
	// envLogLevel selects internal/logging's threshold (debug/info/warn/
	// error, case-insensitive; unset or unrecognized falls back to info)
	// -- see docs/configuration.md.
	envLogLevel = "BIRDCAGE_LOG_LEVEL"

	// envDatabaseURL selects the storage engine per issue #7: unset, or
	// a bare path / "sqlite:PATH", means SQLite; "postgres://..." or
	// "postgresql://..." means Postgres. Takes priority over
	// envDBPath, which stays as the SQLite-only, pre-Postgres way to
	// pick a path and keeps working unchanged when DATABASE_URL is
	// unset -- see docs/configuration.md.
	envDatabaseURL = "DATABASE_URL"
	envDBPath      = "BIRDCAGE_DB_PATH"
	envHTTPAddr    = "BIRDCAGE_HTTP_ADDR"
	// envInternalRanges names extra CIDR blocks GET /api/visitors and GET
	// /api/trace's "inside" kind rule (issue #35) treats as internal,
	// beyond the always-internal defaults (RFC 1918, IPv6 ULA,
	// link-local) -- for an operator whose LAN uses address space
	// outside those. See docs/configuration.md.
	envInternalRanges = "BIRDCAGE_INTERNAL_RANGES"
	// envIngestAddr, envIngestTLSCert and envIngestTLSKey configure issue
	// #32's HTTPS ingest listener -- a canary's agent (#48) posts event
	// batches here, authenticated by its own bearer token, never the
	// dashboard's requireAuth seam. Cert/key are PEM files on disk;
	// #47 (enrolment) is what will eventually mint them automatically,
	// so until it lands an operator supplies them by hand. Leaving both
	// unset disables this listener entirely (see the switch in main
	// below) rather than failing startup, since no project this size can
	// assume #47's CA exists yet; setting only one of the two is treated
	// as a configuration error and fails startup loudly, since a
	// half-configured TLS listener is never an acceptable fallback
	// (issue #32 fail-closed: "no plaintext fallback; no plaintext
	// listener on any ingest port, ever").
	envIngestAddr    = "BIRDCAGE_INGEST_ADDR"
	envIngestTLSCert = "BIRDCAGE_INGEST_TLS_CERT"
	envIngestTLSKey  = "BIRDCAGE_INGEST_TLS_KEY"

	defaultDBPath     = "birdcage.db"
	defaultHTTPAddr   = ":8080"
	defaultIngestAddr = ":8443"

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
	// #71's ratified startup order: level first, so nothing logged below
	// this line is ever silently dropped or shown by mistake at the
	// wrong threshold; the banner immediately after, unconditionally --
	// including ahead of the `canary`/`settings` one-shot CLI modes
	// below, matching the decision as written rather than mikroview's
	// own "server-start path only" carve-out for PrintBanner.
	logging.SetLevel(os.Getenv(envLogLevel))
	logging.PrintBanner()

	canaryLog := logging.New("canary")
	settingsLog := logging.New("settings")

	// `birdcage canary ...` (cmd/birdcage/canary.go) are standalone CLI
	// subcommands -- `add` a dev/testing convenience predating enrollment
	// (#34's "Not in this slice"), `mint`/`list`/`revoke` issue #32 item
	// 9's canary token management -- that exit immediately rather than
	// starting the HTTP/ingest services below.
	if len(os.Args) > 1 && os.Args[1] == "canary" {
		if len(os.Args) < 3 {
			canaryLog.Error("usage: birdcage canary <add|mint|list|revoke> ...")
			os.Exit(1)
		}
		var err error
		switch os.Args[2] {
		case "add":
			err = runCanaryAdd(os.Args[3:])
		case "mint":
			err = runCanaryMint(os.Args[3:])
		case "list":
			err = runCanaryList(os.Args[3:])
		case "revoke":
			err = runCanaryRevoke(os.Args[3:])
		default:
			canaryLog.Error(fmt.Sprintf("unknown canary subcommand %q (want add, mint, list or revoke)", os.Args[2]))
			os.Exit(1)
		}
		if err != nil {
			canaryLog.Error(err.Error())
			os.Exit(1)
		}
		return
	}

	// `birdcage settings ...` (cmd/birdcage/settings.go) is issue #46's
	// CLI for the settings table (note 17934: "schedule settings are
	// data, not configuration") -- `list`/`get` read a setting (or every
	// setting), falling back to its documented default when unset; `set`
	// writes one, validated against internal/store's closed key/value
	// rules. Like `canary` above, these exit immediately rather than
	// starting the HTTP/ingest services below.
	if len(os.Args) > 1 && os.Args[1] == "settings" {
		if len(os.Args) < 3 {
			settingsLog.Error("usage: birdcage settings <list|get|set> ...")
			os.Exit(1)
		}
		var err error
		switch os.Args[2] {
		case "list":
			err = runSettingsList(os.Args[3:])
		case "get":
			err = runSettingsGet(os.Args[3:])
		case "set":
			err = runSettingsSet(os.Args[3:])
		default:
			settingsLog.Error(fmt.Sprintf("unknown settings subcommand %q (want list, get or set)", os.Args[2]))
			os.Exit(1)
		}
		if err != nil {
			settingsLog.Error(err.Error())
			os.Exit(1)
		}
		return
	}

	// Component loggers for the real server-start path below -- one per
	// subsystem, so `docker logs | grep ingest` (or config, db, http)
	// isolates exactly that subsystem's lines.
	configLog := logging.New("config")
	dbLog := logging.New("db")
	httpLog := logging.New("http")
	ingestLog := logging.New("ingest")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dbPath := os.Getenv(envDBPath)
	if dbPath == "" {
		dbPath = defaultDBPath
	}
	configLog.Info(fmt.Sprintf("%s=%s", envDBPath, dbPath))

	httpAddr := os.Getenv(envHTTPAddr)
	if httpAddr == "" {
		httpAddr = defaultHTTPAddr
	}
	configLog.Info(fmt.Sprintf("%s=%s", envHTTPAddr, httpAddr))

	// DATABASE_URL, when set, picks the engine (including Postgres);
	// unset, dbPath (BIRDCAGE_DB_PATH or its default) is passed through
	// as a bare path, which db.Open treats as SQLite -- the same
	// behavior as before DATABASE_URL existed.
	databaseURL := os.Getenv(envDatabaseURL)
	if databaseURL == "" {
		databaseURL = dbPath
	} else {
		configLog.Info(fmt.Sprintf("%s=%s", envDatabaseURL, redactDatabaseURL(databaseURL)))
	}

	database, err := db.Open(databaseURL)
	if err != nil {
		dbLog.Error(fmt.Sprintf("open database (%s=%q): %v", envDatabaseURL, databaseURL, err))
		os.Exit(1)
	}
	defer func() {
		if err := database.Close(); err != nil {
			dbLog.Error(fmt.Sprintf("close database: %v", err))
			os.Exit(1)
		}
	}()

	if err := db.Migrate(ctx, database); err != nil {
		dbLog.Error(fmt.Sprintf("migrate database: %v", err))
		os.Exit(1)
	}
	dbLog.Info(fmt.Sprintf("opened %s database, storing alerts via %s", database.Engine, redactDatabaseURL(databaseURL)))

	internalRangesEnv := os.Getenv(envInternalRanges)
	if internalRangesEnv != "" {
		configLog.Info(fmt.Sprintf("%s=%s", envInternalRanges, internalRangesEnv))
	}
	internalRanges, err := store.ParseInternalRanges(internalRangesEnv)
	if err != nil {
		configLog.Error(fmt.Sprintf("%s: %v", envInternalRanges, err))
		os.Exit(1)
	}

	// hub is shared between the dashboard's GET /api/stream (issue #44)
	// and the ingest listener below (issue #32): an alert the ingest
	// endpoint stores is published to it immediately, so an open
	// dashboard sees it without waiting for its 30s poll. Built here
	// (rather than letting api.NewHandler create its own, unreachable
	// one) specifically so both sides share the same instance.
	hub := stream.NewHub()

	// /api/* keeps its exact routing (internal/api.NewHandlerWithHub is
	// otherwise untouched); everything else is the dashboard frontend
	// (#36), embedded into this binary by web/embed.go with an SPA
	// fallback to index.html so a client-side route survives a refresh.
	rootMux := http.NewServeMux()
	rootMux.Handle("/api/", api.NewHandlerWithHub(database, internalRanges, hub))
	if uiHandler, err := web.Handler(); err != nil {
		httpLog.Warn(fmt.Sprintf("frontend: %v (serving API only)", err))
	} else {
		if !web.HasUI() {
			httpLog.Warn("no frontend was built into this binary (run `npm run build` in frontend/, see README) -- serving API only")
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
		// Routes Go's own internal server diagnostics (TLS handshake
		// errors from misbehaving clients, etc.) through the same
		// leveled/component output as everything else this binary
		// logs, rather than the stdlib default logger's unformatted
		// stderr lines being the one exception (mikroview's
		// main.go:1997 does the same).
		ErrorLog: slog.NewLogLogger(httpLog.Handler(), slog.LevelWarn),
	}

	// The ingest listener (issue #32) is only started once both TLS
	// files are configured -- see envIngestTLSCert's doc comment above
	// for why an operator who hasn't set them yet (normal, pending #47)
	// gets a disabled listener rather than a startup failure, while a
	// half-configured pair or an unloadable cert/key does fail startup:
	// this listener has no plaintext fallback to degrade to.
	ingestCert := os.Getenv(envIngestTLSCert)
	ingestKey := os.Getenv(envIngestTLSKey)
	var ingestServer *http.Server
	switch {
	case ingestCert == "" && ingestKey == "":
		ingestLog.Info(fmt.Sprintf("%s/%s not set; HTTPS ingest listener disabled (pending #47 enrolment)", envIngestTLSCert, envIngestTLSKey))
	case ingestCert == "" || ingestKey == "":
		ingestLog.Error(fmt.Sprintf("both %s and %s must be set together", envIngestTLSCert, envIngestTLSKey))
		os.Exit(1)
	default:
		configLog.Info(fmt.Sprintf("%s=%s", envIngestTLSCert, ingestCert))
		configLog.Info(fmt.Sprintf("%s=%s", envIngestTLSKey, ingestKey))
		ingestAddr := os.Getenv(envIngestAddr)
		if ingestAddr == "" {
			ingestAddr = defaultIngestAddr
		}
		configLog.Info(fmt.Sprintf("%s=%s", envIngestAddr, ingestAddr))
		srv, err := ingest.NewTLSServer(ingestAddr, ingest.NewHandler(database, hub), ingestCert, ingestKey)
		if err != nil {
			// Fail-closed, loudly, before any socket binds (issue #32:
			// "TLS certificate or key unloadable -> the ingest listener
			// refuses to start").
			ingestLog.Error(err.Error())
			os.Exit(1)
		}
		ingestServer = srv
	}

	// Every service below runs concurrently, and all are watched to
	// completion below -- a plain channel rather than a library
	// dependency, since a handful of goroutines are ever in flight and
	// all are collected the same way. Whichever finishes first (from a
	// signal, or from a failure of its own, e.g. "address already in
	// use") triggers stop() below, which cancels ctx and so brings the
	// others down too: without that, a lone failure in one service would
	// leave main blocked forever waiting on the rest.
	serviceCount := 1
	if ingestServer != nil {
		serviceCount++
	}
	results := make(chan serviceResult, serviceCount)

	go func() {
		httpLog.Info(fmt.Sprintf("serving dashboard HTTP API on %s", httpAddr))
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
			httpLog.Warn(fmt.Sprintf("shutdown: %v", err))
		}
	}()

	if ingestServer != nil {
		go func() {
			ingestLog.Info(fmt.Sprintf("serving HTTPS ingest listener on %s", ingestServer.Addr))
			// Cert/key are already loaded into ingestServer.TLSConfig by
			// ingest.NewTLSServer, so both arguments here are empty.
			err := ingestServer.ListenAndServeTLS("", "")
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			results <- serviceResult{"ingest server", err}
		}()

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
			defer cancel()
			if err := ingestServer.Shutdown(shutdownCtx); err != nil {
				ingestLog.Warn(fmt.Sprintf("shutdown: %v", err))
			}
		}()
	}

	// The first result to arrive (a signal, or any one service failing on
	// its own, e.g. "address already in use") triggers stop() so every
	// other service is asked to stop too; every remaining result is then
	// drained so main doesn't exit while a service is still shutting
	// down.
	mainLog := logging.New("birdcage")
	failed := false
	for i := 0; i < serviceCount; i++ {
		res := <-results
		if res.err != nil {
			mainLog.Error(fmt.Sprintf("%s: %v", res.name, res.err))
			failed = true
		}
		if i == 0 {
			stop() // idempotent; ensures every other service is asked to stop too
		}
	}

	if failed {
		os.Exit(1)
	}
	mainLog.Info("shutdown complete")
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
