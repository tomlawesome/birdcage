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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/enrol"
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
	// envIngestAddr configures issue #32's HTTPS ingest listener -- a
	// canary's agent (#48) posts event batches here, authenticated by
	// its own bearer token, never the dashboard's requireAuth seam.
	// Since #47 slice 1, the listener's serving certificate is minted by
	// birdcage's own CA (internal/ca, envCADir below) rather than a
	// cert/key pair an operator supplied by hand, so envIngestAddr alone
	// now gates the listener: unset disables it entirely (see the
	// switch in main below); set, it both picks the address and turns
	// the listener on. There is no half-configured state left to reject
	// -- issue #32's fail-closed rule ("no plaintext fallback; no
	// plaintext listener on any ingest port, ever") is upheld instead by
	// envCADir: an unloadable or misconfigured CA directory fails
	// startup loudly rather than falling back to plaintext.
	envIngestAddr = "BIRDCAGE_INGEST_ADDR"
	// envCADir is where internal/ca.Load keeps birdcage's own CA: it
	// loads dir/ca-key.pem and dir/ca.pem, generating and persisting
	// both the first time (#62 owner decision: this key is the only
	// private key birdcage ever writes to disk -- every certificate the
	// ingest listener serves after that is minted fresh in memory). The
	// directory must already exist, mode 0700, owned by the birdcage
	// process. Defaults under the Dockerfile's existing
	// /var/lib/birdcage volume, so a container operator gets a
	// persistent CA with no Dockerfile change.
	envCADir = "BIRDCAGE_CA_DIR"
	// envAdvertiseHost is the hostname or IP a canary's agent reaches
	// this birdcage instance on -- added as a SAN (alongside localhost
	// and 127.0.0.1, always included) to the ingest listener's serving
	// certificate, so a canary connecting to that address passes
	// certificate verification. Unset means only localhost/127.0.0.1
	// are covered, which is enough for same-host testing but not for a
	// real canary on another box.
	envAdvertiseHost = "BIRDCAGE_ADVERTISE_HOST"
	// envEnrolAddr configures issue #47 slice 1b's HTTPS enrolment
	// listener -- POST /enrol/hello (internal/enrol), the one place a
	// freshly minted deploy token (`birdcage canary enrol`) is ever
	// accepted. It is its own listener, never sharing a mux with ingest
	// or the dashboard (design note decision 1). Enabled whenever
	// envIngestAddr is set, not by a toggle of its own: the two are one
	// feature (enrolment hands a canary the credentials it then uses on
	// the ingest listener), so there is no configuration in which one
	// runs without the other. Uses the same CA-minted serving
	// certificate (same SANs, same TTL/renewal) as the ingest listener
	// -- see the shared getCert closure in main below.
	envEnrolAddr = "BIRDCAGE_ENROL_ADDR"

	defaultDBPath    = "birdcage.db"
	defaultHTTPAddr  = ":8080"
	defaultCADir     = "/var/lib/birdcage/ca"
	defaultEnrolAddr = ":8444"

	// ingestServingTTL/ingestRenewBefore are internal/ca.CA.
	// ServerCertificateSource's lifetime for the ingest listener's
	// serving leaf -- minted fresh in memory, so a short TTL costs
	// nothing on disk and limits how long a leaked leaf (never the CA
	// key) stays valid; renewal happens well ahead of expiry so a slow
	// handshake never races it.
	ingestServingTTL  = 24 * time.Hour
	ingestRenewBefore = 6 * time.Hour

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
	// Level first, so nothing logged below this line is ever silently
	// dropped or shown at the wrong threshold. The banner waits for the
	// server-start path: it exists to mark a restart in `docker logs`,
	// and a one-shot `birdcage canary enrol` whose output the operator
	// is about to paste must not be buried under it.
	logging.SetLevel(os.Getenv(envLogLevel))

	canaryLog := logging.New("canary")
	settingsLog := logging.New("settings")

	// `birdcage canary ...` (cmd/birdcage/canary.go) are standalone CLI
	// subcommands -- `add` a dev/testing convenience predating enrollment
	// (#34's "Not in this slice"), `mint`/`list`/`revoke` issue #32 item
	// 9's canary token management, `enrol` issue #47 slice 1b's deploy-
	// token mint -- that exit immediately rather than starting the
	// HTTP/ingest services below.
	if len(os.Args) > 1 && os.Args[1] == "canary" {
		if len(os.Args) < 3 {
			canaryLog.Error("usage: birdcage canary <add|mint|list|revoke|enrol> ...")
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
		case "enrol":
			err = runCanaryEnrol(os.Args[3:])
		default:
			canaryLog.Error(fmt.Sprintf("unknown canary subcommand %q (want add, mint, list, revoke or enrol)", os.Args[2]))
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

	logging.PrintBanner()

	// Component loggers for the real server-start path below -- one per
	// subsystem, so `docker logs | grep ingest` (or config, db, http)
	// isolates exactly that subsystem's lines.
	configLog := logging.New("config")
	dbLog := logging.New("db")
	httpLog := logging.New("http")
	ingestLog := logging.New("ingest")
	enrolLog := logging.New("enrol")

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

	// The ingest listener (issue #32) and the enrolment listener (issue
	// #47 slice 1b, envEnrolAddr) are only started when
	// BIRDCAGE_INGEST_ADDR is set -- see envIngestAddr's and
	// envEnrolAddr's doc comments above for why one setting gates both.
	// Once set, birdcage loads (or, on a fresh CA directory, generates)
	// its own CA and mints both listeners' serving certificates from it
	// -- #47 slice 1, #62 "Drop them": an unloadable or
	// wrongly-permissioned CA directory fails startup loudly, before any
	// socket binds, the same fail-closed posture issue #32 required of
	// the cert/key files this replaces.
	var ingestServer, enrolServer *http.Server
	ingestAddr := os.Getenv(envIngestAddr)
	if ingestAddr == "" {
		ingestLog.Info(fmt.Sprintf("%s not set; HTTPS ingest and enrolment listeners disabled", envIngestAddr))
	} else {
		configLog.Info(fmt.Sprintf("%s=%s", envIngestAddr, ingestAddr))

		caDir := os.Getenv(envCADir)
		if caDir == "" {
			caDir = defaultCADir
		}
		configLog.Info(fmt.Sprintf("%s=%s", envCADir, caDir))

		birdcageCA, caCreated, err := ca.Load(caDir, nil)
		if err != nil {
			// Fail-closed, loudly, before any socket binds -- the same
			// posture issue #32 required of an unloadable cert/key,
			// now applied to the CA directory instead.
			ingestLog.Error(fmt.Sprintf("load CA (%s=%q): %v", envCADir, caDir, err))
			os.Exit(1)
		}
		action := "loaded"
		if caCreated {
			action = "created"
		}
		// The pin is public -- it's the value the enrolment command
		// (a later slice) hands a canary operator to verify against --
		// but the CA key itself is never logged, here or anywhere else.
		ingestLog.Info(fmt.Sprintf("%s CA at %s: pin=%s expiry=%s", action, caDir, birdcageCA.Pin(), birdcageCA.Expiry().Format(time.RFC3339)))

		advertiseHost := os.Getenv(envAdvertiseHost)
		hosts := []string{"localhost", "127.0.0.1"}
		if advertiseHost != "" {
			configLog.Info(fmt.Sprintf("%s=%s", envAdvertiseHost, advertiseHost))
			hosts = append([]string{advertiseHost}, hosts...)
		}

		// ingestURL is POST /enrol/hello's new "ingest_url" field (issue
		// #47 slice 3): where a provisioned canary's agent posts to.
		// Built from the same advertiseHost as the serving certificate's
		// SANs, and BIRDCAGE_INGEST_ADDR's own port -- never the enrol
		// listener's port, since that is not where a provisioned canary
		// ever sends anything. Left empty (with a boot warning) when
		// BIRDCAGE_ADVERTISE_HOST is unset: the listeners still start --
		// same-host testing needs no advertised address -- but there is
		// no address to hand a real canary either.
		var ingestURL string
		if advertiseHost == "" {
			enrolLog.Warn(fmt.Sprintf("%s is not set; POST /enrol/hello's ingest_url will be empty", envAdvertiseHost))
		} else {
			_, ingestPort, err := net.SplitHostPort(ingestAddr)
			if err != nil {
				ingestLog.Error(fmt.Sprintf("%s=%q is not a valid address: %v", envIngestAddr, ingestAddr, err))
				os.Exit(1)
			}
			ingestURL = fmt.Sprintf("https://%s:%s", advertiseHost, ingestPort)
		}

		// Shared by both listeners below, deliberately: issue #47 slice
		// 1b's spec is "same SANs as ingest, same 24h/6h" for the
		// enrolment listener's own serving certificate, and passing this
		// one closure to both NewTLSServer calls is a stronger guarantee
		// of that than constructing a second, separately-configured
		// source that has to be kept in sync by hand.
		getCert := birdcageCA.ServerCertificateSource(hosts, ingestServingTTL, ingestRenewBefore, nil)
		// clientCAs: the ingest listener requires a client certificate
		// birdcageCA issued (issue #47 slice 3's mutual TLS); the
		// enrolment listener below passes nil -- a canary has no
		// certificate to present before it is provisioned.
		ingestServer = ingest.NewTLSServer(ingestAddr, ingest.NewHandler(database, hub), getCert, birdcageCA.Pool())

		enrolAddr := os.Getenv(envEnrolAddr)
		if enrolAddr == "" {
			enrolAddr = defaultEnrolAddr
		}
		configLog.Info(fmt.Sprintf("%s=%s", envEnrolAddr, enrolAddr))
		enrolServer = ingest.NewTLSServer(enrolAddr, enrol.NewHandler(database, birdcageCA, ingestURL, nil, enrolLog), getCert, nil)
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
	if enrolServer != nil {
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

	if enrolServer != nil {
		go func() {
			enrolLog.Info(fmt.Sprintf("serving HTTPS enrolment listener on %s", enrolServer.Addr))
			// Cert/key are already loaded into enrolServer.TLSConfig by
			// ingest.NewTLSServer, so both arguments here are empty.
			err := enrolServer.ListenAndServeTLS("", "")
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			results <- serviceResult{"enrol server", err}
		}()

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
			defer cancel()
			if err := enrolServer.Shutdown(shutdownCtx); err != nil {
				enrolLog.Warn(fmt.Sprintf("shutdown: %v", err))
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
