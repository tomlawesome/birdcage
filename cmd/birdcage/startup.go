package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/enrol"
	"github.com/tomlawesome/birdcage/internal/history"
	"github.com/tomlawesome/birdcage/internal/ingest"
	"github.com/tomlawesome/birdcage/internal/logging"
	"github.com/tomlawesome/birdcage/internal/mail"
	"github.com/tomlawesome/birdcage/internal/mailbox"
	"github.com/tomlawesome/birdcage/internal/startcheck"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/stream"
	"github.com/tomlawesome/birdcage/internal/tlsconfig"
	"github.com/tomlawesome/birdcage/web"
)

// startupError pairs a startup refusal with the component logger
// main() must report it on. Several of the functions below can refuse
// for more than one reason on more than one subsystem's behalf --
// loadStartupConfig fails as http, config or ingest depending which
// check tripped; checkStartupFiles fails as db or http -- so the
// refusal has to carry its own logger rather than main() guessing one
// from which function returned it. Every startup* function that can
// only ever fail onto a single logger skips this and just returns a
// plain error instead, with main() logging it on that one logger
// itself.
type startupError struct {
	log *slog.Logger
	msg string
}

func (e *startupError) Error() string { return e.msg }

// logStartupError logs err on the logger it names (if it is a
// *startupError) or does nothing (nil err). main() calls this and then
// os.Exit(1), matching every one of today's inline
// `log.Error(...); os.Exit(1)` sites this replaces.
func logStartupError(err error) {
	var se *startupError
	if errors.As(err, &se) {
		se.log.Error(se.msg)
	}
}

// errServeFailed is serveAll's non-nil return when a service failed --
// its text is never logged (the failing service's own Error line,
// logged inside serveAll, already said what happened); it exists only
// so main() can tell "clean shutdown" from "a service failed" and pick
// the right exit code.
var errServeFailed = errors.New("birdcage: a service failed")

// runSubcommand dispatches birdcage's non-server subcommands -- version,
// canary, settings and approval -- each of which exits immediately
// rather than starting the HTTP/ingest services. handled reports
// whether args named one of them at all: false means main should
// continue into the server-start path. When handled is true, exitCode
// is what main should exit with (0 meaning main should just return).
func runSubcommand(args []string, stdout io.Writer) (handled bool, exitCode int) {
	// `birdcage version` prints the stamped build version and exits. It
	// comes first, and writes to stdout rather than the log, because the
	// release job compares its output with the tag it built from: one
	// line, no banner, no level prefix.
	if len(args) > 1 && args[1] == "version" {
		if err := runVersion(stdout); err != nil {
			return true, 1
		}
		return true, 0
	}

	canaryLog := logging.New("canary")
	settingsLog := logging.New("settings")

	// `birdcage canary ...` (cmd/birdcage/canary.go) are standalone CLI
	// subcommands -- `add` a dev/testing convenience predating enrollment
	// (#34's "Not in this slice"), `mint`/`list`/`revoke` issue #32 item
	// 9's canary token management, `enrol` issue #47 slice 1b's deploy-
	// token mint -- that exit immediately rather than starting the
	// HTTP/ingest services below.
	if len(args) > 1 && args[1] == "canary" {
		if len(args) < 3 {
			canaryLog.Error("usage: birdcage canary <add|mint|list|revoke|enrol> ...")
			return true, 1
		}
		var err error
		switch args[2] {
		case "add":
			err = runCanaryAdd(args[3:])
		case "mint":
			err = runCanaryMint(args[3:])
		case "list":
			err = runCanaryList(args[3:])
		case "revoke":
			err = runCanaryRevoke(args[3:])
		case "enrol":
			err = runCanaryEnrol(args[3:])
		default:
			canaryLog.Error(fmt.Sprintf("unknown canary subcommand %q (want add, mint, list, revoke or enrol)", args[2]))
			return true, 1
		}
		if err != nil {
			canaryLog.Error(err.Error())
			return true, 1
		}
		return true, 0
	}

	// `birdcage settings ...` (cmd/birdcage/settings.go) is issue #46's
	// CLI for the settings table (note 17934: "schedule settings are
	// data, not configuration") -- `list`/`get` read a setting (or every
	// setting), falling back to its documented default when unset; `set`
	// writes one, validated against internal/store's closed key/value
	// rules. Like `canary` above, these exit immediately rather than
	// starting the HTTP/ingest services below.
	if len(args) > 1 && args[1] == "settings" {
		if len(args) < 3 {
			settingsLog.Error("usage: birdcage settings <list|get|set> ...")
			return true, 1
		}
		var err error
		switch args[2] {
		case "list":
			err = runSettingsList(args[3:])
		case "get":
			err = runSettingsGet(args[3:])
		case "set":
			err = runSettingsSet(args[3:])
		default:
			settingsLog.Error(fmt.Sprintf("unknown settings subcommand %q (want list, get or set)", args[2]))
			return true, 1
		}
		if err != nil {
			settingsLog.Error(err.Error())
			return true, 1
		}
		return true, 0
	}

	// `birdcage approval check <file>` (cmd/birdcage/approval.go) is
	// issue #54's way of trying a real provider's DKIM signature by
	// hand: a real signed approval cannot be a committed test fixture,
	// so the only honest way to find out whether an operator's mail
	// provider satisfies the rules is to run one through the same
	// verifier the agents use. Like `canary` and `settings` above, it
	// exits immediately rather than starting the services below.
	if len(args) > 1 && args[1] == "approval" {
		approvalLog := logging.New("approval")
		if len(args) < 3 {
			approvalLog.Error("usage: birdcage approval check <file.eml>")
			return true, 1
		}
		var err error
		switch args[2] {
		case "check":
			err = runApprovalCheck(args[3:])
		default:
			approvalLog.Error(fmt.Sprintf("unknown approval subcommand %q (want check)", args[2]))
			return true, 1
		}
		if err != nil {
			approvalLog.Error(err.Error())
			return true, 1
		}
		return true, 0
	}

	return false, 0
}

// startupConfig holds everything main() reads from the environment for
// the server-start path, resolved and defaulted by loadStartupConfig so
// every function downstream of it takes this struct rather than
// reaching for the environment itself.
type startupConfig struct {
	dbPath        string
	httpAddr      string
	httpTLSCert   string
	httpTLSKey    string
	httpSelection tlsconfig.Selection

	caDir    string
	caNeeded bool

	// databaseURL is set by main() itself, after mail/mailbox config
	// loads and before checkStartupDatabase -- see loadStartupConfig's
	// doc comment for why, unlike everything else here, it is not
	// resolved by loadStartupConfig.
	databaseURL string

	internalRangesEnv string
	internalRanges    []*net.IPNet

	ingestAddr       string
	enrolAddr        string
	advertiseHost    string
	ingestURL        string
	dashboardHostEnv string
}

// loadStartupConfig resolves every environment variable the
// server-start path needs, applies documented defaults, and emits
// today's `config` Info lines in today's order. It stops at the first
// refusal, returned as a *startupError naming the exact logger and
// wording main() used for that refusal today.
//
// Three things are read and validated here but *logged* later, by the
// code that actually uses them, so every existing log line stays in its
// original position: BIRDCAGE_INTERNAL_RANGES's Info line (main(), just
// before api.NewHandlerWithHub), BIRDCAGE_CA_DIR's (main(), just before
// loadStartupCA) and BIRDCAGE_INGEST_ADDR's/BIRDCAGE_ADVERTISE_HOST's
// (inside buildIngestServers, after the dashboard TLS mode lines).
// Because BIRDCAGE_INTERNAL_RANGES's parse and the ingest_url
// derivation's net.SplitHostPort both move here, a malformed value for
// either now refuses at this earlier point instead of its later
// original one -- still before any listener binds either way.
//
// DATABASE_URL is deliberately not resolved here: today it is read (and
// its Info line logged) after mail/mailbox config loads, which happens
// in main() between loadStartupConfig and checkStartupDatabase, so
// main() resolves it itself at that point instead.
func loadStartupConfig(getenv func(string) string, configLog, httpLog, ingestLog, enrolLog *slog.Logger) (startupConfig, error) {
	var cfg startupConfig

	cfg.dbPath = getenv(envDBPath)
	if cfg.dbPath == "" {
		cfg.dbPath = defaultDBPath
	}
	configLog.Info(fmt.Sprintf("%s=%s", envDBPath, cfg.dbPath))

	cfg.httpAddr = getenv(envHTTPAddr)
	if cfg.httpAddr == "" {
		cfg.httpAddr = defaultHTTPAddr
	}
	configLog.Info(fmt.Sprintf("%s=%s", envHTTPAddr, cfg.httpAddr))

	cfg.httpTLSCert = getenv(envHTTPTLSCert)
	cfg.httpTLSKey = getenv(envHTTPTLSKey)
	if cfg.httpTLSCert != "" {
		configLog.Info(fmt.Sprintf("%s=%s", envHTTPTLSCert, cfg.httpTLSCert))
	}
	if cfg.httpTLSKey != "" {
		configLog.Info(fmt.Sprintf("%s=%s", envHTTPTLSKey, cfg.httpTLSKey))
	}

	// Issue #63: decide, before anything else starts, which of the
	// four permitted modes the dashboard listener runs in -- or refuse
	// outright when the address itself is unusable. Never a plaintext
	// listener reachable off loopback.
	selection, err := tlsconfig.Select(cfg.httpAddr, cfg.httpTLSCert, cfg.httpTLSKey)
	if err != nil {
		return startupConfig{}, &startupError{httpLog, err.Error()}
	}
	cfg.httpSelection = selection

	cfg.ingestAddr = getenv(envIngestAddr)

	// birdcage's own CA (internal/ca) is needed by two independent
	// things: the dashboard's ModeMintedCert (issue #63) whenever no
	// operator certificate is configured, and the ingest/enrolment
	// listeners (issue #47/#62) whenever BIRDCAGE_INGEST_ADDR is set.
	// It is loaded only when one of those two actually needs it. A
	// deployment serving the dashboard from an operator certificate (or
	// on loopback/a unix socket behind its own proxy) with ingest off
	// uses no CA at all, and must not be made to own one: loading
	// unconditionally made birdcage demand a writable BIRDCAGE_CA_DIR
	// from installations that never mint anything, which broke
	// `npm run smoke` (pipeline 1320) and would have broken the same way
	// for an operator on first upgrade.
	cfg.caNeeded = cfg.httpSelection.Mode == tlsconfig.ModeMintedCert || cfg.ingestAddr != ""
	cfg.caDir = getenv(envCADir)
	if cfg.caDir == "" {
		cfg.caDir = defaultCADir
	}

	cfg.enrolAddr = getenv(envEnrolAddr)
	if cfg.enrolAddr == "" {
		cfg.enrolAddr = defaultEnrolAddr
	}
	cfg.advertiseHost = getenv(envAdvertiseHost)

	// ingestURL is POST /enrol/hello's new "ingest_url" field (issue
	// #47 slice 3): where a provisioned canary's agent posts to. Built
	// from the same advertiseHost as the serving certificate's SANs,
	// and BIRDCAGE_INGEST_ADDR's own port -- never the enrol listener's
	// port, since that is not where a provisioned canary ever sends
	// anything. Only derived when both the ingest listener and
	// advertiseHost are set, matching today: with ingest off there is
	// no ingest_url to derive at all, and buildIngestServers logs its
	// own "ingest_url will be empty" warning (today's wording, kept
	// there) when advertiseHost is unset but ingest is on.
	if cfg.ingestAddr != "" && cfg.advertiseHost != "" {
		_, ingestPort, err := net.SplitHostPort(cfg.ingestAddr)
		if err != nil {
			return startupConfig{}, &startupError{ingestLog, fmt.Sprintf("%s=%q is not a valid address: %v", envIngestAddr, cfg.ingestAddr, err)}
		}
		cfg.ingestURL = fmt.Sprintf("https://%s:%s", cfg.advertiseHost, ingestPort)
	}

	cfg.dashboardHostEnv = getenv(envDashboardHost)

	cfg.internalRangesEnv = getenv(envInternalRanges)
	internalRanges, err := store.ParseInternalRanges(cfg.internalRangesEnv)
	if err != nil {
		return startupConfig{}, &startupError{configLog, fmt.Sprintf("%s: %v", envInternalRanges, err)}
	}
	cfg.internalRanges = internalRanges

	return cfg, nil
}

// checkStartupFiles proves, before the CA loads or any listener binds,
// that the data directory and (ModeCert only) the configured TLS
// certificate/key are usable by this uid -- issue #70's rule. Refusals
// carry today's exact wording, on the same logger (db for the data
// directory, http for the certificate/key) main() used for them.
func checkStartupFiles(cfg startupConfig, dbLog, httpLog *slog.Logger) error {
	// Issue #70: prove the data directory and any configured TLS
	// certificate/key are actually usable by this uid before any
	// listener binds or the database opens -- never a fallback, never a
	// retry. The CA directory (internal/ca.Load) already fails closed
	// the same way; this covers the two paths that don't yet.
	if err := startcheck.WritableDir(filepath.Dir(cfg.dbPath)); err != nil {
		return &startupError{dbLog, err.Error()}
	}
	if cfg.httpSelection.Mode == tlsconfig.ModeCert {
		if err := startcheck.ReadableFile(cfg.httpTLSCert); err != nil {
			return &startupError{httpLog, err.Error()}
		}
		if err := startcheck.ReadableFile(cfg.httpTLSKey); err != nil {
			return &startupError{httpLog, err.Error()}
		}
	}
	return nil
}

// checkStartupDatabase runs after mail/mailbox config loads and the
// DATABASE_URL line -- matching today's position -- and proves cfg's
// databaseURL could not ever connect to Postgres without authenticating
// the server (issue #84). db.Open's sql.Open does no network I/O, so
// without this the refusal would otherwise only surface on the first
// query, deep inside pgx.
func checkStartupDatabase(cfg startupConfig) error {
	return startcheck.PostgresRequiresVerifyFull(cfg.databaseURL)
}

// loadStartupCA loads birdcage's own CA when cfg.caNeeded, and logs
// today's "no CA needed" line otherwise. An unloadable or
// wrongly-permissioned CA directory fails startup loudly before either
// listener binds, matching #62's and #70's existing fail-closed
// posture.
func loadStartupCA(cfg startupConfig, caLog *slog.Logger) (*ca.CA, error) {
	if !cfg.caNeeded {
		caLog.Info("no CA needed: the dashboard uses an operator certificate or a local plain listener, and the ingest listener is off")
		return nil, nil
	}

	birdcageCA, caCreated, err := ca.Load(cfg.caDir, nil)
	if err != nil {
		return nil, fmt.Errorf("load CA (%s=%q): %v", envCADir, cfg.caDir, err)
	}
	caAction := "loaded"
	if caCreated {
		caAction = "created"
	}
	// The pin is public -- it's the value the enrolment command
	// hands a canary operator to verify against, and the value an
	// operator pastes into their browser's trust store for the
	// dashboard's ModeMintedCert -- but the CA key itself is never
	// logged, here or anywhere else.
	caLog.Info(fmt.Sprintf("%s CA at %s: pin=%s expiry=%s", caAction, cfg.caDir, birdcageCA.Pin(), birdcageCA.Expiry().Format(time.RFC3339)))
	return birdcageCA, nil
}

// openStartupDatabase opens and migrates the database cfg.databaseURL
// selects, and logs today's "opened ... database" line. main() keeps
// the deferred Close.
func openStartupDatabase(ctx context.Context, cfg startupConfig, dbLog *slog.Logger) (*db.DB, error) {
	database, err := db.Open(cfg.databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open database (%s=%q): %v", envDatabaseURL, cfg.databaseURL, err)
	}

	if err := db.Migrate(ctx, database); err != nil {
		return nil, fmt.Errorf("migrate database: %v", err)
	}
	dbLog.Info(fmt.Sprintf("opened %s database, storing alerts via %s", database.Engine, redactDatabaseURL(cfg.databaseURL)))
	return database, nil
}

// runHistoryLoop is issue #56's canary state recorder's tick loop, with
// issue #55's outbound mail drain riding the same tick. sender may be
// nil (mail not configured); Sender.Tick is nil-safe.
//
// Neither a failed tick nor a failed send stops the process: the
// dashboard and the ingest listener are what this binary is for, and
// neither reads either table. Every failure is logged at ERROR and the
// loop carries on.
func runHistoryLoop(ctx context.Context, recorder *history.Recorder, sender *mail.Sender, interval time.Duration, historyLog, mailLog *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case tick := <-ticker.C:
			// ctx.Err() == nil keeps a tick canceled by shutdown
			// itself out of the log: that is the signal arriving
			// mid-tick, not a failure worth reporting.
			now := tick.UTC()
			if err := recorder.Tick(ctx, now); err != nil && ctx.Err() == nil {
				historyLog.Error(fmt.Sprintf("record canary state history: %v", err))
			}
			// Issue #55's outbound mail drains on the same loop,
			// immediately after the recorder rather than on a
			// ticker of its own: the recorder is what writes an
			// alert into the outbox, so sending in the same pass
			// means a token conflict is mailed on the tick that
			// noticed it rather than on whichever tick happened to
			// come next. Nil when mail is off, and a no-op then.
			//
			// A failure here is logged and the loop carries on, for
			// the same reason a failed history tick does: this
			// binary exists to run the dashboard and the ingest
			// listener, and neither reads this table.
			if err := sender.Tick(ctx, now); err != nil && ctx.Err() == nil {
				mailLog.Error(fmt.Sprintf("send queued mail: %v", err))
			}
		}
	}
}

// runApprovalLoop is issue #54's approval mailbox poll loop -- on a
// tick of its own rather than sharing the history loop's, since a poll
// opens a TLS connection to somebody else's IMAP server and is bounded
// at 60s, so hanging it off the 30s loop that records canary state
// would let a slow mail provider delay the thing this binary is
// actually for.
//
// A failed poll is logged and the loop carries on, for the same reason
// a failed history tick is: losing a poll costs a minute of latency on
// a human's reply, while exiting would take the dashboard and the
// ingest listener down over it.
func runApprovalLoop(ctx context.Context, reader *mailbox.Reader, handle mailbox.Handler, interval time.Duration, approvalLog *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// ctx.Err() == nil keeps a poll cut short by
			// shutdown out of the log: that is the signal
			// arriving mid-poll, not a failure worth reporting.
			if _, err := reader.Poll(ctx, handle); err != nil && ctx.Err() == nil {
				approvalLog.Error(fmt.Sprintf("poll the approval mailbox: %v", err))
			}
		}
	}
}

// buildDashboardServer builds the dashboard's http.Server -- mounting
// handler under /api/ and the embedded frontend (or a "no frontend"
// fallback) under / -- and wires whichever of issue #63's four modes
// cfg.httpSelection picked. unixPath is ModePlainUnixSocket's socket
// path (empty otherwise), for serveAll's serve/shutdown goroutines.
func buildDashboardServer(cfg startupConfig, birdcageCA *ca.CA, handler http.Handler, configLog, httpLog *slog.Logger) (*http.Server, string, error) {
	// /api/* keeps its exact routing (internal/api.NewHandlerWithHub is
	// otherwise untouched); everything else is the dashboard frontend
	// (#36), embedded into this binary by web/embed.go with an SPA
	// fallback to index.html so a client-side route survives a refresh.
	rootMux := http.NewServeMux()
	rootMux.Handle("/api/", handler)
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

	// Issue #63: wire the mode httpSelection picked above. unixPath
	// is read by serveAll's serve/shutdown goroutines; it stays empty
	// outside ModePlainUnixSocket.
	var unixPath string
	switch cfg.httpSelection.Mode {
	case tlsconfig.ModeCert:
		httpReloader, err := tlsconfig.NewCertReloader(cfg.httpTLSCert, cfg.httpTLSKey, httpLog)
		if err != nil {
			return nil, "", fmt.Errorf("load dashboard TLS certificate: %v", err)
		}
		httpServer.Addr = cfg.httpSelection.Addr
		httpServer.TLSConfig = tlsconfig.HardenedTLSConfig(httpReloader.GetCertificate)
		httpServer.Protocols = tlsconfig.HTTP1Only()
		httpLog.Info(fmt.Sprintf("dashboard TLS mode: operator-supplied certificate (cert=%s key=%s)", cfg.httpTLSCert, cfg.httpTLSKey))
	case tlsconfig.ModeMintedCert:
		if cfg.dashboardHostEnv != "" {
			configLog.Info(fmt.Sprintf("%s=%s", envDashboardHost, cfg.dashboardHostEnv))
		}
		dashboardHosts, err := tlsconfig.DashboardHosts(cfg.dashboardHostEnv)
		if err != nil {
			if dashboardHosts == nil {
				// Only the explicit-and-empty case (BIRDCAGE_DASHBOARD_HOST
				// set to nothing usable) returns no hosts at all -- that is
				// a configuration mistake, not something to guess past.
				return nil, "", err
			}
			// Best-effort case: enumerating this machine's interfaces
			// failed, but the loopback trio (and the hostname, if that
			// much worked) is still usable -- continue, having logged why
			// an operator might see fewer SANs than expected.
			httpLog.Warn(fmt.Sprintf("could not list every network interface for the dashboard certificate, continuing with fewer names: %v", err))
		}
		httpServer.Addr = cfg.httpSelection.Addr
		httpServer.TLSConfig = tlsconfig.HardenedTLSConfig(birdcageCA.ServerCertificateSource(dashboardHosts, dashboardServingTTL, dashboardRenewBefore, nil))
		httpServer.Protocols = tlsconfig.HTTP1Only()
		// Named explicitly, per host, so an operator who hits a browser
		// warning can see from this line alone whether it's because a
		// name they expect is missing, without guessing -- and the pin
		// they need to install the CA and make the warning go away.
		httpLog.Info(fmt.Sprintf("dashboard TLS mode: certificate minted from birdcage's own CA (pin=%s), covering: %s -- install the CA to stop the browser warning, see docs/configuration.md#dashboard-tls", birdcageCA.Pin(), strings.Join(dashboardHosts, ", ")))
	case tlsconfig.ModePlainLoopbackTCP:
		httpServer.Addr = cfg.httpSelection.Addr
		httpLog.Info("dashboard TLS mode: plain HTTP bound to loopback")
	case tlsconfig.ModePlainUnixSocket:
		unixPath = cfg.httpSelection.UnixPath
		httpLog.Info(fmt.Sprintf("dashboard TLS mode: plain HTTP on unix socket %s", unixPath))
	}

	return httpServer, unixPath, nil
}

// buildIngestServers builds the HTTPS ingest and enrolment listeners
// issue #32/#47 gate on BIRDCAGE_INGEST_ADDR -- both nil, with today's
// "disabled" Info line, when it is unset. Once set, both listeners mint
// their serving certificates from birdcageCA -- #47 slice 1, #62 "Drop
// them".
//
// hook (main.go's *selftestsched.Scheduler) is what turns a rotation
// completing, and -- #47 steps 7-9 -- a provisioned canary's very first
// authenticated request, into a self-test mint; nothing here has to
// change when the hook interface grows a method, since Scheduler already
// implements both and this parameter's static type is the interface, not
// the concrete package.
func buildIngestServers(cfg startupConfig, database *db.DB, birdcageCA *ca.CA, hub *stream.Hub, idx *store.SelfTestIndex, hook ingest.SelfTestRotationHook, configLog, ingestLog, enrolLog *slog.Logger) (ingestServer, enrolServer *http.Server, err error) {
	if cfg.ingestAddr == "" {
		ingestLog.Info(fmt.Sprintf("%s not set; HTTPS ingest and enrolment listeners disabled", envIngestAddr))
		return nil, nil, nil
	}

	configLog.Info(fmt.Sprintf("%s=%s", envIngestAddr, cfg.ingestAddr))

	hosts := []string{"localhost", "127.0.0.1"}
	if cfg.advertiseHost != "" {
		configLog.Info(fmt.Sprintf("%s=%s", envAdvertiseHost, cfg.advertiseHost))
		hosts = append([]string{cfg.advertiseHost}, hosts...)
	} else {
		// ingestURL is POST /enrol/hello's new "ingest_url" field
		// (issue #47 slice 3): left empty (with this boot warning) when
		// BIRDCAGE_ADVERTISE_HOST is unset -- the listeners still start
		// -- same-host testing needs no advertised address -- but there
		// is no address to hand a real canary either.
		enrolLog.Warn(fmt.Sprintf("%s is not set; POST /enrol/hello's ingest_url will be empty", envAdvertiseHost))
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
	ingestServer = ingest.NewTLSServer(cfg.ingestAddr, ingest.NewHandler(database, hub, idx, hook, ingest.WithClientCertSigner(birdcageCA)), getCert, birdcageCA.Pool())

	configLog.Info(fmt.Sprintf("%s=%s", envEnrolAddr, cfg.enrolAddr))
	enrolServer = ingest.NewTLSServer(cfg.enrolAddr, enrol.NewHandler(database, birdcageCA, cfg.ingestURL, nil, enrolLog), getCert, nil)

	return ingestServer, enrolServer, nil
}

// serveAll runs the dashboard, ingest and enrolment listeners
// concurrently and watches them to completion. It returns errServeFailed
// the moment any service has failed -- each one's own Error line is
// already logged, on mainLog, by the point this returns, so main() logs
// nothing further -- and nil once every service has shut down cleanly,
// having logged "shutdown complete" itself.
func serveAll(ctx context.Context, stop context.CancelFunc, dashboard *http.Server, mode tlsconfig.Mode, unixPath string, ingestServer, enrolServer *http.Server, httpLog, ingestLog, enrolLog, mainLog *slog.Logger) error {
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
		var err error
		switch mode {
		case tlsconfig.ModeCert, tlsconfig.ModeMintedCert:
			httpLog.Info(fmt.Sprintf("serving dashboard HTTPS on %s", dashboard.Addr))
			// The certificate source is already loaded into
			// httpServer.TLSConfig above (tlsconfig.NewCertReloader for
			// ModeCert, birdcageCA.ServerCertificateSource for
			// ModeMintedCert), so both arguments here are empty, matching
			// ingest.NewTLSServer's callers.
			err = dashboard.ListenAndServeTLS("", "")
		case tlsconfig.ModePlainUnixSocket:
			httpLog.Info(fmt.Sprintf("serving dashboard HTTP on unix socket %s", unixPath))
			var ln net.Listener
			ln, err = tlsconfig.UnixListener(unixPath)
			if err == nil {
				err = dashboard.Serve(ln)
			}
		default: // ModePlainLoopbackTCP
			httpLog.Info(fmt.Sprintf("serving dashboard HTTP on %s", dashboard.Addr))
			err = dashboard.ListenAndServe()
		}
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
		if err := dashboard.Shutdown(shutdownCtx); err != nil {
			httpLog.Warn(fmt.Sprintf("shutdown: %v", err))
		}
		if unixPath != "" {
			// net.UnixListener.Close (invoked by Shutdown above) already
			// unlinks the socket file it created; this is belt and
			// braces for a listener that for whatever reason didn't,
			// tolerating "already gone" the same way ca.go's own cleanup
			// does elsewhere.
			if err := os.Remove(unixPath); err != nil && !os.IsNotExist(err) {
				httpLog.Warn(fmt.Sprintf("remove unix socket %s: %v", unixPath, err))
			}
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
		return errServeFailed
	}
	mainLog.Info("shutdown complete")
	return nil
}
