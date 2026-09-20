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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tomlawesome/birdcage/internal/api"
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
	// envHTTPAddr, together with envHTTPTLSCert/envHTTPTLSKey below,
	// picks which of issue #63's four permitted modes the dashboard
	// HTTP listener runs in -- see internal/tlsconfig.Select, called
	// below. Never a fifth mode, and never a plaintext listener reachable
	// off loopback: an address with no certificate configured and a
	// non-loopback (or empty) host, including the default below, now
	// gets a certificate birdcage mints from its own CA (ModeMintedCert)
	// rather than refusing or falling back to plaintext.
	envHTTPAddr = "BIRDCAGE_HTTP_ADDR"
	// envHTTPTLSCert/envHTTPTLSKey name an operator-supplied PEM
	// certificate and key for the dashboard listener (issue #63's
	// ModeCert) -- both or neither; one alone is a startup error. Their
	// files are reloaded whenever either's mtime changes (see
	// internal/tlsconfig.CertReloader), so renewing a certificate in
	// place needs no restart. When neither is set, ModeMintedCert below
	// takes over instead of refusing.
	envHTTPTLSCert = "BIRDCAGE_HTTP_TLS_CERT"
	envHTTPTLSKey  = "BIRDCAGE_HTTP_TLS_KEY"
	// envDashboardHost names the hostnames and/or IP addresses (comma
	// separated) issue #63's ModeMintedCert mints the dashboard's leaf
	// certificate for -- see internal/tlsconfig.DashboardHosts. Unset
	// means birdcage guesses: this machine's hostname, every
	// non-loopback IP address on any interface, and
	// localhost/127.0.0.1/::1 -- an operator commonly browses to the
	// dashboard by LAN IP from another machine, so IP SANs are not
	// optional. Ignored by every other mode.
	envDashboardHost = "BIRDCAGE_DASHBOARD_HOST"
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

	// dashboardServingTTL/dashboardRenewBefore are the dashboard's own
	// ModeMintedCert leaf's lifetime -- same values as the ingest
	// listener's for the same reason (a short TTL on a leaf that is
	// never written to disk costs nothing and bounds how long a leaked
	// one matters), kept as separate constants because the two
	// listeners' lifetimes have no reason to be tied together going
	// forward.
	dashboardServingTTL  = 24 * time.Hour
	dashboardRenewBefore = 6 * time.Hour

	// httpReadHeaderTimeout bounds how long the HTTP server waits for a
	// client to finish sending request headers, so a slow or stalled
	// client can't tie up a connection indefinitely.
	httpReadHeaderTimeout = 5 * time.Second
	// httpShutdownTimeout bounds Shutdown's wait for in-flight requests
	// to finish once ctx is canceled, so process exit is never blocked
	// on a client that never goes away.
	httpShutdownTimeout = 5 * time.Second

	// historyTickInterval is how often internal/history reconciles each
	// canary's health states against the spans it has open (issue #56).
	// It is the granularity of every start and end time in that history:
	// a state is recorded as having begun at the first tick that saw it,
	// so 30s is the most a span's edges can be wrong by. Cheap enough to
	// run that often -- a tick is the same query GET /api/canaries
	// already runs on every dashboard poll, plus one small transaction.
	historyTickInterval = 30 * time.Second
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

	// `birdcage approval check <file>` (cmd/birdcage/approval.go) is
	// issue #54's way of trying a real provider's DKIM signature by
	// hand: a real signed approval cannot be a committed test fixture,
	// so the only honest way to find out whether an operator's mail
	// provider satisfies the rules is to run one through the same
	// verifier the agents use. Like `canary` and `settings` above, it
	// exits immediately rather than starting the services below.
	if len(os.Args) > 1 && os.Args[1] == "approval" {
		approvalLog := logging.New("approval")
		if len(os.Args) < 3 {
			approvalLog.Error("usage: birdcage approval check <file.eml>")
			os.Exit(1)
		}
		var err error
		switch os.Args[2] {
		case "check":
			err = runApprovalCheck(os.Args[3:])
		default:
			approvalLog.Error(fmt.Sprintf("unknown approval subcommand %q (want check)", os.Args[2]))
			os.Exit(1)
		}
		if err != nil {
			approvalLog.Error(err.Error())
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
	caLog := logging.New("ca")
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

	httpTLSCert := os.Getenv(envHTTPTLSCert)
	httpTLSKey := os.Getenv(envHTTPTLSKey)
	if httpTLSCert != "" {
		configLog.Info(fmt.Sprintf("%s=%s", envHTTPTLSCert, httpTLSCert))
	}
	if httpTLSKey != "" {
		configLog.Info(fmt.Sprintf("%s=%s", envHTTPTLSKey, httpTLSKey))
	}

	// Issue #63: decide, before anything else starts, which of the
	// four permitted modes the dashboard listener runs in -- or refuse
	// outright when the address itself is unusable. Never a plaintext
	// listener reachable off loopback.
	httpSelection, err := tlsconfig.Select(httpAddr, httpTLSCert, httpTLSKey)
	if err != nil {
		httpLog.Error(err.Error())
		os.Exit(1)
	}

	// Issue #70: prove the data directory and any configured TLS
	// certificate/key are actually usable by this uid before any
	// listener binds or the database opens -- never a fallback, never a
	// retry. The CA directory (internal/ca.Load) already fails closed
	// the same way; this covers the two paths that don't yet.
	if err := startcheck.WritableDir(filepath.Dir(dbPath)); err != nil {
		dbLog.Error(err.Error())
		os.Exit(1)
	}
	if httpSelection.Mode == tlsconfig.ModeCert {
		if err := startcheck.ReadableFile(httpTLSCert); err != nil {
			httpLog.Error(err.Error())
			os.Exit(1)
		}
		if err := startcheck.ReadableFile(httpTLSKey); err != nil {
			httpLog.Error(err.Error())
			os.Exit(1)
		}
	}

	// birdcage's own CA (internal/ca) is loaded here, unconditionally and
	// before any listener binds or the database opens, because two
	// independent things need it: the dashboard's ModeMintedCert (issue
	// #63, this block) whenever no operator certificate is configured,
	// and the ingest/enrolment listeners (issue #47/#62) whenever
	// BIRDCAGE_INGEST_ADDR is set. Loading it once here -- rather than
	// only inside the "ingest is on" branch further down, which is where
	// it used to live and where the dashboard's own-CA mode could not
	// reach it -- means neither caller loads it twice, and an unloadable
	// or wrongly-permissioned CA directory fails startup loudly before
	// either the dashboard or the ingest listener binds, matching #62's
	// and #70's existing fail-closed posture.
	caDir := os.Getenv(envCADir)
	if caDir == "" {
		caDir = defaultCADir
	}
	configLog.Info(fmt.Sprintf("%s=%s", envCADir, caDir))

	birdcageCA, caCreated, err := ca.Load(caDir, nil)
	if err != nil {
		caLog.Error(fmt.Sprintf("load CA (%s=%q): %v", envCADir, caDir, err))
		os.Exit(1)
	}
	caAction := "loaded"
	if caCreated {
		caAction = "created"
	}
	// The pin is public -- it's the value the enrolment command hands a
	// canary operator to verify against, and the value an operator
	// pastes into their browser's trust store for the dashboard's
	// ModeMintedCert -- but the CA key itself is never logged, here or
	// anywhere else.
	caLog.Info(fmt.Sprintf("%s CA at %s: pin=%s expiry=%s", caAction, caDir, birdcageCA.Pin(), birdcageCA.Expiry().Format(time.RFC3339)))

	// Issue #55: outbound mail is all-or-nothing and is settled here,
	// before the database opens and long before any listener binds --
	// including reading the password file, so an unreadable or empty
	// one refuses to start with startcheck's own message rather than
	// surfacing much later inside a failed send.
	mailLog := logging.New("mail")
	mailConfig, mailEnabled := loadMailConfig(mailLog)

	// Issue #54: the inbound half, settled in the same place and for
	// the same reason -- including reading the IMAP password file, so
	// an unreadable or empty one refuses to start here rather than
	// surfacing much later inside a failed poll.
	approvalLog := logging.New("approval")
	mailboxConfig, mailboxEnabled := loadMailboxConfig(approvalLog)

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

	// Issue #56's canary state recorder, started as soon as the schema
	// is in place. Start runs once, before the loop: only it can see the
	// gap between the last tick this database recorded and now -- the
	// stretch nothing was watching -- and it writes that down instead of
	// letting the history read as healthy through an outage.
	//
	// Neither a failed start nor a failed tick stops the process. The
	// dashboard and the ingest listener are what this binary is for, and
	// neither reads this table; losing a tick costs 30s of precision at
	// the edge of a span, while exiting would take the whole service
	// down over bookkeeping. Every failure is logged at ERROR and the
	// loop carries on.
	// Issue #55's sender, and the hook that feeds it. Both are nil when
	// mail is not configured: internal/mail's methods are nil-safe, so
	// the tick below runs unconditionally and does nothing, and the
	// recorder is built with no hook at all rather than one that checks
	// a flag on every state change.
	//
	// The hook runs inside the recorder's own transaction, so the alert
	// and the state period that caused it commit together or not at
	// all.
	var mailSender *mail.Sender
	var conflictHook history.TokenConflictHook
	if mailEnabled {
		mailSender = mail.New(database, mailConfig, mailLog)
		conflictHook = func(hookCtx context.Context, tx *db.Tx, canaryID, canaryName string, at time.Time) error {
			return mailSender.EnqueueTokenConflict(hookCtx, tx, canaryID, canaryName, at)
		}
	}

	historyLog := logging.New("history")
	stateRecorder := history.NewWithTokenConflictHook(database, conflictHook)
	if err := stateRecorder.Start(ctx, time.Now().UTC()); err != nil {
		historyLog.Error(fmt.Sprintf("start canary state recorder: %v", err))
	}
	go func() {
		ticker := time.NewTicker(historyTickInterval)
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
				if err := stateRecorder.Tick(ctx, now); err != nil && ctx.Err() == nil {
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
				if err := mailSender.Tick(ctx, now); err != nil && ctx.Err() == nil {
					mailLog.Error(fmt.Sprintf("send queued mail: %v", err))
				}
			}
		}
	}()

	// Issue #54's approval mailbox, on a tick of its own rather than
	// sharing the history loop's: a poll opens a TLS connection to
	// somebody else's IMAP server and is bounded at 60s, so hanging it
	// off the 30s loop that records canary state would let a slow mail
	// provider delay the thing this binary is actually for. Started
	// only when the mailbox is configured; there is no nil-safe no-op
	// tick to run otherwise.
	//
	// A failed poll is logged and the loop carries on, for the same
	// reason a failed history tick is: losing a poll costs a minute of
	// latency on a human's reply, while exiting would take the
	// dashboard and the ingest listener down over it.
	if mailboxEnabled {
		reader := mailbox.New(mailboxConfig, approvalLog)
		handle := approvalHandler(database, approvalLog)
		go func() {
			ticker := time.NewTicker(approvalPollInterval)
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
		}()
	}

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
	rootMux.Handle("/api/", api.NewHandlerWithHub(database, internalRanges, hub, mailEnabled))
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

	// Issue #63: wire the mode httpSelection picked above. httpUnixPath
	// is read by the serve/shutdown goroutines below; it stays empty
	// outside ModePlainUnixSocket.
	var httpUnixPath string
	switch httpSelection.Mode {
	case tlsconfig.ModeCert:
		httpReloader, err := tlsconfig.NewCertReloader(httpTLSCert, httpTLSKey, httpLog)
		if err != nil {
			httpLog.Error(fmt.Sprintf("load dashboard TLS certificate: %v", err))
			os.Exit(1)
		}
		httpServer.Addr = httpSelection.Addr
		httpServer.TLSConfig = tlsconfig.HardenedTLSConfig(httpReloader.GetCertificate)
		httpServer.Protocols = tlsconfig.HTTP1Only()
		httpLog.Info(fmt.Sprintf("dashboard TLS mode: operator-supplied certificate (cert=%s key=%s)", httpTLSCert, httpTLSKey))
	case tlsconfig.ModeMintedCert:
		dashboardHostEnv := os.Getenv(envDashboardHost)
		if dashboardHostEnv != "" {
			configLog.Info(fmt.Sprintf("%s=%s", envDashboardHost, dashboardHostEnv))
		}
		dashboardHosts, err := tlsconfig.DashboardHosts(dashboardHostEnv)
		if err != nil {
			if dashboardHosts == nil {
				// Only the explicit-and-empty case (BIRDCAGE_DASHBOARD_HOST
				// set to nothing usable) returns no hosts at all -- that is
				// a configuration mistake, not something to guess past.
				httpLog.Error(err.Error())
				os.Exit(1)
			}
			// Best-effort case: enumerating this machine's interfaces
			// failed, but the loopback trio (and the hostname, if that
			// much worked) is still usable -- continue, having logged why
			// an operator might see fewer SANs than expected.
			httpLog.Warn(fmt.Sprintf("could not list every network interface for the dashboard certificate, continuing with fewer names: %v", err))
		}
		httpServer.Addr = httpSelection.Addr
		httpServer.TLSConfig = tlsconfig.HardenedTLSConfig(birdcageCA.ServerCertificateSource(dashboardHosts, dashboardServingTTL, dashboardRenewBefore, nil))
		httpServer.Protocols = tlsconfig.HTTP1Only()
		// Named explicitly, per host, so an operator who hits a browser
		// warning can see from this line alone whether it's because a
		// name they expect is missing, without guessing -- and the pin
		// they need to install the CA and make the warning go away.
		httpLog.Info(fmt.Sprintf("dashboard TLS mode: certificate minted from birdcage's own CA (pin=%s), covering: %s -- install the CA to stop the browser warning, see docs/configuration.md#dashboard-tls", birdcageCA.Pin(), strings.Join(dashboardHosts, ", ")))
	case tlsconfig.ModePlainLoopbackTCP:
		httpServer.Addr = httpSelection.Addr
		httpLog.Info("dashboard TLS mode: plain HTTP bound to loopback")
	case tlsconfig.ModePlainUnixSocket:
		httpUnixPath = httpSelection.UnixPath
		httpLog.Info(fmt.Sprintf("dashboard TLS mode: plain HTTP on unix socket %s", httpUnixPath))
	}

	// The ingest listener (issue #32) and the enrolment listener (issue
	// #47 slice 1b, envEnrolAddr) are only started when
	// BIRDCAGE_INGEST_ADDR is set -- see envIngestAddr's and
	// envEnrolAddr's doc comments above for why one setting gates both.
	// Once set, both listeners mint their serving certificates from
	// birdcageCA, loaded unconditionally above (alongside the dashboard's
	// own ModeMintedCert case) -- #47 slice 1, #62 "Drop them".
	var ingestServer, enrolServer *http.Server
	ingestAddr := os.Getenv(envIngestAddr)
	if ingestAddr == "" {
		ingestLog.Info(fmt.Sprintf("%s not set; HTTPS ingest and enrolment listeners disabled", envIngestAddr))
	} else {
		configLog.Info(fmt.Sprintf("%s=%s", envIngestAddr, ingestAddr))

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
		var err error
		switch httpSelection.Mode {
		case tlsconfig.ModeCert, tlsconfig.ModeMintedCert:
			httpLog.Info(fmt.Sprintf("serving dashboard HTTPS on %s", httpServer.Addr))
			// The certificate source is already loaded into
			// httpServer.TLSConfig above (tlsconfig.NewCertReloader for
			// ModeCert, birdcageCA.ServerCertificateSource for
			// ModeMintedCert), so both arguments here are empty, matching
			// ingest.NewTLSServer's callers.
			err = httpServer.ListenAndServeTLS("", "")
		case tlsconfig.ModePlainUnixSocket:
			httpLog.Info(fmt.Sprintf("serving dashboard HTTP on unix socket %s", httpUnixPath))
			var ln net.Listener
			ln, err = tlsconfig.UnixListener(httpUnixPath)
			if err == nil {
				err = httpServer.Serve(ln)
			}
		default: // ModePlainLoopbackTCP
			httpLog.Info(fmt.Sprintf("serving dashboard HTTP on %s", httpServer.Addr))
			err = httpServer.ListenAndServe()
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
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			httpLog.Warn(fmt.Sprintf("shutdown: %v", err))
		}
		if httpUnixPath != "" {
			// net.UnixListener.Close (invoked by Shutdown above) already
			// unlinks the socket file it created; this is belt and
			// braces for a listener that for whatever reason didn't,
			// tolerating "already gone" the same way ca.go's own cleanup
			// does elsewhere.
			if err := os.Remove(httpUnixPath); err != nil && !os.IsNotExist(err) {
				httpLog.Warn(fmt.Sprintf("remove unix socket %s: %v", httpUnixPath, err))
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
