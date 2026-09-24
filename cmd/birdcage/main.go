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
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/history"
	"github.com/tomlawesome/birdcage/internal/logging"
	"github.com/tomlawesome/birdcage/internal/mail"
	"github.com/tomlawesome/birdcage/internal/mailbox"
	"github.com/tomlawesome/birdcage/internal/selftestsched"
	"github.com/tomlawesome/birdcage/internal/store"
	"github.com/tomlawesome/birdcage/internal/stream"
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
	// -- see the shared getCert closure in buildIngestServers below.
	envEnrolAddr = "BIRDCAGE_ENROL_ADDR"

	// envTestClientCertTTL is a test-only override for how long an
	// issued or renewed client certificate lives (ADR-0012 B2's normal
	// 7 days), so a live journey can drive a certificate to half-life
	// and expiry in minutes instead of days (#130 scope: "TTL
	// overridden to minutes in the fixture"). Refused above
	// maxTestClientCertTTL so a typo or a value copied into a real
	// deployment can never quietly outlive the real 7-day rule it is
	// meant to shorten, not lengthen.
	envTestClientCertTTL = "BIRDCAGE_TEST_CLIENT_CERT_TTL"
	// maxTestClientCertTTL bounds envTestClientCertTTL: it can only ever
	// shorten ADR-0012 B2's 7-day certificate life, never extend it.
	maxTestClientCertTTL = 7 * 24 * time.Hour

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

	// selfTestTickInterval is how often internal/selftestsched checks
	// the self-test schedule (issue #46 item 5): once a minute, since
	// the schedule itself is a "HH:MM" time of day and a tick any more
	// often than that could fire the same minute twice.
	selfTestTickInterval = time.Minute
)

// serviceResult is what each of the two services below reports once it
// has stopped -- name identifies which one, for the log line.
type serviceResult struct {
	name string
	err  error
}

func main() {
	// Level first, so nothing logged below is silently dropped or shown
	// at the wrong threshold. The banner waits for the server-start
	// path so a `canary enrol` paste isn't buried under it.
	logging.SetLevel(os.Getenv(envLogLevel))

	// version/canary/settings/approval all exit immediately rather than
	// starting the HTTP/ingest services below -- see runSubcommand.
	if handled, exitCode := runSubcommand(os.Args, os.Stdout); handled {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return
	}

	logging.PrintBanner()

	// Component loggers for the server-start path below -- one per
	// subsystem, so `docker logs | grep ingest` isolates its lines.
	configLog := logging.New("config")
	dbLog := logging.New("db")
	httpLog := logging.New("http")
	caLog := logging.New("ca")
	ingestLog := logging.New("ingest")
	enrolLog := logging.New("enrol")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadStartupConfig(os.Getenv, configLog, httpLog, ingestLog, enrolLog)
	if err != nil {
		logStartupError(err)
		os.Exit(1)
	}

	if err := checkStartupFiles(cfg, dbLog, httpLog); err != nil {
		logStartupError(err)
		os.Exit(1)
	}

	if cfg.caNeeded {
		configLog.Info(fmt.Sprintf("%s=%s", envCADir, cfg.caDir))
	}
	birdcageCA, err := loadStartupCA(cfg, caLog)
	if err != nil {
		caLog.Error(err.Error())
		os.Exit(1)
	}

	// Issue #55/#54: outbound mail and the inbound approval mailbox are
	// each all-or-nothing and settled here, including their password
	// files, so a bad config refuses at startup, not inside a failed
	// send or poll.
	mailLog := logging.New("mail")
	mailConfig, mailEnabled := loadMailConfig(mailLog)
	approvalLog := logging.New("approval")
	mailboxConfig, mailboxEnabled := loadMailboxConfig(approvalLog)

	// DATABASE_URL picks the engine (Postgres) when set; unset,
	// cfg.dbPath passes through as a bare path, which db.Open treats
	// as SQLite.
	cfg.databaseURL = os.Getenv(envDatabaseURL)
	if cfg.databaseURL == "" {
		cfg.databaseURL = cfg.dbPath
	} else {
		configLog.Info(fmt.Sprintf("%s=%s", envDatabaseURL, redactDatabaseURL(cfg.databaseURL)))
	}

	if err := checkStartupDatabase(cfg); err != nil {
		dbLog.Error(err.Error())
		os.Exit(1)
	}

	database, err := openStartupDatabase(ctx, cfg, dbLog)
	if err != nil {
		dbLog.Error(err.Error())
		os.Exit(1)
	}
	defer func() {
		if err := database.Close(); err != nil {
			dbLog.Error(fmt.Sprintf("close database: %v", err))
			os.Exit(1)
		}
	}()

	// Issue #56's canary state recorder starts once the schema is in
	// place (a failed Start is non-fatal, per runHistoryLoop's tick
	// policy). mailSender/conflictHook are nil when mail is off
	// (internal/mail is nil-safe); the hook runs inside the recorder's
	// own transaction, so the alert and the state commit together.
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
	go runHistoryLoop(ctx, stateRecorder, mailSender, historyTickInterval, historyLog, mailLog)

	// Started only when the mailbox is configured; there is no
	// nil-safe no-op tick to run otherwise.
	if mailboxEnabled {
		reader := mailbox.New(mailboxConfig, approvalLog)
		handle := approvalHandler(database, approvalLog)
		go runApprovalLoop(ctx, reader, handle, approvalPollInterval, approvalLog)
	}

	// hub (issue #44) and selfTestIndex (issue #46) are each shared
	// between the dashboard/ingest listener below and their own
	// scheduler, so an alert or marker is visible immediately rather
	// than through an unreachable second copy.
	hub := stream.NewHub()
	selfTestIndex := store.NewSelfTestIndex()
	selfTestLog := logging.New("selftest")
	selfTestScheduler := selftestsched.New(database, selfTestIndex, time.Now, selfTestLog)
	go selfTestScheduler.Run(ctx, selfTestTickInterval)

	if cfg.internalRangesEnv != "" {
		configLog.Info(fmt.Sprintf("%s=%s", envInternalRanges, cfg.internalRangesEnv))
	}
	apiHandler := api.NewHandlerWithHub(database, cfg.internalRanges, hub, mailEnabled)

	dashboardServer, unixPath, err := buildDashboardServer(cfg, birdcageCA, apiHandler, configLog, httpLog)
	if err != nil {
		httpLog.Error(err.Error())
		os.Exit(1)
	}

	ingestServer, enrolServer, err := buildIngestServers(cfg, database, birdcageCA, hub, selfTestIndex, selfTestScheduler, configLog, ingestLog, enrolLog)
	if err != nil {
		ingestLog.Error(err.Error())
		os.Exit(1)
	}

	mainLog := logging.New("birdcage")
	if err := serveAll(ctx, stop, dashboardServer, cfg.httpSelection.Mode, unixPath, ingestServer, enrolServer, httpLog, ingestLog, enrolLog, mainLog); err != nil {
		os.Exit(1)
	}
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
