// Package auth puts sign-in in front of birdcage's dashboard API, through
// the shared auth module gauntlet (ADR-0005, ADR-0016).
//
// Open builds the module's stores over birdcage's own database (accounts,
// API tokens and sign-in history, each sealed under the operator's key
// file), its HTTP gate, and the background work that goes with it. Wrap
// puts the gate in front of a handler. Close stops the work.
//
// Only the dashboard API needs a sign-in. The canary side (enrolment and
// ingest) runs on its own listeners and never passes through here.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/blocklist"
	"github.com/tomlawesome/gauntlet/gate"
	"github.com/tomlawesome/gauntlet/geoip"
	"github.com/tomlawesome/gauntlet/oidc"
	"github.com/tomlawesome/gauntlet/passkey"
	"github.com/tomlawesome/gauntlet/persist"

	"github.com/tomlawesome/birdcage/internal/api"
	"github.com/tomlawesome/birdcage/internal/authstore"
	"github.com/tomlawesome/birdcage/internal/db"
)

// sessionIdle is how long a session may sit unused before it ends
// (ADR-0016 decision 6). It is a variable only so tests can shorten it,
// through export_test.go.
var sessionIdle = gauntlet.MaxSessionIdle

const (
	// productName is the deployment's name in authenticator-app and
	// passkey prompts, and a word no password may be.
	productName = "birdcage"
	// cookieName is the session cookie. gauntlet adds the __Host- prefix
	// itself while SecureCookie is set.
	cookieName = "birdcage_session"
	// csrfValue is the X-Requested-With value the dashboard's API client
	// sends on every request that changes data.
	csrfValue = "birdcage"

	// loginFailures and loginWindow: failed sign-ins allowed per client
	// address and per account in the window before a 429 (docs/using.md).
	loginFailures = 5
	loginWindow   = time.Minute

	// sweepInterval is how often API tokens are swept (ADR-0016
	// decision 6): expired and orphaned ones are removed, and the owner
	// of one about to expire is told.
	sweepInterval = 24 * time.Hour

	// The three stores. Each name is both the auth_documents row and the
	// label the document is sealed under.
	storeAccounts = "accounts"
	storeTokens   = "tokens"
	storeSignIns  = "signins"
)

// Config is everything Open needs. Only Key is required.
type Config struct {
	// Key is the key material every store is sealed under: at least
	// persist.MinKeyBytes (32) bytes, read from BIRDCAGE_AUTH_KEY_FILE.
	Key []byte
	// PublicURL is the address people reach the dashboard on
	// (BIRDCAGE_PUBLIC_URL). Passkeys and SSO are wired from it; empty
	// leaves both off.
	PublicURL string
	// AdminPasskeyOverride is BIRDCAGE_AUTH_ADMIN_PASSKEY: "required",
	// "optional" or empty. See AdminPasskeyRule.
	AdminPasskeyOverride string
	// SecureCookie sets the session cookie's Secure attribute (and its
	// __Host- prefix): true whenever the dashboard serves TLS itself or
	// BIRDCAGE_PUBLIC_URL is https.
	SecureCookie bool
	// TrustedProxies are the peers a forwarding header is believed from
	// (BIRDCAGE_TRUSTED_PROXIES). Empty, the default, means headers are
	// ignored and the client is the connecting peer.
	TrustedProxies []netip.Prefix
	// TrustedHops are the entries skipped in the forwarding chain: explicit
	// BIRDCAGE_TRUSTED_PROXIES addresses and CIDRs, never the private
	// shorthand, so a shorthand covering whole client populations cannot be
	// used by a client to step over its own entry. See ProxyTrust.
	TrustedHops []netip.Prefix
	// TrustUnixSocket trusts a proxy connected over the dashboard's unix
	// socket (the entry "unix" in BIRDCAGE_TRUSTED_PROXIES). A unix peer has
	// no IP address, so no prefix can match it. See ClientIPWith.
	TrustUnixSocket bool
	// ClientIPHeader is the forwarding header read for a trusted peer;
	// empty means X-Forwarded-For. See ClientIPWith.
	ClientIPHeader string

	// DataDir is birdcage's data directory. The common-password list
	// refresher and the country data keep their files beneath it. Empty
	// turns the refresher off (the list built into gauntlet is used) and
	// is refused when a country provider is configured.
	DataDir string

	// Country lookup runs only when a provider is configured: an IPinfo
	// token, or a MaxMind account ID with its licence key. The values are
	// the secrets themselves, read from files by the caller and never
	// logged.
	IPinfoToken       string
	MaxMindAccountID  string
	MaxMindLicenceKey string

	// SSO runs only when OIDCIssuer is set; the client ID and secret go
	// with it (the secret read from a file by the caller).
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
}

// Service is the sign-in layer: the opened stores, the gate and the
// background loops.
type Service struct {
	gate    *gate.Gate
	signIns *gauntlet.SignInHistory
	geo     *geoip.Manager
	log     *slog.Logger

	cancel    context.CancelFunc
	loops     sync.WaitGroup
	closeOnce sync.Once
}

// Open builds the sign-in layer over database. When there is no account
// yet it logs the one-time setup code on log, and the emergency unlock
// code if one is due, in gauntlet's own words, but only once everything
// below has opened: an Open that fails logs no code. It refuses a short
// key, a key that cannot open the stored documents, and any setting
// gauntlet refuses.
//
// Background work starts only once everything has opened: a daily token
// sweep, the common-password list refresher when DataDir is set, and the
// country data refresh when a provider is configured. Close stops it.
func Open(ctx context.Context, database *db.DB, cfg Config, log *slog.Logger) (*Service, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if len(cfg.Key) < persist.MinKeyBytes {
		return nil, fmt.Errorf("auth: the sign-in key is %d bytes; it must be at least %d (BIRDCAGE_AUTH_KEY_FILE)", len(cfg.Key), persist.MinKeyBytes)
	}

	// Unwound if a later step fails, so a refused start leaves nothing running.
	var undo []func()
	fail := func(err error) (*Service, error) {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		return nil, err
	}

	seal := func(name string) (persist.Backend, error) {
		return persist.Encrypt(authstore.NewBackend(database, name), cfg.Key, persist.EncryptOptions{Label: name})
	}

	// Common-password list. The refresher fetches a signed update once a
	// day (docs/configuration.md); without a data directory to keep it in,
	// the list built into gauntlet is used and nothing is fetched.
	var refresher *blocklist.Refresher
	var passwordList gauntlet.PasswordList
	if cfg.DataDir != "" {
		r, err := blocklist.NewRefresher(blocklist.RefreshConfig{
			Dir: filepath.Join(cfg.DataDir, "passwords"),
			Log: log,
		})
		if err != nil {
			return fail(fmt.Errorf("auth: common-password list: %w", err))
		}
		refresher, passwordList = r, r
	}

	accountsDoc, err := seal(storeAccounts)
	if err != nil {
		return fail(fmt.Errorf("auth: seal accounts: %w", err))
	}
	// The setup and unlock codes are held until Open has fully succeeded
	// (below), so an operator never copies a code from a process that
	// then refused to start.
	codes := &heldCodes{log: log}
	users, err := gauntlet.OpenStore(accountsDoc, gauntlet.Options{
		Log:               log,
		ProductName:       productName,
		OnSetupCode:       gauntlet.SetupCodeFunc(codes.setup),
		OnUnlockCode:      gauntlet.UnlockCodeFunc(codes.unlock),
		PasswordBlocklist: passwordList, // nil: gauntlet's built-in list
		// BreachCheck stays nil: no Have I Been Pwned lookups (ADR-0016 decision 6).
	})
	if err != nil {
		return fail(fmt.Errorf("auth: open accounts: %w", err))
	}

	tokensDoc, err := seal(storeTokens)
	if err != nil {
		return fail(fmt.Errorf("auth: seal tokens: %w", err))
	}
	tokens, err := gauntlet.OpenTokenStore(tokensDoc, gauntlet.TokenOptions{
		Log: log,
		// Birdcage issues no ingest tokens: canaries keep their own credentials.
		Kinds: []gauntlet.TokenKind{gauntlet.TokenKindAPI},
	})
	if err != nil {
		return fail(fmt.Errorf("auth: open tokens: %w", err))
	}

	signInsDoc, err := seal(storeSignIns)
	if err != nil {
		return fail(fmt.Errorf("auth: seal sign-in history: %w", err))
	}
	signIns, err := gauntlet.OpenSignInHistory(signInsDoc, gauntlet.SignInHistoryOptions{Log: log})
	if err != nil {
		return fail(fmt.Errorf("auth: open sign-in history: %w", err))
	}
	undo = append(undo, func() { _ = signIns.Close() })

	limiter, err := gauntlet.NewLoginLimiter(loginFailures, loginWindow)
	if err != nil {
		return fail(fmt.Errorf("auth: login limiter: %w", err))
	}
	sessions := gauntlet.NewSessionStore(sessionIdle, gauntlet.MaxSessionLifetime)

	deps := gate.Deps{Users: users, Sessions: sessions, Tokens: tokens, Limiter: limiter, SignIns: signIns}

	// Passkeys are wired only when there is a public URL to anchor them to;
	// they work only where browsers can make them (an IP address or plain
	// http cannot), which is what the admin passkey rule asks about.
	passkeysWired := false
	if cfg.PublicURL != "" {
		rp, err := passkey.New(passkey.Config{PublicURL: cfg.PublicURL, DisplayName: productName})
		if err != nil {
			return fail(fmt.Errorf("auth: passkeys: %w", err))
		}
		deps.Passkeys = rp
		passkeysWired = rp.Status() == gauntlet.PasskeyStatusReady
	}
	rule, err := AdminPasskeyRule(cfg.PublicURL, passkeysWired, cfg.AdminPasskeyOverride)
	if err != nil {
		return fail(err)
	}

	// SSO, only when configured, and optional: a configuration mistake
	// refuses to start, but an identity provider that cannot be reached
	// leaves SSO off for this run rather than stopping the dashboard,
	// alerts and listeners with it. Password sign-in still works, and SSO
	// returns on the next start once the provider answers. Its redirect
	// address is built from the configured public URL, never from a request.
	if cfg.OIDCIssuer != "" {
		if cfg.PublicURL == "" {
			return fail(errors.New("auth: SSO needs BIRDCAGE_PUBLIC_URL, which its redirect address is built from"))
		}
		// Policy stays zero: SSO group roles are off (ADR-0016 decision 7).
		// A shared issuer with no tenant pin is a configuration mistake, so
		// it is checked here, before the network, and still refuses.
		policy := oidc.Policy{}
		if err := oidc.AllowIssuerWithPolicy(cfg.OIDCIssuer, policy); err != nil {
			return fail(fmt.Errorf("auth: SSO: %w", err))
		}
		client, err := oidc.New(ctx, oidc.Config{
			IssuerURL:    cfg.OIDCIssuer,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			RedirectURL:  trimSlash(cfg.PublicURL) + "/api/auth/oidc/callback",
			Policy:       policy,
		})
		if err != nil {
			log.Error(fmt.Sprintf("SSO is unavailable until the next start: %v", err))
		} else {
			state, err := oidc.NewStateCodec()
			if err != nil {
				return fail(fmt.Errorf("auth: SSO: %w", err))
			}
			deps.OIDC, deps.OIDCState = client, state
			log.Info(fmt.Sprintf("SSO on against %s", cfg.OIDCIssuer))
			if users.Count() > 0 && !users.HasLocalAdmin() {
				log.Warn("no admin has a local password, so SSO is the only way in; if the identity provider is down at start, sign-in needs a restart once it answers")
			}
		}
	}

	// Country, only when a provider is configured.
	var geo *geoip.Manager
	if gcfg, ok, err := geoConfig(cfg, log); err != nil {
		return fail(err)
	} else if ok {
		if geo, err = geoip.New(gcfg); err != nil {
			return fail(fmt.Errorf("auth: country data: %w", err))
		}
		undo = append(undo, func() { _ = geo.Close() })
	}

	gcfg := gate.Config{
		CookieName:      cookieName,
		SecureCookie:    cfg.SecureCookie,
		CSRFHeaderValue: csrfValue,
		ProductName:     productName,
		LoginPath:       "/",
		Log:             log,
		ClientIP: func(r *http.Request) string {
			return ClientIPWith(r, ProxyTrust{Peers: cfg.TrustedProxies, Hops: cfg.TrustedHops, Unix: cfg.TrustUnixSocket}, cfg.ClientIPHeader)
		},
		AdminPasskey: rule,
		Audit:        auditor{db: database, log: log},
		// PasskeySignIn stays off, and UnusualSignIns at gauntlet's default
		// (flag): ADR-0016 decisions 7 and 9.
	}
	if geo != nil {
		gcfg.Country = geo.Country
	}
	g, err := gate.New(gcfg, deps)
	if err != nil {
		return fail(fmt.Errorf("auth: %w", err))
	}

	loopCtx, cancel := context.WithCancel(ctx)
	s := &Service{gate: g, signIns: signIns, geo: geo, log: log, cancel: cancel}
	s.loop(func() { sweepTokens(loopCtx, g, log) })
	if refresher != nil {
		s.loop(func() { refresher.Run(loopCtx) })
	}
	if geo != nil {
		s.loop(func() { geo.Run(loopCtx) })
	}
	codes.release()
	return s, nil
}

// heldCodes keeps the one-time setup and unlock codes gauntlet announces
// while the accounts store opens, and writes them to the log only once
// Open has fully succeeded, in the words gauntlet's own default log line
// uses. If Open fails they are never written. After release, a code
// gauntlet announces later (it re-issues the setup code if a reload finds
// no accounts) is logged at once.
type heldCodes struct {
	log *slog.Logger

	mu       sync.Mutex
	released bool
	held     []func()
}

func (h *heldCodes) setup(code string) {
	h.announce(func() {
		h.log.Warn(fmt.Sprintf("no account exists yet -- create the first admin with setup code %s (valid until an account exists or this process restarts)", code))
	})
}

func (h *heldCodes) unlock(username, code string) {
	h.announce(func() {
		h.log.Warn(fmt.Sprintf("sign-in for the admin account %q is disabled after %d failed attempts in a row, and no other admin can unlock it -- "+
			"lift the disable with unlock code %s (valid until the account is unlocked or this process restarts; "+
			"the admin then signs in with their existing password and second factor). "+
			"Without it the disable lifts itself %s after it began",
			username, gauntlet.MaxConsecutiveLoginFailures, code, gauntlet.LoginDisableDuration))
	})
}

func (h *heldCodes) announce(write func()) {
	h.mu.Lock()
	if !h.released {
		h.held = append(h.held, write)
		h.mu.Unlock()
		return
	}
	h.mu.Unlock()
	write()
}

// release writes every held code, in the order announced, and lets later
// ones through.
func (h *heldCodes) release() {
	h.mu.Lock()
	h.released = true
	held := h.held
	h.held = nil
	h.mu.Unlock()
	for _, write := range held {
		write()
	}
}

// loop runs fn in the background until Close.
func (s *Service) loop(fn func()) {
	s.loops.Add(1)
	go func() {
		defer s.loops.Done()
		fn()
	}()
}

// Close stops the background work and saves the sign-in history. Safe to
// call more than once. It does not close the database.
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		s.cancel()
		s.loops.Wait()
		_ = s.geo.Close() // after Run has returned; a nil Manager is fine
		if err := s.signIns.Close(); err != nil {
			s.log.Warn(fmt.Sprintf("save sign-in history: %v", err))
		}
	})
}

// CountryLookupEnabled reports whether a country provider is configured,
// so country is recorded with each sign-in.
func (s *Service) CountryLookupEnabled() bool { return s.geo != nil }

// Wrap puts sign-in in front of dashboard, the dashboard API handler.
// Everything under /api/ needs a signed-in session, or a read API token
// as a bearer; gauntlet's own routes (/api/auth/ and /api/tokens) are
// served beside it. Everything outside /api/ -- the frontend, whose
// sign-in screen must load without a session -- passes straight to
// dashboard.
//
// A bearer token of kind api is answered by dashboard itself, so it
// reaches exactly the read-only dashboard routes and never gauntlet's
// account or token routes. Call Wrap once, before serving.
//
// Each request dashboard receives carries api.WithCredentialCheck: a
// function that asks again whether the request's credential is still
// valid, so a long-lived response (the event stream) can end after
// sign-out or a token revoke. The answer comes from gauntlet itself:
// the check calls (*gate.Gate).StillSignedIn, which applies every rule
// the gate applies at the door (session expiry, ended sessions, revoked
// or expired tokens, a forced password change) and so nothing is
// duplicated here. Unlike a request through the gate, it changes
// nothing: it does not extend the session's idle expiry, so an open
// stream idles its session out like any other client (#190).
func (s *Service) Wrap(dashboard http.Handler) http.Handler {
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		check := func() bool { return s.gate.StillSignedIn(r) == nil }
		dashboard.ServeHTTP(w, r.WithContext(api.WithCredentialCheck(r.Context(), check)))
	})
	s.gate.Handle(gauntlet.TokenKindAPI, guarded)

	routes := s.gate.Routes()
	inner := http.NewServeMux()
	inner.Handle("/api/auth/", routes)
	inner.Handle("/api/tokens", routes)
	inner.Handle("/api/tokens/", routes)
	inner.Handle("/api/", guarded)
	protected := s.gate.Protect(inner)

	outer := http.NewServeMux()
	outer.Handle("/api/", protected)
	outer.Handle("/", dashboard)
	return outer
}

// geoConfig builds the country-data settings, or reports false when no
// provider is configured.
func geoConfig(cfg Config, log *slog.Logger) (geoip.Config, bool, error) {
	gcfg := geoip.Config{Log: log}
	switch {
	case cfg.IPinfoToken != "" && (cfg.MaxMindAccountID != "" || cfg.MaxMindLicenceKey != ""):
		return geoip.Config{}, false, errors.New("auth: configure one country provider, IPinfo or MaxMind, not both")
	case cfg.IPinfoToken != "":
		gcfg.Source = geoip.SourceIPinfo
		gcfg.IPinfo = geoip.IPinfoKey{Token: cfg.IPinfoToken}
	case cfg.MaxMindAccountID != "" || cfg.MaxMindLicenceKey != "":
		gcfg.Source = geoip.SourceMaxMind
		gcfg.MaxMind = geoip.MaxMindKey{AccountID: cfg.MaxMindAccountID, LicenceKey: cfg.MaxMindLicenceKey}
	default:
		return geoip.Config{}, false, nil
	}
	if cfg.DataDir == "" {
		return geoip.Config{}, false, errors.New("auth: country data needs a data directory to keep its file in")
	}
	// Provider data, downloaded again on demand: kept out of backups.
	gcfg.Dir = filepath.Join(cfg.DataDir, "geoip")
	return gcfg, true, nil
}

// sweepTokens runs the token maintenance pass at once and then daily,
// until ctx ends.
func sweepTokens(ctx context.Context, g *gate.Gate, log *slog.Logger) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		res, err := g.SweepTokens(ctx, time.Now())
		switch {
		case err != nil && ctx.Err() == nil:
			log.Warn(fmt.Sprintf("sweep API tokens: %v", err))
		case res.Removed+res.Warned+res.Orphaned > 0:
			log.Info(fmt.Sprintf("swept API tokens: %d removed, %d warned of expiry, %d orphaned", res.Removed, res.Warned, res.Orphaned))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
