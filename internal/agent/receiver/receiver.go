package receiver

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/event"
)

// Path is the only route this listener serves. OpenCanary's WebhookHandler
// posts once per event and nothing else ever needs to reach this listener
// -- issue #48 rules out any command, control or status surface riding
// loopback -- so there is exactly one path and exactly one method (Method),
// checked directly in serveHTTP rather than through http.ServeMux: a mux
// adds behaviour this listener must not have, such as redirecting
// "/event/" to "/event".
const Path = "/event"

// Method is the only HTTP method Path accepts.
const Method = http.MethodPost

// Default cap and timeout values. See Config's fields for what each one
// defends against; these are the values New uses when a Config field is
// left at its zero value.
const (
	// DefaultMaxBodyBytes reuses internal/agent/event's cap on one webhook
	// body (event.MaxWebhookBodyBytes) rather than defining a second
	// number that could drift out of sync with it. That package computes
	// the event id from the same body this listener reads and enforces
	// the identical cap while doing it (event.IDFromWebhookBody); using
	// two different limits here and there would let this listener accept
	// a body that package then refuses, for no benefit.
	DefaultMaxBodyBytes = event.MaxWebhookBodyBytes

	// DefaultMaxHeaderBytes bounds the request line and headers, which are
	// attacker-controlled the same as the body (any local uid can set
	// them). Generous for a webhook POST that carries no meaningful
	// headers of its own.
	DefaultMaxHeaderBytes = 4 * 1024

	// DefaultMaxConnections bounds concurrent accepted TCP connections.
	// OpenCanary's logger runs every log() call on its single reactor
	// thread (issue #48, "Two events inside one microsecond"), so it never
	// holds more than one webhook connection open at a time; a small
	// multiple leaves headroom for TCP's own connection teardown overlap
	// without giving a local flood room to tie up file descriptors.
	DefaultMaxConnections = 8

	// DefaultReadHeaderTimeout bounds how long Accept-to-headers-read may
	// take, so a connection that opens and then sends nothing (or sends
	// one byte at a time) cannot hold a connection slot indefinitely.
	DefaultReadHeaderTimeout = 1 * time.Second

	// DefaultReadTimeout bounds the entire request read, headers through
	// body, for the same slow-loris reason as DefaultReadHeaderTimeout.
	DefaultReadTimeout = 1 * time.Second

	// DefaultWriteTimeout bounds how long writing the response may take.
	DefaultWriteTimeout = 1 * time.Second

	// DefaultIdleTimeout bounds how long an idle keep-alive connection is
	// held open between requests, so a client that opens a connection and
	// then never sends a second request doesn't hold a slot forever.
	DefaultIdleTimeout = 30 * time.Second

	// DefaultHandlerTimeout bounds how long Handler may run before
	// serveHTTP gives up waiting on it and responds. See Handler's doc
	// comment for why this exists and what happens when it fires.
	DefaultHandlerTimeout = 250 * time.Millisecond
)

// Handler receives one accepted, already-capped request body and reports
// whether the downstream that owns it accepted it. body is exactly what
// arrived on the wire -- not decoded, not validated, not hashed; per the
// package doc, this listener does not look inside it.
//
// Handler must return promptly. The design this listener serves (issue
// #48's memory-only, capped, drop-oldest send queue -- see
// internal/agent/queue's MemQueue.Push) is non-blocking by contract: a push
// either succeeds or evicts the oldest queued event to make room, but it
// never waits and never fails, so a well-behaved Handler built on it always
// returns quickly with a nil error. DefaultHandlerTimeout exists as a
// backstop against a Handler that violates that contract -- a bug, a lock
// held elsewhere, a future downstream that isn't actually non-blocking --
// not as a path this listener expects to take.
//
// If Handler has not returned within Config.HandlerTimeout, or returns a
// non-nil error, serveHTTP responds 503 without waiting further and closes
// the connection: the "never blocks OpenCanary" constraint applies exactly
// as much to a slow downstream as to a slow client, and OpenCanary treats
// any non-2xx response the same as a failed attempt. Either way the event
// is not lost -- it still reaches birdcage by the log road, since
// OpenCanary wrote it before the webhook fired (issue #48, "Loopback
// receive: oversized body, malformed JSON, slow or flooding local client ->
// rejected and counted; the connection is closed rather than waited on.
// The event still arrives by the log road"). Counting a downstream refusal
// is the caller's job, not this package's: Handler's own error carries
// whatever the caller wants recorded.
//
// A Handler call that times out is not cancelled -- Go has no way to
// preempt a running function -- so it keeps running in its own goroutine
// after serveHTTP has moved on. A Handler built on MemQueue.Push finishes
// in microseconds regardless, so this is bounded in practice by
// Config.MaxConnections, the same as any other in-flight request.
type Handler func(body []byte) error

// Config controls one Receiver's caps, timeouts and bind address. The zero
// value is valid for every numeric field except Addr: New fills any
// zero-valued cap or timeout field with its Default* constant, but Addr
// must always be supplied and must be a literal loopback address.
type Config struct {
	// Addr is the loopback address to listen on, for example
	// "127.0.0.1:8180". Use "127.0.0.1:0" for an OS-assigned port (tests
	// do this). Addr must name a literal loopback IP -- New refuses a
	// hostname (no DNS resolution is trusted to decide what "loopback"
	// means) and refuses any address that is not 127.0.0.0/8 or ::1,
	// enforcing issue #48's "listens on loopback only" inside this
	// package rather than trusting the caller to have gotten the address
	// right.
	Addr string

	MaxBodyBytes      int64
	MaxHeaderBytes    int
	MaxConnections    int
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	HandlerTimeout    time.Duration
}

func (c Config) withDefaults() Config {
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if c.MaxHeaderBytes <= 0 {
		c.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if c.MaxConnections <= 0 {
		c.MaxConnections = DefaultMaxConnections
	}
	if c.ReadHeaderTimeout <= 0 {
		c.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = DefaultReadTimeout
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = DefaultWriteTimeout
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.HandlerTimeout <= 0 {
		c.HandlerTimeout = DefaultHandlerTimeout
	}
	return c
}

// Receiver is the loopback listener. Construct one with New, then call
// Serve (blocking) from its own goroutine and Close when the agent shuts
// down.
type Receiver struct {
	cfg     Config
	handler Handler
	ln      *limitListener
	srv     *http.Server
}

// New binds Config.Addr and returns a Receiver ready to Serve. It does not
// start serving; call Serve for that. New returns an error without binding
// anything if handler is nil or Addr is not a literal loopback address.
func New(cfg Config, handler Handler) (*Receiver, error) {
	if handler == nil {
		return nil, errors.New("receiver: handler must not be nil")
	}
	cfg = cfg.withDefaults()

	if err := requireLoopback(cfg.Addr); err != nil {
		return nil, fmt.Errorf("receiver: %w", err)
	}

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("receiver: listen: %w", err)
	}
	// Defense in depth: re-check what was actually bound, not just what
	// was asked for, in case a future caller passes an address whose
	// literal-IP parse succeeds but whose bind behaves unexpectedly. This
	// is the same check requireLoopback already ran on cfg.Addr; running
	// it again on the live listener costs nothing and means "loopback
	// only" is enforced against reality, not intent.
	if err := requireLoopback(ln.Addr().String()); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("receiver: %w", err)
	}

	r := &Receiver{
		cfg:     cfg,
		handler: handler,
		ln:      newLimitListener(ln, cfg.MaxConnections),
	}
	r.srv = &http.Server{
		Handler:           http.HandlerFunc(r.serveHTTP),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
	return r, nil
}

// Addr is the bound address, including the OS-assigned port if Config.Addr
// asked for one. Safe to call any time after New returns.
func (r *Receiver) Addr() net.Addr {
	return r.ln.Addr()
}

// Serve blocks, accepting and handling requests until Close is called. It
// always returns a non-nil error: http.ErrServerClosed after a clean Close,
// or the error that made the listener unusable otherwise. Callers that
// treat a clean shutdown as success should check errors.Is(err,
// http.ErrServerClosed).
func (r *Receiver) Serve() error {
	return r.srv.Serve(r.ln)
}

// Close stops Serve and closes the listener and any open connections
// immediately. Issue #48 gives this listener nothing worth draining --
// every in-flight request either finishes within Config.HandlerTimeout or
// is already being abandoned by serveHTTP -- so Close does not wait for
// in-flight requests the way http.Server.Shutdown would.
func (r *Receiver) Close() error {
	return r.srv.Close()
}

// serveHTTP is the entire route table: reject anything that isn't exactly
// Method to exactly Path, cap and read the body, hand it to Handler within
// a bounded wait, and respond. See the package doc and Handler's doc
// comment for why each step is shaped this way.
func (r *Receiver) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != Path {
		http.NotFound(w, req)
		return
	}
	if req.Method != Method {
		w.Header().Set("Allow", Method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// http.MaxBytesReader enforces the cap while reading rather than after
	// -- a sender that never stops writing cannot force an unbounded
	// buffer, and one that merely exceeds the cap doesn't cost a full-size
	// allocation just to be rejected (net/http closes the connection once
	// the limit is crossed, which is the "connection is closed rather
	// than waited on" fail-closed behaviour issue #48 specifies).
	req.Body = http.MaxBytesReader(w, req.Body, r.cfg.MaxBodyBytes)
	body, err := io.ReadAll(req.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "event too large", http.StatusRequestEntityTooLarge)
			return
		}
		// Any other read error is a client that stalled past
		// ReadTimeout/ReadHeaderTimeout or disconnected mid-body -- the
		// "slow or flooding local client" case. Reject and stop; do not
		// wait for more bytes that may never arrive. The event still
		// reaches birdcage by the log road, since OpenCanary wrote it
		// before the webhook fired.
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Hand off to the caller and race it against HandlerTimeout, so a
	// downstream that cannot accept -- or simply takes too long -- can
	// never make this response, and therefore OpenCanary's one webhook
	// attempt, wait past a bound this package owns. See Handler's doc
	// comment for the full reasoning and what happens to the goroutine
	// when the timeout fires first.
	done := make(chan error, 1)
	go func() { done <- r.handler(body) }()

	timer := time.NewTimer(r.cfg.HandlerTimeout)
	defer timer.Stop()

	select {
	case err := <-done:
		if err != nil {
			http.Error(w, "not accepted", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	case <-timer.C:
		http.Error(w, "not accepted", http.StatusServiceUnavailable)
	}
}

// requireLoopback rejects anything that is not a literal loopback IP
// address with an explicit port. Hostnames are rejected outright: resolving
// one would mean trusting a resolver to decide what "loopback only" means,
// and issue #48's threat model treats every local uid as potentially
// hostile, which extends to whatever it can influence about name
// resolution.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address %q must be host:port: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("address %q binds all interfaces, not loopback only", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host %q must be a literal IP address, not a hostname", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("host %q is not a loopback address", host)
	}
	return nil
}

// limitListener wraps a net.Listener with a hard cap on concurrent accepted
// connections. A connection accepted over the cap is closed immediately
// rather than left in the OS accept backlog: queueing it would risk
// eventually delaying OpenCanary's own connection attempt, which is exactly
// the blocking issue #48 forbids, so a local flood is turned away instead
// of made to wait.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(ln net.Listener, max int) *limitListener {
	return &limitListener{Listener: ln, sem: make(chan struct{}, max)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.sem <- struct{}{}:
			return &limitConn{Conn: c, sem: l.sem}, nil
		default:
			_ = c.Close()
			// Surplus connection, rejected; loop to accept the next.
		}
	}
}

// limitConn releases its connection's semaphore slot exactly once, however
// many times Close is called -- net/http can call Close more than once on
// the same connection during error handling, and a second release would
// let two connections think they hold the same slot.
type limitConn struct {
	net.Conn
	sem  chan struct{}
	once sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.sem })
	return err
}
