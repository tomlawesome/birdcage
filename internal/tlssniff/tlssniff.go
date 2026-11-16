// Package tlssniff lets a TLS listener answer a plain http:// visit with a
// redirect to https instead of a handshake error.
//
// It peeks at the first byte of each connection: 0x16 (a TLS handshake
// record) passes through to the TLS server with the byte replayed; anything
// else is read as one bounded HTTP request, answered with 308 to https on a
// host the certificate covers (or a bare 400) and closed. Nothing else is
// ever served over plain HTTP. A host check stops the redirect sending a
// browser somewhere an attacker chose; the size, time and concurrency limits
// stop an unidentified client holding resources.
package tlssniff

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SniffTimeout bounds how long a connection may take to send its first byte
// and, if plain HTTP, its whole request head.
var SniffTimeout = 10 * time.Second

// MaxConcurrentSniffs caps connections waiting to be identified; past it a
// new connection is closed. Read when Listener is called.
var MaxConcurrentSniffs = 256

// maxRequestBytes bounds a plain request's line and headers together.
const maxRequestBytes = 8 << 10

// tlsHandshake is the record type byte every TLS ClientHello starts with.
const tlsHandshake = 0x16

// HostAllower is given a plain request's Host header (possibly with a port)
// and returns the bare host name to redirect to, or "" to refuse.
type HostAllower func(requestHost string) string

// Listener wraps inner. Accept returns only connections that started a TLS
// handshake; plain HTTP is answered and closed inside the package.
func Listener(inner net.Listener, log *slog.Logger, allow HostAllower) net.Listener {
	port := ""
	if _, p, err := net.SplitHostPort(inner.Addr().String()); err == nil {
		port = p
	}
	l := &listener{
		Listener: inner,
		log:      log,
		allow:    allow,
		port:     port,
		sem:      make(chan struct{}, max(MaxConcurrentSniffs, 1)),
		timeout:  SniffTimeout,
		conns:    make(chan net.Conn),
		done:     make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

type listener struct {
	net.Listener
	log     *slog.Logger
	allow   HostAllower
	port    string
	sem     chan struct{}
	timeout time.Duration

	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error // the inner listener's permanent Accept error
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		l.errMu.Lock()
		defer l.errMu.Unlock()
		if l.err != nil {
			return nil, l.err
		}
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

// acceptLoop accepts from the inner listener, retrying temporary errors with
// the same backoff net/http's Server.Serve uses (5ms doubling to 1s).
func (l *listener) acceptLoop() {
	var delay time.Duration
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			var ne interface{ Temporary() bool }
			if errors.As(err, &ne) && ne.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay = min(delay*2, time.Second)
				}
				l.log.Warn(fmt.Sprintf("tlssniff: accept error: %v; retrying in %v", err, delay))
				select {
				case <-time.After(delay):
					continue
				case <-l.done:
					return
				}
			}
			l.errMu.Lock()
			l.err = err
			l.errMu.Unlock()
			l.closeOnce.Do(func() { close(l.done) })
			return
		}
		delay = 0
		select {
		case l.sem <- struct{}{}:
			go l.sniff(c)
		default:
			l.log.Debug(fmt.Sprintf("tlssniff: %d connections already waiting to be identified, closing %s", cap(l.sem), c.RemoteAddr()))
			_ = c.Close()
		}
	}
}

func (l *listener) sniff(c net.Conn) {
	release := func() { <-l.sem }
	_ = c.SetDeadline(time.Now().Add(l.timeout))
	var first [1]byte
	if _, err := io.ReadFull(c, first[:]); err != nil {
		release()
		_ = c.Close()
		return
	}
	if first[0] == tlsHandshake {
		_ = c.SetDeadline(time.Time{})
		release()
		select {
		case l.conns <- &replayConn{Conn: c, first: first[0], pending: true}:
		case <-l.done:
			_ = c.Close()
		}
		return
	}
	defer release()
	defer c.Close()
	l.answerPlain(c, first[0])
}

// answerPlain reads one request head and writes a redirect or a 400. A
// request that is malformed, oversized or too slow gets no answer at all.
func (l *listener) answerPlain(c net.Conn, first byte) {
	r := io.MultiReader(bytes.NewReader([]byte{first}), io.LimitReader(c, maxRequestBytes-1))
	req, err := http.ReadRequest(bufio.NewReaderSize(r, maxRequestBytes))
	if err != nil {
		l.log.Debug(fmt.Sprintf("tlssniff: unreadable plain request from %s: %v", c.RemoteAddr(), err))
		return
	}
	name := ""
	if req.Host != "" {
		name = l.allow(req.Host)
	}
	if name == "" || l.port == "" || strings.ContainsAny(name, "\r\n/ ") {
		l.log.Debug(fmt.Sprintf("tlssniff: plain request from %s for host %q refused", c.RemoteAddr(), req.Host))
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	path := req.URL.RequestURI()
	if !strings.HasPrefix(path, "/") {
		path = "/"
	}
	loc := "https://" + net.JoinHostPort(name, l.port) + path
	_, _ = io.WriteString(c, "HTTP/1.1 308 Permanent Redirect\r\nLocation: "+loc+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

// replayConn returns the sniffed byte before reading from the connection.
type replayConn struct {
	net.Conn
	mu      sync.Mutex
	first   byte
	pending bool
}

func (c *replayConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.pending && len(p) > 0 {
		p[0] = c.first
		c.pending = false
		c.mu.Unlock()
		return 1, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}
