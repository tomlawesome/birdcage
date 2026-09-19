package mailbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

const (
	// dialTimeout bounds the TCP connection and the TLS handshake, so an
	// IMAP server that accepts a connection and then says nothing
	// cannot hold birdcage's tick loop open.
	dialTimeout = 10 * time.Second
	// pollDeadline bounds the whole conversation after the connection
	// is up -- LOGIN, SELECT, SEARCH, every FETCH, every STORE and
	// LOGOUT together. The poll runs on the same 60s tick that starts
	// it, so a poll that outlasts its own interval is already going
	// wrong; cutting it here means the next tick starts clean rather
	// than two polls overlapping.
	pollDeadline = 60 * time.Second
	// maxMessagesPerPoll is how many matching messages one poll will
	// look at. A mailbox is attacker-reachable input: anyone who learns
	// the address can fill it. The rest are not lost, only deferred --
	// they are still unseen, so the next poll picks them up.
	maxMessagesPerPoll = 50
	// MaxMessageSize is the largest message this package will download.
	// It matches internal/agent/approval.MaxRawSize, deliberately:
	// fetching bytes the verifier would refuse to parse would be work
	// done for nothing. Anything larger is marked seen and skipped, so
	// one oversized message cannot block the mailbox forever.
	MaxMessageSize = 1 << 20
)

// subjectPrefix is the SEARCH narrowing. It is the opening of the
// reference token internal/agent/approval.Token writes, so the server
// does most of the filtering and birdcage downloads only what could
// plausibly be an approval. It is an optimisation and nothing more:
// every rule that decides whether a message is genuine runs on the
// bytes afterwards, and none of them trusts this having matched.
const subjectPrefix = "[birdcage "

// Handler is given the raw bytes of one message. Returning nil means
// birdcage has taken responsibility for it, and only then is the
// message marked \Seen; returning an error leaves it unseen so the next
// poll tries again. That ordering is the whole reason this package has
// a handler rather than returning a slice: a message that was fetched
// and then lost to a database failure must still be owed.
type Handler func(ctx context.Context, raw []byte) error

// Reader polls one IMAP mailbox. It holds no connection between polls:
// a long-lived IMAP session would have to deal with idle timeouts,
// server-side disconnects and reconnection, none of which buys anything
// at a 60-second interval.
type Reader struct {
	cfg Config
	log *slog.Logger

	// testRoots is the test-only injection point for the certificate
	// pool, the same seam internal/mail.Sender uses. Nil in production,
	// which means the system roots. There is no environment variable
	// that reaches it.
	testRoots *x509.CertPool
}

// New returns a Reader for cfg.
func New(cfg Config, log *slog.Logger) *Reader {
	return &Reader{cfg: cfg, log: log}
}

// tlsConfig is the one place this package decides what it will accept
// from an IMAP server. Two things are fixed and have no configuration
// knob at all: the certificate is verified against the system roots,
// and the server name is the host from BIRDCAGE_APPROVAL_IMAP_HOST.
// There is no InsecureSkipVerify here and no environment variable that
// reaches one -- this credential reads the mailbox that authorises
// upgrades, and quietly accepting any certificate would hand it to
// anything on the network path.
//
// MinVersion is TLS 1.2 rather than the TLS 1.3 floor birdcage sets on
// every listener of its own (internal/tlsconfig, internal/ingest), for
// the reason internal/mail/smtp.go gives: both ends of those
// connections are ours, so 1.3 costs nothing there. This connection's
// far end is whatever mail provider the operator already uses, and a
// good number of them still terminate IMAP at TLS 1.2. Refusing to
// speak to them would mean approvals never arriving, which is a worse
// outcome than a 1.2 handshake to a fully verified server.
func (r *Reader) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName: r.cfg.Hostname(),
		MinVersion: tls.VersionTLS12,
		RootCAs:    r.testRoots,
		// go-imap's own DialTLS sets this; an IMAP server that does not
		// speak ALPN simply negotiates nothing, so it costs nothing.
		NextProtos: []string{"imap"},
	}
}

// Poll runs one pass over the mailbox: connect, log in, select, find
// the unseen messages whose subject could carry a reference, fetch each
// one, hand it to handle, and mark it \Seen only once handle has
// returned without an error. It returns the number of messages handled.
//
// Everything is bounded. The whole conversation shares one deadline
// (pollDeadline); at most maxMessagesPerPoll messages are looked at;
// anything over MaxMessageSize is skipped without being downloaded.
//
// An error from handle stops the poll rather than moving on to the next
// message. Both plausible causes -- the database is unavailable, or
// shutdown has begun -- would apply just as much to the next message,
// and carrying on would mark nothing seen while doing the work anyway.
func (r *Reader) Poll(ctx context.Context, handle Handler) (int, error) {
	if handle == nil {
		return 0, errors.New("mailbox: Poll needs a handler")
	}
	conn, err := r.dial(ctx)
	if err != nil {
		return 0, err
	}
	if err := conn.SetDeadline(time.Now().Add(pollDeadline)); err != nil {
		_ = conn.Close()
		return 0, fmt.Errorf("mailbox: set deadline: %w", err)
	}

	// Closing the connection is what makes ctx cancellation (shutdown,
	// mostly) actually interrupt a conversation the IMAP client has no
	// way to abort: the in-flight read fails and the poll returns.
	// Double-closing is harmless. Same shape as internal/mail's
	// deliver.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	client := imapclient.New(conn, nil)
	// Logout is the clean way out and is worth attempting, but the
	// close is what actually frees the socket, so it runs either way.
	defer func() { _ = conn.Close() }()

	if err := client.Login(r.cfg.Username, r.cfg.Password).Wait(); err != nil {
		// The error text comes from the server. It never contains the
		// password -- the password is not echoed in an IMAP response --
		// but the username is named here by us rather than quoted from
		// the server, so the message reads the same whatever the server
		// says.
		return 0, fmt.Errorf("mailbox: log in to %s as %s: %w", r.cfg.Host, r.cfg.Username, err)
	}
	if _, err := client.Select(r.cfg.Mailbox, &imap.SelectOptions{ReadOnly: false}).Wait(); err != nil {
		return 0, fmt.Errorf("mailbox: select %q on %s: %w", r.cfg.Mailbox, r.cfg.Host, err)
	}

	uids, err := r.search(client)
	if err != nil {
		return 0, err
	}

	handled := 0
	for _, uid := range uids {
		ok, err := r.handleOne(ctx, client, uid, handle)
		if err != nil {
			return handled, err
		}
		if ok {
			handled++
		}
	}

	if err := client.Logout().Wait(); err != nil {
		// The work is already done and every handled message is already
		// marked seen, so a failed LOGOUT is worth a line but is not a
		// failed poll.
		r.log.Warn(fmt.Sprintf("log out of %s: %v", r.cfg.Host, err))
	}
	return handled, nil
}

// search asks the server for the unseen messages whose subject contains
// the reference token's opening, capped at maxMessagesPerPoll. UIDs
// rather than sequence numbers: a sequence number is only meaningful
// until something else is expunged from the mailbox, and another client
// (the administrator's own mail app) may well be looking at the same
// folder.
func (r *Reader) search(client *imapclient.Client) ([]imap.UID, error) {
	data, err := client.UIDSearch(&imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagSeen},
		Header:  []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: subjectPrefix}},
	}, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("mailbox: search %q on %s: %w", r.cfg.Mailbox, r.cfg.Host, err)
	}
	uids, ok := data.All.(imap.UIDSet)
	if !ok {
		// No matches at all: the server returned an empty set, which is
		// not a UIDSet.
		return nil, nil
	}
	nums, ok := uids.Nums()
	if !ok {
		return nil, fmt.Errorf("mailbox: search on %s returned an open-ended UID set", r.cfg.Host)
	}
	if len(nums) > maxMessagesPerPoll {
		r.log.Warn(fmt.Sprintf("%d unread approval replies in %s; handling %d this poll and the rest next time",
			len(nums), r.cfg.Mailbox, maxMessagesPerPoll))
		nums = nums[:maxMessagesPerPoll]
	}
	return nums, nil
}

// handleOne fetches one message and runs the handler on it. It reports
// whether the handler was given the message: an oversized one is marked
// seen and skipped without being downloaded, which is a successful poll
// but not a handled message.
func (r *Reader) handleOne(ctx context.Context, client *imapclient.Client, uid imap.UID, handle Handler) (bool, error) {
	set := imap.UIDSetNum(uid)

	// Size first, in its own round trip, so an oversized message is
	// never downloaded at all. Asking for the body and then stopping
	// partway would still have pulled the bytes across the wire.
	sizes, err := client.Fetch(set, &imap.FetchOptions{RFC822Size: true}).Collect()
	if err != nil {
		return false, fmt.Errorf("mailbox: fetch the size of message %v: %w", uid, err)
	}
	if len(sizes) == 0 {
		// Expunged between the search and now -- another client moved
		// or deleted it. Nothing to do and nothing wrong.
		return false, nil
	}
	if sizes[0].RFC822Size > MaxMessageSize {
		r.log.Warn(fmt.Sprintf("message %v in %s is %d bytes, over the %d-byte limit; marking it read and skipping it",
			uid, r.cfg.Mailbox, sizes[0].RFC822Size, MaxMessageSize))
		return false, r.markSeen(client, set, uid)
	}

	// BODY.PEEK[] rather than BODY[]: peeking does not set \Seen, so
	// this package decides when a message counts as read, and that
	// decision happens after the handler has returned.
	section := &imap.FetchItemBodySection{Peek: true}
	messages, err := client.Fetch(set, &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{section},
	}).Collect()
	if err != nil {
		return false, fmt.Errorf("mailbox: fetch message %v: %w", uid, err)
	}
	if len(messages) == 0 {
		return false, nil
	}
	raw := messages[0].FindBodySection(section)
	if len(raw) == 0 {
		r.log.Warn(fmt.Sprintf("message %v in %s came back empty; marking it read and skipping it", uid, r.cfg.Mailbox))
		return false, r.markSeen(client, set, uid)
	}
	// A server that reported one size and then sent more is either
	// broken or hostile; either way the limit is the limit.
	if len(raw) > MaxMessageSize {
		r.log.Warn(fmt.Sprintf("message %v in %s arrived larger than the %d-byte limit it declared; marking it read and skipping it",
			uid, r.cfg.Mailbox, MaxMessageSize))
		return false, r.markSeen(client, set, uid)
	}

	if err := handle(ctx, raw); err != nil {
		return false, fmt.Errorf("mailbox: handle message %v: %w", uid, err)
	}
	if err := r.markSeen(client, set, uid); err != nil {
		return false, err
	}
	return true, nil
}

// markSeen adds \Seen, which is this package's record that a message
// has been dealt with. It is the last thing that happens to a message,
// after the handler has returned without an error: a message marked
// seen before the handler ran would be lost if birdcage died in
// between.
func (r *Reader) markSeen(client *imapclient.Client, set imap.UIDSet, uid imap.UID) error {
	err := client.Store(set, &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Flags:  []imap.Flag{imap.FlagSeen},
		Silent: true,
	}, nil).Close()
	if err != nil {
		return fmt.Errorf("mailbox: mark message %v read: %w", uid, err)
	}
	return nil
}

// dial opens the transport: TLS from the first byte, always. There is
// no plaintext path and no STARTTLS path out of this function.
//
// tls.DialWithDialer rather than tls.Dial, and DialContext rather than
// Dial, only so the connection attempt is bounded and cancellable --
// tls.Dial uses the zero net.Dialer, which has no timeout at all.
func (r *Reader) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", r.cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("mailbox: connect to %s: %w", r.cfg.Host, err)
	}
	conn := tls.Client(rawConn, r.tlsConfig())
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("mailbox: TLS handshake with %s: %w", r.cfg.Host, err)
	}
	return conn, nil
}
