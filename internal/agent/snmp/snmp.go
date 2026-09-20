// Package snmp is a UDP listener that reads SNMP v1/v2c requests aimed
// at the canary, logs the community string and the OIDs asked for, and
// never answers (issue #88).
//
// # Why this is here rather than in OpenCanary
//
// OpenCanary ships its own snmp module (opencanary/modules/snmp.py),
// and it stays disabled (build/mockingbird/opencanary.conf,
// "snmp.enabled": false). That module decodes SNMP with scapy, and #85
// already ruled scapy out of the Mockingbird image's dependency closure
// -- the same reasoning #86's llmnr decision applied. An SNMP v1/v2c
// request is a small ASN.1 BER structure; reading a community string
// and a list of OIDs out of it is a modest amount of Go against the
// standard library, against adding a large packet-crafting library to
// the one container built to be attacked.
//
// # What it reads
//
// parse.go hand-decodes exactly the shape a v1/v2c request has: a
// SEQUENCE carrying a version, a community string and a PDU, and the
// PDU's own varbind list names the OIDs asked for. SNMPv3 -- a
// different message format with no plaintext community string -- is
// out of scope and dropped, the same as anything else that fails to
// parse.
//
// Every bound in parse.go exists because this is a parser for bytes
// arriving on a port the whole point of this service is to invite
// strangers to attack: a length field in the packet is checked against
// the data actually in hand before anything is sliced from it, never
// trusted to size an allocation (there are none on the parse path --
// every value extracted is a sub-slice of the datagram already in
// memory), and the number of OIDs one message can contribute is capped
// the same way portscan caps how many ports one event lists.
//
// # What separates a hit from a monitoring poll
//
// Nothing in this package -- it logs every parseable request the same
// way. The community string is what lets an operator, or #46's
// self-test, tell a monitoring system's configured community from an
// attacker's guess; that judgement belongs downstream, on the
// dashboard, not here.
//
// # What it emits
//
// One event per parseable request, in OpenCanary's own JSON shape with
// logtype 13001 (LOG_SNMP_CMD), which internal/opencanary already maps
// to the service name "snmp". Like portscan's road, it goes into the
// agent's queue directly rather than through OpenCanary's log file,
// with an id minted the same way -- SHA-256 of the emitted bytes,
// verbatim -- and gets no ledger entry, for the same reason: the
// acknowledged-position ledger tracks positions in OpenCanary's log
// file, and this event was never in it.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// DefaultListenAddr is the standard SNMP port, on every interface --
// matching upstream's own default (opencanary/modules/snmp.py:
// snmp.port defaults to 161) so an operator who has not overridden
// anything sees the same port either way. Binding it needs no special
// capability: build/mockingbird/Dockerfile's
// net.ipv4.ip_unprivileged_port_start=0 sysctl already lowers the whole
// container's privileged-port floor to zero for OpenCanary's own low
// ports, and that applies to every process in the container's network
// namespace, this agent included.
const DefaultListenAddr = ":161"

// maxDatagramLen bounds one read from the UDP socket. Real SNMP v1/v2c
// requests -- a handful of small OIDs and a short community string --
// are well under a kilobyte; this covers that many times over while
// keeping one hostile datagram from costing an unbounded read. A
// datagram larger than this is truncated by the kernel the same way any
// over-large UDP read is, so the length fields BER parsing checks below
// then see less data than they claim -- the malformed case, dropped,
// never trusted into an allocation.
const maxDatagramLen = 8192

// readDeadline bounds one read so Run can notice ctx being cancelled
// even with nothing arriving. Short enough that shutdown is prompt,
// long enough that it costs nothing on an idle port.
const readDeadline = time.Second

// Submit is how a parsed SNMP request leaves this package: the caller
// is handed the exact bytes to hash and queue, and decides what to do
// with them. Mirrors portscan.Submit.
type Submit func(message []byte) error

// Config is everything the detector needs. Every field has a working
// default, so cmd/mockingbird sets only what its environment overrides.
type Config struct {
	// ListenAddr is where the UDP socket binds. Empty means
	// DefaultListenAddr.
	ListenAddr string

	// ConfPath is OpenCanary's configuration file, read once at startup
	// for the node id only -- see opencanaryconf.go. Empty means
	// DefaultConfPath.
	ConfPath string

	// Now is injected by the tests. Nil means time.Now.
	Now func() time.Time
}

// Detector listens for SNMP requests until its context is cancelled. It
// never replies: Run only ever reads from conn, and nothing in this
// package calls WriteTo, WriteToUDP or anything else that would put a
// byte back on the wire.
type Detector struct {
	cfg    Config
	log    *slog.Logger
	submit Submit
	nodeID string
	now    func() time.Time
	logged atomic.Uint64

	// conn is opened by Open and read by Run, split the same way
	// portscan splits Open from Run: a caller learns at startup whether
	// the port bound -- most likely failure is the port being
	// privileged, see DefaultListenAddr's comment -- rather than
	// whenever the Run goroutine happens to be scheduled.
	conn *net.UDPConn
}

// New builds a Detector: it reads OpenCanary's configuration for the
// node id and prepares the detector's state. It opens no socket -- Run
// does that, so a caller can construct the detector during startup and
// start it alongside every other long-lived goroutine.
//
// An unreadable or unparseable configuration file is not fatal, for the
// same reason portscan.New treats one that way: the detector falls back
// to DefaultNodeID, and the caller is told why through the returned
// warning string rather than an error, because the caller must carry
// on regardless.
func New(cfg Config, submit Submit, log *slog.Logger) (*Detector, string) {
	confPath := cfg.ConfPath
	if confPath == "" {
		confPath = DefaultConfPath
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	nodeID, err := readNodeID(confPath)
	var warning string
	if err != nil {
		nodeID = DefaultNodeID
		warning = fmt.Sprintf("OpenCanary configuration unreadable, using the fallback node id: %v", err)
	}

	return &Detector{
		cfg:    cfg,
		log:    log,
		submit: submit,
		nodeID: nodeID,
		now:    now,
	}, warning
}

// Logged is the number of SNMP requests emitted as events since start.
// Read for the agent's own accounting; not a heartbeat field yet, the
// same caveat portscan.Detected carries.
func (d *Detector) Logged() uint64 { return d.logged.Load() }

// Open binds the UDP socket. Separate from Run so a failure to bind is
// reported to the caller's startup log rather than discovered inside a
// background goroutine -- the same contract portscan.Open states.
//
// A non-nil error here means SNMP detection is off for this run. It is
// never a reason for the caller to exit.
func (d *Detector) Open() error {
	addr := d.cfg.ListenAddr
	if addr == "" {
		addr = DefaultListenAddr
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve snmp listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	d.conn = conn
	return nil
}

// Run reads datagrams from the socket Open returned until ctx is
// cancelled, then closes it. Calling Run without a successful Open is a
// programming error, reported rather than papered over -- the same
// contract portscan.Run states, for the same reason.
func (d *Detector) Run(ctx context.Context) error {
	if d.conn == nil {
		return errors.New("snmp: Run called before a successful Open")
	}
	defer func() { _ = d.conn.Close() }()

	// One buffer for the life of the loop, reused per datagram: nothing
	// this package extracts from it outlives the call that reads it
	// (encode copies what it needs into the wire event), so reuse costs
	// nothing and keeps a flood of datagrams from allocating one buffer
	// each.
	buf := make([]byte, maxDatagramLen)
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := d.conn.SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			return fmt.Errorf("set snmp read deadline: %w", err)
		}
		n, src, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read snmp socket: %w", err)
		}
		d.handle(buf[:n], src)
	}
}

// handle runs one captured datagram through the parser, emitting at
// most one event.
func (d *Detector) handle(b []byte, src *net.UDPAddr) {
	community, oids, err := parseMessage(b)
	if err != nil {
		// Malformed, truncated, wrongly typed, an unsupported version,
		// or simply not SNMP: dropped quietly, exactly as
		// portscan.handle drops an uninteresting packet -- a log line
		// per bad datagram, on a port this service exists to be
		// attacked on, would itself be the denial of service.
		return
	}
	d.emit(community, oids, src)
}

// emit encodes one parsed request and hands it to the submit callback.
func (d *Detector) emit(community string, oids []string, src *net.UDPAddr) {
	var dstHost string
	var dstPort int
	// local is this socket's own bound address -- matching upstream's
	// own dst_host/dst_port, which OpenCanary's CanaryService.log fills
	// from transport.getHost() (the transport's local endpoint), never
	// from anything per-packet. See internal/opencanary's package
	// comment for the wire-shape contract this mirrors. d.conn is nil
	// in tests that call handle directly without Open; that is not a
	// programming error worth panicking over, just an event with an
	// empty dst_host.
	if d.conn != nil {
		if local, ok := d.conn.LocalAddr().(*net.UDPAddr); ok {
			dstHost, dstPort = local.IP.String(), local.Port
		}
	}

	message, err := encode(detection{
		Src:       src.IP.String(),
		SrcPort:   src.Port,
		Dst:       dstHost,
		DstPort:   dstPort,
		Community: community,
		OIDs:      oids,
	}, d.nodeID, d.now())
	if err != nil {
		d.log.Warn(fmt.Sprintf("could not encode an snmp request: %v", err))
		return
	}
	if err := d.submit(message); err != nil {
		d.log.Warn(fmt.Sprintf("could not queue an snmp request: %v", err))
		return
	}
	d.logged.Add(1)
	// The source address is already in the event on its way to
	// birdcage, so naming it here tells an attacker reading this box's
	// stdout nothing new -- they are the source. The community string
	// and the OIDs are left out: those are what the event itself is
	// for, and the community string in particular is what tells an
	// operator's monitoring poll from an attacker's guess (see this
	// package's doc comment) -- not something to also spray across
	// stdout.
	d.log.Warn(fmt.Sprintf("snmp request from %s (%d OIDs)", src.IP, len(oids)))
}
