// Package portscan detects port scans against the canary itself, from
// inside the Mockingbird container's own network namespace, and emits
// them as ordinary OpenCanary events (issue #65).
//
// # Why this is here rather than in OpenCanary
//
// OpenCanary ships a portscan module, and it stays disabled
// (build/mockingbird/opencanary.conf, "portscan.enabled": false). It
// works by watching /var/log/kern.log for iptables LOG lines, which
// means iptables-legacy rules and a root process to install them --
// both of which the Mockingbird image deliberately does not have
// (ADR-0008: distroless, no shell, uid 65532, nothing ever root). The
// owner settled this on 2026-09-19: the agent watches for scans itself.
//
// # How it watches
//
// One AF_PACKET socket in the container's own network namespace, with a
// classic BPF filter attached before it starts receiving. The filter --
// not userspace -- is the flood defence: a SYN flood against this box is
// the expected case, not the exceptional one, and the kernel dropping
// everything that is not a bare TCP SYN or a UDP datagram is what keeps
// a flood from costing a syscall and a scheduler wakeup per packet. The
// filter is in from the first commit for that reason, not as an
// optimisation to add later.
//
// The only privilege this needs is CAP_NET_RAW, granted as a file
// capability on the binary (build/mockingbird/Dockerfile) and as
// --cap-add NET_RAW on the container. It is not root and does not lead
// to root: CAP_NET_RAW permits opening raw and packet sockets, nothing
// else, and the socket is read-only in practice -- this package never
// sends. What it can see is every frame arriving on the container's own
// interfaces; what it cannot see is any other container, the host, or
// anything off that segment. Without the capability the socket call
// returns EPERM, which is logged once and detection stays off; the
// honeypot itself is unaffected.
//
// # What counts as a scan
//
// A connection attempt to a port none of OpenCanary's enabled modules
// is listening on. The listening set is read from OpenCanary's own
// configuration file at startup, so an operator who bind-mounts their
// own opencanary.conf changes both at once. Five distinct such ports
// from one source inside thirty seconds is a scan; while it continues,
// at most one further event per source per minute. Nothing is emitted
// per packet.
//
// # What it emits
//
// One event per detection, in OpenCanary's own JSON shape with
// logtype 5001 (LOG_PORT_SYN), which internal/opencanary already maps
// to the service name "portscan". It goes into the agent's queue by a
// third road alongside the webhook receiver and the log tailer, with an
// id minted the same way -- SHA-256 of the emitted bytes, verbatim. Like
// the webhook road, and unlike the log road, it gets no ledger entry:
// the acknowledged-position ledger tracks positions in OpenCanary's log
// file, and this event was never in that file.
package portscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// captureBufferLen bounds one read from the capture socket. An IPv4
// header plus options is at most 60 bytes and a TCP or UDP header at
// most 60 more; everything past that is payload this package never
// looks at, and the kernel truncates its copy to whatever the buffer
// holds. 256 bytes covers both headers several times over, and the
// buffer is allocated once and reused for the life of the loop.
const captureBufferLen = 256

// errReadTimeout is what a capture socket returns when a read waited out
// its timeout without a packet arriving. Not a failure: it is how the
// capture loop gets a chance to notice the agent is shutting down.
var errReadTimeout = errors.New("portscan: capture read timed out")

// Submit is how a detected scan leaves this package: the caller is
// handed the exact bytes to hash and queue, and decides what to do with
// them. An error is logged by the caller and the detector carries on --
// a rejected event must never stop the loop that is watching for the
// next one.
type Submit func(message []byte) error

// Config is everything the detector needs. Every field has a working
// default, so cmd/mockingbird sets only what its environment overrides.
type Config struct {
	// ConfPath is OpenCanary's configuration file, read once at startup
	// for the listening-port set and the node id. Empty means
	// DefaultConfPath.
	ConfPath string

	// ExtraIgnorePorts are treated as listening in addition to whatever
	// the configuration names -- the agent's own loopback receiver port,
	// and MOCKINGBIRD_PORTSCAN_IGNORE_PORTS.
	ExtraIgnorePorts []uint16

	// Threshold, Window, Cooldown and MaxSources are the tracker's
	// tunables; see tracker.go for what each one means and why it has
	// the value it has. Zero takes the default.
	Threshold  int
	Window     time.Duration
	Cooldown   time.Duration
	MaxSources int

	// Now is injected by the tests. Nil means time.Now.
	Now func() time.Time
}

// Detector watches for scans until its context is cancelled.
type Detector struct {
	cfg      Config
	log      *slog.Logger
	submit   Submit
	nodeID   string
	ignore   map[uint16]struct{}
	now      func() time.Time
	tracker  *tracker
	detected atomic.Uint64

	// sock is opened by Open and read by Run. Split in two so the caller
	// learns at startup whether detection is available -- the whole
	// point of the "log one WARN and keep running" behaviour is that the
	// operator is told at boot, not whenever the goroutine happens to
	// get scheduled.
	sock *captureSocket
}

// New builds a Detector: it reads OpenCanary's configuration for the
// listening-port set and the node id, and prepares the sliding window.
// It opens no socket -- Run does that, so a caller can construct the
// detector during startup and start it alongside every other long-lived
// goroutine.
//
// An unreadable or unparseable configuration file is not fatal. The
// detector falls back to DefaultNodeID and to whatever ports the caller
// passed in ExtraIgnorePorts, and says so through the returned warning
// -- which is a string rather than an error precisely because the caller
// must carry on. Refusing to detect scans because a config file moved
// would be the wrong trade on a box whose job is to notice being
// scanned; the cost of carrying on is some false positives against
// OpenCanary's own listening ports, which is the noisy direction rather
// than the silent one.
func New(cfg Config, submit Submit, log *slog.Logger) (*Detector, string) {
	confPath := cfg.ConfPath
	if confPath == "" {
		confPath = DefaultConfPath
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	var warning string
	conf, err := readOpenCanaryConf(confPath)
	if err != nil {
		warning = fmt.Sprintf("OpenCanary configuration unreadable, treating every port as non-listening: %v", err)
	}

	ignore := make(map[uint16]struct{}, len(conf.Ports)+len(cfg.ExtraIgnorePorts))
	for p := range conf.Ports {
		ignore[p] = struct{}{}
	}
	for _, p := range cfg.ExtraIgnorePorts {
		ignore[p] = struct{}{}
	}

	return &Detector{
		cfg:    cfg,
		log:    log,
		submit: submit,
		nodeID: conf.NodeID,
		ignore: ignore,
		now:    now,
		tracker: newTracker(trackerConfig{
			Threshold:  cfg.Threshold,
			Window:     cfg.Window,
			Cooldown:   cfg.Cooldown,
			MaxSources: cfg.MaxSources,
			Now:        now,
		}),
	}, warning
}

// ListeningPorts is the set of ports the detector treats as ours, and so
// never counts towards a scan. Exposed for the startup log line, which
// reports how many there are -- never which, since this agent runs on
// the one machine an attacker gets to read stdout from (cmd/mockingbird's
// package doc), and a list of the ports it does not alert on is a map of
// where to look.
func (d *Detector) ListeningPorts() int { return len(d.ignore) }

// Detected is the number of scan events emitted since start. Read for
// the agent's own accounting; not a heartbeat field (that belongs to
// #45/#47).
func (d *Detector) Detected() uint64 { return d.detected.Load() }

// Open opens the capture socket and attaches the filter, and is the call
// that needs CAP_NET_RAW. Separate from Run so the caller learns at
// startup whether detection is available: the contract is one clear WARN
// at boot and a process that keeps running (issue #65), and a failure
// discovered inside a background goroutine would arrive whenever that
// goroutine happened to be scheduled rather than beside the rest of the
// startup log.
//
// A non-nil error here means detection is off for this run. It is never
// a reason for the caller to exit.
func (d *Detector) Open() error {
	sock, err := openCapture()
	if err != nil {
		return err
	}
	d.sock = sock
	return nil
}

// Run watches the socket Open returned until ctx is cancelled, then
// closes it. Calling Run without a successful Open is a programming
// error, reported rather than papered over with a second open attempt --
// the caller that skipped Open is the caller that never logged why
// detection was unavailable.
func (d *Detector) Run(ctx context.Context) error {
	if d.sock == nil {
		return errors.New("portscan: Run called before a successful Open")
	}
	defer func() { _ = d.sock.Close() }()

	// One buffer for the life of the loop. parseIPv4 copies out the four
	// values it needs and retains nothing, so reuse is safe and a
	// per-packet allocation on the flood path is avoided.
	buf := make([]byte, captureBufferLen)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, inbound, err := d.sock.Read(buf)
		switch {
		case errors.Is(err, errReadTimeout):
			continue
		case err != nil:
			// A read error that is not a timeout means the socket is
			// gone. Returning lets the caller decide; it does not stop
			// the agent.
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read capture socket: %w", err)
		}
		if !inbound {
			// This agent's own outbound traffic, seen on the way past.
			continue
		}
		d.handle(buf[:n])
	}
}

// handle runs one captured packet through the parser, the listening-port
// test and the sliding window, emitting at most one event.
func (d *Detector) handle(b []byte) {
	p, err := parseIPv4(b)
	if err != nil {
		// Both errNotOfInterest and errMalformed end here. Neither is
		// logged: on a box built to be flooded, a log line per
		// uninteresting packet is itself the denial of service.
		return
	}
	if _, listening := d.ignore[p.DstPort]; listening {
		return
	}
	det, ok := d.tracker.Observe(p)
	if !ok {
		return
	}
	d.emit(det)
}

// emit encodes one detection and hands it to the submit callback.
func (d *Detector) emit(det detection) {
	message, err := encode(det, d.nodeID, d.now())
	if err != nil {
		d.log.Warn(fmt.Sprintf("could not encode a detected scan: %v", err))
		return
	}
	if err := d.submit(message); err != nil {
		d.log.Warn(fmt.Sprintf("could not queue a detected scan: %v", err))
		return
	}
	d.detected.Add(1)
	// The source address is in the event that just went to birdcage, so
	// naming it here tells an attacker reading this box's stdout nothing
	// they did not already know -- they are the source. The ports are
	// left out: those are what the event is for.
	d.log.Warn(fmt.Sprintf("port scan from %s (%s, %d ports)", det.Src, det.Protocol, len(det.Ports)))
}
