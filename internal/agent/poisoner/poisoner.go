package poisoner

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Submit is how a caught poisoner leaves this package: the caller is handed
// the exact bytes to hash and queue, and decides what to do with them.
// Mirrors portscan.Submit and snmp.Submit.
type Submit func(message []byte) error

// Config is everything the detector needs. Every field has a working
// default, so cmd/mockingbird sets only what its environment overrides.
type Config struct {
	// Profile is the canary's segment profile. Empty means DefaultProfile.
	Profile Profile

	// OperatorNames are the bait names the operator supplied at enrolment,
	// already parsed by ParseNames. Empty means derive them from the
	// canary's own hostname.
	OperatorNames Names

	// Pace holds the floor, the ceiling and the working hours. A zero
	// value means DefaultPaceSettings.
	Pace PaceSettings

	// ConfPath is OpenCanary's configuration file, read once at startup
	// for the node id -- which attributes the events and seeds this
	// canary's rhythm. Empty means DefaultConfPath.
	ConfPath string

	// Hostname is what the neighbour names are derived from. Empty means
	// os.Hostname.
	Hostname string

	// ARPPath is the kernel neighbour table a hit's MAC is read from.
	// Empty means DefaultARPPath. A parameter only so a test can point it
	// at a fixture.
	ARPPath string

	// Now is injected by the tests. Nil means time.Now.
	Now func() time.Time
}

// Detector asks the segment for names nobody should answer, listens for
// anything that does, and counts the segment's own queries so it can match
// their pace. It never answers a query: see this package's comment on how
// that is the kernel's guarantee rather than this code's.
type Detector struct {
	cfg      Config
	log      *slog.Logger
	submit   Submit
	nodeID   string
	now      func() time.Time
	profile  Profile
	shape    Shape
	names    Names
	pace     PaceSettings
	schedule *Schedule
	counter  *paceCounter
	arpPath  string

	// rand draws the transaction ids. Separate from schedule's stream so
	// that how many questions a burst sends cannot shift the rhythm, and
	// seeded from the same node id so a test can reproduce a run.
	randMu sync.Mutex
	rand   *rand.Rand

	// listeners are the receive-only counting sockets, opened by Open.
	listeners []listener

	// segment is the interface to ask on, found by Open. Zero when there
	// is none, which turns sending off and leaves counting running.
	segment    segment
	canSend    bool
	bursts     atomic.Uint64
	lookups    atomic.Uint64
	answers    atomic.Uint64
	submitFail atomic.Uint64
}

// listener is one receive-only socket, with the port it is counting for.
type listener struct {
	proto Protocol
	port  int
	conn  *net.UDPConn
}

// New builds a Detector: it reads OpenCanary's configuration for the node
// id, settles the profile, the names and the pacing settings, and prepares
// the counters. It opens no socket -- Open does that -- so a caller can
// construct the detector during startup and start it alongside every other
// long-lived goroutine.
//
// Like portscan.New and snmp.New it returns warnings rather than errors for
// everything the caller must carry on past: an unreadable configuration
// file, a hostname nothing can be derived from, an operator name that had
// to be refused. Each warning is a whole sentence an operator can act on,
// and none of them ever contains a bait name.
func New(cfg Config, submit Submit, log *slog.Logger) (*Detector, []string) {
	var warnings []string

	confPath := cfg.ConfPath
	if confPath == "" {
		confPath = DefaultConfPath
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	arpPath := cfg.ARPPath
	if arpPath == "" {
		arpPath = DefaultARPPath
	}

	nodeID, err := readNodeID(confPath)
	if err != nil {
		nodeID = DefaultNodeID
		warnings = append(warnings, fmt.Sprintf(
			"OpenCanary configuration unreadable, so the bait lookups fall back to a shared identity for their timing and names: %v", err))
	}

	profile := cfg.Profile
	if profile == "" {
		profile = DefaultProfile
	}

	schedule := NewSchedule(nodeID)

	hostname := cfg.Hostname
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}
	names, warning := DeriveNames(hostname, cfg.OperatorNames, schedule.Seed())
	if warning != "" {
		warnings = append(warnings, warning)
	}

	return &Detector{
		cfg:      cfg,
		log:      log,
		submit:   submit,
		nodeID:   nodeID,
		now:      now,
		profile:  profile,
		shape:    profile.Shape(),
		names:    names,
		pace:     cfg.Pace.normalise(),
		schedule: schedule,
		counter:  newPaceCounter(now()),
		arpPath:  arpPath,
		rand:     rand.New(rand.NewPCG(schedule.Seed(), 0x2545f4914f6cdd1d)),
	}, warnings
}

// Profile is the profile this detector settled on.
func (d *Detector) Profile() Profile { return d.profile }

// NameCount is how many names are in the rotation. The count, never the
// names: see this package's comment on why a bait name never reaches a log
// line.
func (d *Detector) NameCount() int { return len(d.names) }

// Bursts, Lookups and Answers are this detector's own counters, read for
// the agent's accounting. Not heartbeat fields yet, the same caveat
// portscan.Detected and snmp.Logged carry.
func (d *Detector) Bursts() uint64  { return d.bursts.Load() }
func (d *Detector) Lookups() uint64 { return d.lookups.Load() }
func (d *Detector) Answers() uint64 { return d.answers.Load() }

// CanSend reports whether the detector found an interface to ask on and a
// profile that asks anything. False means this run only listens and counts.
func (d *Detector) CanSend() bool { return d.canSend }

// Listening reports how many counting sockets opened.
func (d *Detector) Listening() int { return len(d.listeners) }

// Open finds the segment and opens the receive-only counting sockets.
// Separate from Run so a failure is reported to the caller's startup log
// rather than discovered inside a background goroutine -- the same contract
// portscan.Open and snmp.Open state.
//
// It returns an error only when nothing at all could be opened. A partial
// result is normal and is reported through the warnings: a container with no
// IPv6 has no IPv6 twin to send, a container with only loopback cannot send
// at all but can still count, and a port that will not bind (the
// privileged-port floor not lowered) costs that protocol's counting and
// nothing else.
func (d *Detector) Open() ([]string, error) {
	var warnings []string

	seg, err := findSegment()
	switch {
	case err != nil:
		warnings = append(warnings, fmt.Sprintf(
			"no interface to send bait lookups from, so this canary will listen for poisoners but never bait one: %v", err))
	case !d.profile.Sends():
		warnings = append(warnings, fmt.Sprintf(
			"segment profile %q sends no bait lookups, so a poisoner on this segment will not be baited; the segment's own query rate is still counted", d.profile))
		d.segment = seg
	default:
		d.segment, d.canSend = seg, true
	}

	// The counting sockets, one per protocol port. Every profile opens all
	// three, including "off" and "linux": issue #86 decision 41 is explicit
	// that the pace-matcher runs in all three profiles, and a count of NBT-NS
	// traffic is how an operator on a `linux` profile would find out their
	// segment is not as Linux as they thought.
	for _, l := range []struct {
		proto  Protocol
		port   int
		groups []net.IP
	}{
		{ProtocolLLMNR, LLMNRPort, []net.IP{llmnrGroupV4}},
		{ProtocolMDNS, MDNSPort, []net.IP{mdnsGroupV4}},
		// NBT-NS is broadcast, not multicast: there is no group to join,
		// and a socket bound to the wildcard address receives the subnet
		// broadcast anyway.
		{ProtocolNBNS, NBNSPort, nil},
	} {
		conn, err := listenReceiveOnly(l.port, l.groups)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf(
				"not counting %s queries on port %d, so this canary's bait rate falls back to the floor for that protocol: %v",
				l.proto, l.port, err))
			continue
		}
		d.listeners = append(d.listeners, listener{proto: l.proto, port: l.port, conn: conn})
	}

	if len(d.listeners) == 0 && !d.canSend {
		return warnings, errors.New("poisoner: no socket opened and nothing to send from")
	}
	return warnings, nil
}

// Run counts the segment's queries and makes bait lookups until ctx is
// cancelled. Calling Run without a successful Open is a programming error,
// reported rather than papered over -- the same contract portscan.Run and
// snmp.Run state.
func (d *Detector) Run(ctx context.Context) error {
	if len(d.listeners) == 0 && !d.canSend {
		return errors.New("poisoner: Run called before a successful Open")
	}

	var wg sync.WaitGroup
	for _, l := range d.listeners {
		wg.Add(1)
		go func(l listener) {
			defer wg.Done()
			d.count(ctx, l)
		}(l)
	}
	if d.canSend {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.ask(ctx)
		}()
	}
	wg.Wait()
	return nil
}

// countReadDeadline bounds one read on a counting socket so the loop can
// notice ctx being cancelled on a segment where nothing is being asked.
// Short enough that shutdown is prompt, long enough that it costs nothing
// on an idle port -- the same figure internal/agent/snmp's readDeadline
// uses, for the same reason.
const countReadDeadline = time.Second

// count reads one listening socket, counting every query it sees against
// its source host, until ctx is cancelled.
//
// It also catches a poisoner that answers by multicast rather than unicast.
// A compliant mDNS responder multicasts its answer to the group (RFC 6762
// section 6), which would never reach the query socket's ephemeral port --
// Responder unicasts, so the query socket is what catches Responder, but a
// multicast answer naming a bait name is the same proof and arrives here.
func (d *Detector) count(ctx context.Context, l listener) {
	defer func() { _ = l.conn.Close() }()

	buf := make([]byte, MaxDatagramLen)
	for {
		if ctx.Err() != nil {
			return
		}
		if err := l.conn.SetReadDeadline(time.Now().Add(countReadDeadline)); err != nil {
			return
		}
		n, src, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			// Anything else on a socket that cannot write is not
			// recoverable by reading again.
			return
		}
		d.observe(l, buf[:n], src)
	}
}

// observe is one datagram on a counting socket: either another host's
// query, which is what the pace-matcher counts, or a response naming one of
// this canary's bait names, which is a hit.
func (d *Detector) observe(l listener, b []byte, src *net.UDPAddr) {
	if len(b) < dnsHeaderLen {
		return
	}
	if binary.BigEndian.Uint16(b[2:4])&headerFlagResponse == 0 {
		// A query. Counted against its source host and nothing else: this
		// counter never resolves an address, connects to it or keeps
		// anything about it beyond a tally (see paceCounter.Observe).
		d.counter.Observe(src.IP.String(), d.now())
		return
	}

	r, err := parseReplyFor(l.proto, b)
	if err != nil || r.Answers == 0 || !d.names.contains(r.Name) {
		return
	}
	local, localPort := localAddr(l.conn)
	d.emit(Answer{
		Source:     src.IP.String(),
		SourcePort: src.Port,
		Protocol:   l.proto,
		Name:       r.Name,
		MAC:        lookupMAC(d.arpPath, src.IP.String()),
		Local:      local,
		LocalPort:  localPort,
	})
}

// ask is the burst loop: one burst shortly after start-up, then a burst
// every matched-and-jittered gap, only inside working hours.
func (d *Detector) ask(ctx context.Context) {
	// "Always once after the agent starts, as a machine does on boot"
	// (issue #86 decision 33). Not gated on working hours: a machine that
	// boots at three in the morning asks at three in the morning, and a
	// canary that stayed silent until nine would be the one host on the
	// segment whose first question always arrives at the start of the
	// working day.
	if !sleepCtx(ctx, d.schedule.StartupDelay()) {
		return
	}
	d.burst(ctx)

	for {
		queries, hosts := d.counter.Median(d.now())
		gap := d.schedule.Jitter(matchedGap(queries, hosts, d.pace), d.pace)
		if !sleepCtx(ctx, gap) {
			return
		}
		if !d.waitForWorkingHours(ctx) {
			return
		}
		d.burst(ctx)
	}
}

// waitForWorkingHours sleeps until the working window opens, in as few
// wakeups as possible. Returns false if ctx was cancelled first.
func (d *Detector) waitForWorkingHours(ctx context.Context) bool {
	for {
		now := d.now()
		if d.pace.Hours.Contains(now) {
			return true
		}
		wait := d.pace.Hours.NextStart(now).Sub(now)
		if wait <= 0 {
			// NextStart found nothing inside its search: treat it as a
			// long sleep and re-check, rather than spinning.
			wait = countReadDeadline
		}
		if !sleepCtx(ctx, wait) {
			return false
		}
	}
}

// burst makes one burst of lookups: two to five of them, on every protocol
// the profile asks, spread unevenly across a minute.
func (d *Detector) burst(ctx context.Context) {
	size := d.schedule.BurstSize()
	gaps := d.schedule.BurstGaps(size)
	d.bursts.Add(1)

	for i := 0; i < size; i++ {
		if i > 0 && !sleepCtx(ctx, gaps[i-1]) {
			return
		}
		name := d.schedule.NextName(d.names)
		if name == "" {
			return
		}
		for _, proto := range d.shape.Protocols {
			if ctx.Err() != nil {
				return
			}
			d.lookups.Add(1)
			answers, err := d.lookupLocked(ctx, proto, name)
			if err != nil {
				// A lookup that could not go out is a running condition,
				// not an alert. It is logged at debug because on a
				// container missing the privileged-port floor it would
				// otherwise repeat every burst forever; the startup
				// warnings are where an operator is told once, loudly.
				d.log.Debug(fmt.Sprintf("a %s bait lookup did not go out: %v", proto, err))
				continue
			}
			for _, a := range answers {
				d.emit(a)
			}
		}
	}
}

// lookupLocked makes one lookup, holding the transaction-id generator's
// lock for the draw only. math/rand/v2's generators are not safe for
// concurrent use, and the counting goroutines never draw, but a future
// second sender would.
func (d *Detector) lookupLocked(ctx context.Context, proto Protocol, name string) ([]Answer, error) {
	d.randMu.Lock()
	r := d.rand
	d.randMu.Unlock()
	return lookup(ctx, proto, name, d.segment, d.shape, r, d.arpPath)
}

// emit encodes one answer and hands it to the submit callback.
func (d *Detector) emit(a Answer) {
	message, err := encode(a, d.nodeID, d.now())
	if err != nil {
		d.log.Warn(fmt.Sprintf("could not encode a poisoner answer: %v", err))
		return
	}
	if err := d.submit(message); err != nil {
		d.submitFail.Add(1)
		d.log.Warn(fmt.Sprintf("could not queue a poisoner answer: %v", err))
		return
	}
	d.answers.Add(1)
	// The answering address only. It is the attacker's own, so naming it
	// on this box's stdout tells them nothing they do not know -- whereas
	// the bait name is the one thing an attacker reading this log must not
	// learn, because the bait only works while nobody knows which names it
	// uses. The name, the protocol and the MAC are in the event, on their
	// way to birdcage.
	d.log.Warn(fmt.Sprintf("%s answered a bait lookup for a name nobody should answer", a.Source))
}

// PaceReport is what the detector can say about the segment's own query
// rate, for the startup line and for #121's later measurement.
type PaceReport struct {
	// MedianQueries is the median host's query count over the rolling day.
	MedianQueries int

	// Hosts is how many distinct hosts asked anything in that window.
	Hosts int

	// Gap is the gap between bursts that median implies, after the floor
	// and the ceiling.
	Gap time.Duration

	// Matched is whether the gap came from the segment's own rate rather
	// than from the floor. False on a segment with fewer than
	// minTalkingHosts talking.
	Matched bool

	// Overflowed is whether any host went uncounted because a bucket was
	// full.
	Overflowed bool
}

// Pace reports the current pace-matching state.
func (d *Detector) Pace() PaceReport {
	queries, hosts := d.counter.Median(d.now())
	return PaceReport{
		MedianQueries: queries,
		Hosts:         hosts,
		Gap:           matchedGap(queries, hosts, d.pace),
		Matched:       hosts >= minTalkingHosts && queries > 0,
		Overflowed:    d.counter.Overflowed(),
	}
}

// Service is the name a poisoner alert appears under on the dashboard.
// Exported so the self-test (#46) and the dashboard work (#86 slice D) read
// it from here rather than repeating the string.
func Service() string { return serviceName() }

// ErrNotSending is returned by LookupOnce when this detector has nothing
// to send from: either the profile is ProfileOff, or Open found no
// interface to ask on. It is a distinct error because a self-test must
// report "this canary cannot bait" differently from "this canary baited
// and nothing answered" -- the first is a capability that is missing, the
// second is the result the test is looking for.
var ErrNotSending = errors.New("poisoner: this canary has nothing to send bait lookups from")

// LookupOnce makes exactly one bait lookup, on one protocol, for one
// name, and returns every answer it heard -- normally none.
//
// Exported for the self-test (#46 slice C): a run sends one bait query
// and grades silence as a pass. It is deliberately a single lookup rather
// than a burst, because a self-test is proving the machinery works, not
// impersonating a workstation, and because a burst's two-to-five lookups
// spread across a minute would outlast the sweep it runs inside.
//
// An empty name asks for one from this canary's own rotation, so a caller
// that does not want to know the bait names -- which is every caller
// outside this package (see the package comment on why a bait name never
// reaches a log line) -- does not have to handle them.
//
// An empty protocol asks on the first protocol the profile uses, so a
// caller does not have to know which protocols a profile covers either. A
// protocol the profile does not use is an error rather than a silent
// substitution: a self-test that claimed to have asked over NBT-NS while
// actually asking over mDNS would be proving the wrong thing.
//
// The answers it returns have already been submitted as alerts, the same
// as any answer to a scheduled burst: something answering a bait name is
// an intrusion whether or not a self-test happened to be what provoked
// it, and holding that back until the self-test reported would be the one
// case where this detector saw a poisoner and said nothing.
func (d *Detector) LookupOnce(ctx context.Context, proto Protocol, name string) ([]Answer, error) {
	// A nil receiver is the road being off. It reaches here because a
	// caller holding a *Detector in an interface cannot test it against
	// nil -- a typed nil pointer in an interface is not a nil interface --
	// so the check has to be on this side to be reliable. Answering
	// ErrNotSending is the same thing this says for a canary with nothing
	// to send from, which is exactly what a canary with no detector has.
	if d == nil || !d.canSend {
		return nil, ErrNotSending
	}
	protocols := d.shape.Protocols
	if len(protocols) == 0 {
		return nil, ErrNotSending
	}

	if proto == "" {
		proto = protocols[0]
	} else if !d.profile.Asks(proto) {
		return nil, fmt.Errorf("poisoner: the %s profile does not ask on %s", d.profile, proto)
	}

	if name == "" {
		name = d.schedule.NextName(d.names)
	} else {
		normalised, err := normaliseName(name)
		if err != nil {
			return nil, err
		}
		name = normalised
	}
	if name == "" {
		return nil, errNoName
	}

	d.lookups.Add(1)
	answers, err := d.lookupLocked(ctx, proto, name)
	if err != nil {
		return nil, err
	}
	for _, a := range answers {
		d.emit(a)
	}
	return answers, nil
}
