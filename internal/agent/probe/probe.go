package probe

import (
	"context"
	"sync"
	"time"

	"github.com/tomlawesome/birdcage/internal/selftest"
)

// Timeouts and the concurrency bound for one sweep. The probe never
// leaves the canary's own LAN -- selftest.Params.Address is the
// canary's own reported address, per that field's doc comment -- so a
// healthy service should answer well inside these, and a slow or dead
// one should not be allowed to eat the run.
const (
	// DefaultProbeTimeout bounds one target end to end: dial plus
	// whatever handshake that service's carrier needs (SSH key
	// exchange, a MySQL or MSSQL round trip). Generous for a same-LAN
	// call, short enough that one dead service can't dominate the
	// sweep's own budget.
	DefaultProbeTimeout = 8 * time.Second

	// DefaultSweepTimeout bounds the whole run regardless of target
	// count, up to selftest.MaxTargets. A self-test that hangs the
	// agent process defeats its own purpose: an agent that cannot poll
	// for its next command looks exactly like a dead canary. At
	// DefaultConcurrency, a full MaxTargets run needs at most
	// ceil(32/4) = 8 batches of DefaultProbeTimeout each -- 64s -- so
	// 90s leaves headroom without approaching runCommandRunner's
	// sequential-execution assumption for very long.
	DefaultSweepTimeout = 90 * time.Second

	// DefaultConcurrency bounds how many targets probe at once, so a
	// sweep does not open every socket on the canary's own host in the
	// same instant (house rule: probes run against the canary's own
	// host, and must not do that). 4 keeps the canary's other services
	// -- OpenCanary itself, the agent's own tailer -- responsive while
	// the sweep runs.
	DefaultConcurrency = 4
)

// Config bounds one Sweep. The zero value is not usable; use
// DefaultConfig.
type Config struct {
	ProbeTimeout time.Duration
	SweepTimeout time.Duration
	Concurrency  int
}

// DefaultConfig returns the bounds described above.
func DefaultConfig() Config {
	return Config{
		ProbeTimeout: DefaultProbeTimeout,
		SweepTimeout: DefaultSweepTimeout,
		Concurrency:  DefaultConcurrency,
	}
}

// Status is the terminal state of probing one target.
type Status int

const (
	// StatusOK means the carrier for this target's service ran to
	// completion and delivered the marker onto the wire. It says
	// nothing about whether the service accepted any credential --
	// only that the probe reached the point of presenting one.
	StatusOK Status = iota + 1

	// StatusFailed means the carrier returned an error: a dial that
	// never connected, a handshake that timed out, or any other
	// network-level failure. Per #46's fail-closed rule, this is a
	// recorded failure, never a silent skip.
	StatusFailed

	// StatusNoCarrier means the target's service has no entry in this
	// package's carrier table -- see carrier.go for the services this
	// covers and why. Nothing is attempted.
	StatusNoCarrier

	// StatusNotProbeable means the target names one of #46's
	// out-of-scope services (smb, llmnr -- see carrier.go's
	// notProbeable). Nothing is attempted.
	StatusNotProbeable
)

// String renders a Status for logging.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusFailed:
		return "failed"
	case StatusNoCarrier:
		return "no-carrier"
	case StatusNotProbeable:
		return "not-probeable"
	default:
		return "unknown"
	}
}

// Outcome is the result of probing one target. Err is non-nil only when
// Status is StatusFailed. Fact is non-nil only when Status is StatusOK
// and Service is one of attributionCarriers' two entries (ntp,
// portscan) -- cmd/mockingbird's runSelfTest hands it to the claim
// window (#46 slice 3); every other outcome leaves it nil.
type Outcome struct {
	Service  string
	DestPort int
	Status   Status
	Err      error
	Fact     *AttributionFact
}

// Sweep probes every target in params with DefaultConfig. See
// SweepWithConfig.
func Sweep(ctx context.Context, params selftest.Params) []Outcome {
	return SweepWithConfig(ctx, params, DefaultConfig())
}

// SweepWithConfig probes every target in params, at most cfg.Concurrency
// at a time, and returns one Outcome per target in params.Targets order.
// The whole call returns within cfg.SweepTimeout of ctx (or ctx's own
// deadline, if sooner) regardless of how many targets are still
// outstanding -- a target still running when the sweep deadline lands
// gets StatusFailed from its own probeTimeout context, the same as any
// other timeout.
//
// SweepWithConfig does not validate params; callers are expected to have
// already run selftest.DecodeParams, which validates on the caller's
// behalf (empty targets, duplicate markers, and so on are refused
// there, before a sweep is ever started).
func SweepWithConfig(ctx context.Context, params selftest.Params, cfg Config) []Outcome {
	ctx, cancel := context.WithTimeout(ctx, cfg.SweepTimeout)
	defer cancel()

	outcomes := make([]Outcome, len(params.Targets))

	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
	for i, t := range params.Targets {
		i, t := i, t
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			outcomes[i] = probeOne(ctx, cfg.ProbeTimeout, params.Address, t)
		}()
	}
	wg.Wait()

	return outcomes
}

// probeOne resolves and, if applicable, runs the carrier for one
// target. probeTimeout is applied as a child of ctx, so it can only
// shrink the time available, never extend it past the sweep's own
// deadline.
func probeOne(ctx context.Context, probeTimeout time.Duration, address string, t selftest.Target) Outcome {
	o := Outcome{Service: t.Service, DestPort: t.DestPort}

	if notProbeable[t.Service] {
		o.Status = StatusNotProbeable
		return o
	}

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	if ac, ok := attributionCarriers[t.Service]; ok {
		fact, err := ac(probeCtx, address, t.DestPort)
		if err != nil {
			o.Status = StatusFailed
			o.Err = err
			return o
		}
		o.Status = StatusOK
		o.Fact = &fact
		return o
	}

	carrier, ok := carriers[t.Service]
	if !ok {
		o.Status = StatusNoCarrier
		return o
	}

	if err := carrier(probeCtx, address, t.DestPort, t.Marker); err != nil {
		o.Status = StatusFailed
		o.Err = err
		return o
	}

	o.Status = StatusOK
	return o
}
