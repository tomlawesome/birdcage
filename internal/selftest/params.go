package selftest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// MarkerBytes is the entropy behind one marker. A marker must be
// unguessable: an attacker who could predict one could get their own
// traffic classified as synthetic and so kept off the dashboard, which
// inverts the product. 16 bytes is the same 128-bit floor the event id
// uses, and markers are short-lived besides.
const MarkerBytes = 16

// MaxTargets bounds one run. It exists so a malformed or hostile
// command cannot ask an agent to open unbounded connections against its
// own host; upstream OpenCanary offers 22 modules, so anything beyond
// this is not a real configuration.
const MaxTargets = 32

// Params is the schema of a selftest command's params. It replaces the
// opaque object the command seat accepted while the probe engine was
// deferred (cmd/mockingbird/command.go).
type Params struct {
	// RunID identifies this sweep. It is echoed in nothing the agent
	// sends -- the probes produce ordinary OpenCanary events that
	// arrive by the ordinary two roads -- and exists so birdcage's own
	// records, logs and matcher can name one run.
	RunID string `json:"run_id"`

	// Address is the canary's own LAN address, which the agent probes
	// rather than loopback, so a pass also proves each service is bound
	// to the network (#46 settled decision 2: "a honeypot listening
	// only on localhost catches nobody and a loopback probe would pass
	// for one anyway").
	//
	// Birdcage supplies it because birdcage knows the address the
	// canary reports from; an agent asked to discover its own address
	// would have to pick among interfaces with no way to tell which one
	// the fleet reaches it on.
	Address string `json:"address"`

	// Targets is what to probe, one entry per service.
	Targets []Target `json:"targets"`
}

// Target is one service to probe in a run.
type Target struct {
	// Service is birdcage's service name, as internal/opencanary
	// derives it from a logtype -- "ssh", "http", "ftp" and so on.
	Service string `json:"service"`

	// DestPort is where that service listens on this canary. It is
	// carried per target rather than assumed, because OpenCanary's
	// ports are configurable and because HTTP and HTTPS are
	// indistinguishable by service name upstream: both land in the
	// 3000-3003 logtype range and both map to "http", so dst_port is
	// the only thing that tells a run which of the two answered (#46
	// module survey, 2026-09-17).
	DestPort int `json:"dest_port"`

	// Marker is the random value birdcage planted for this target in
	// this run. Per run and per service, never reused, never derived
	// from anything predictable (#46 settled decision 4).
	Marker string `json:"marker"`
}

// ErrNoTargets reports a run with nothing to probe. It is an error
// rather than a silent success: a sweep that probes nothing must not
// report a canary healthy.
var ErrNoTargets = errors.New("selftest: no targets")

// Validate checks a decoded Params well enough that neither end has to
// re-check the basics. It is deliberately strict -- #48's fail-closed
// rule makes a command the agent cannot fully parse a refusal, not a
// partial run.
func (p Params) Validate() error {
	if p.RunID == "" {
		return errors.New("selftest: empty run_id")
	}
	if p.Address == "" {
		return errors.New("selftest: empty address")
	}
	if len(p.Targets) == 0 {
		return ErrNoTargets
	}
	if len(p.Targets) > MaxTargets {
		return fmt.Errorf("selftest: %d targets exceeds the %d cap", len(p.Targets), MaxTargets)
	}
	seen := make(map[string]bool, len(p.Targets))
	for i, t := range p.Targets {
		if t.Service == "" {
			return fmt.Errorf("selftest: target %d has an empty service", i)
		}
		if t.DestPort < 1 || t.DestPort > 65535 {
			return fmt.Errorf("selftest: target %d (%s) has dest_port %d outside 1-65535", i, t.Service, t.DestPort)
		}
		if t.Marker == "" {
			return fmt.Errorf("selftest: target %d (%s) has an empty marker", i, t.Service)
		}
		// Two targets sharing a marker would make a single arriving
		// event prove both, so one dead service could ride in on
		// another's hit.
		if seen[t.Marker] {
			return fmt.Errorf("selftest: target %d (%s) reuses a marker", i, t.Service)
		}
		seen[t.Marker] = true
	}
	return nil
}

// DecodeParams parses and validates a command's raw params.
func DecodeParams(raw json.RawMessage) (Params, error) {
	var p Params
	if len(raw) == 0 {
		return p, errors.New("selftest: empty params")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Unknown fields are a refusal for the same reason the ingest
	// envelope refuses them: version skew and tampering look alike, and
	// both should stop the run rather than produce a half-understood one.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Params{}, fmt.Errorf("selftest: params: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Params{}, err
	}
	return p, nil
}
