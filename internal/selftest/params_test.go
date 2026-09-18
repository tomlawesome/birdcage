package selftest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validParams() Params {
	return Params{
		RunID:   "run-1",
		Address: "192.0.2.10",
		Targets: []Target{
			{Service: "ssh", DestPort: 22, Marker: "aaaa"},
			{Service: "ftp", DestPort: 21, Marker: "bbbb"},
		},
	}
}

func TestValidate_AcceptsAWellFormedRun(t *testing.T) {
	if err := validParams().Validate(); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
}

// A sweep that probes nothing must not be mistaken for a sweep that
// passed: #46's whole point is that a canary which cannot trigger is as
// bad as no protection at all.
func TestValidate_EmptyTargetsIsAnError(t *testing.T) {
	p := validParams()
	p.Targets = nil
	if err := p.Validate(); !errors.Is(err, ErrNoTargets) {
		t.Fatalf("want ErrNoTargets, got %v", err)
	}
}

// Two targets sharing a marker would let one arriving event prove both,
// so a dead service could ride in on a live one's hit.
func TestValidate_RejectsAReusedMarker(t *testing.T) {
	p := validParams()
	p.Targets[1].Marker = p.Targets[0].Marker
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "reuses a marker") {
		t.Fatalf("want a reused-marker refusal, got %v", err)
	}
}

func TestValidate_RejectsMissingFields(t *testing.T) {
	for name, mutate := range map[string]func(*Params){
		"empty run_id":  func(p *Params) { p.RunID = "" },
		"empty address": func(p *Params) { p.Address = "" },
		"empty service": func(p *Params) { p.Targets[0].Service = "" },
		"empty marker":  func(p *Params) { p.Targets[0].Marker = "" },
		"port zero":     func(p *Params) { p.Targets[0].DestPort = 0 },
		"port too high": func(p *Params) { p.Targets[0].DestPort = 65536 },
	} {
		t.Run(name, func(t *testing.T) {
			p := validParams()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

func TestValidate_RejectsMoreTargetsThanTheCap(t *testing.T) {
	p := validParams()
	p.Targets = nil
	for i := 0; i <= MaxTargets; i++ {
		p.Targets = append(p.Targets, Target{Service: "ssh", DestPort: 22, Marker: string(rune('a'+i%26)) + string(rune('0'+i/26))})
	}
	if err := p.Validate(); err == nil {
		t.Fatal("a run beyond the target cap was accepted")
	}
}

func TestDecodeParams_RoundTrips(t *testing.T) {
	raw, err := json.Marshal(validParams())
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeParams(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.RunID != "run-1" || len(got.Targets) != 2 || got.Targets[1].Service != "ftp" {
		t.Fatalf("round trip lost data: %+v", got)
	}
}

// Version skew and tampering look alike, and #48's fail-closed rule
// makes a command the agent cannot fully parse a refusal rather than a
// partial run.
func TestDecodeParams_RefusesUnknownFields(t *testing.T) {
	raw := []byte(`{"run_id":"r","address":"192.0.2.10","targets":[{"service":"ssh","dest_port":22,"marker":"m"}],"surprise":1}`)
	if _, err := DecodeParams(raw); err == nil {
		t.Fatal("unknown field was accepted")
	}
}

func TestDecodeParams_RefusesNonObjectAndEmpty(t *testing.T) {
	for _, raw := range []string{``, `"a string"`, `42`, `{`, `[]`} {
		if _, err := DecodeParams([]byte(raw)); err == nil {
			t.Fatalf("params %q was accepted", raw)
		}
	}
}
