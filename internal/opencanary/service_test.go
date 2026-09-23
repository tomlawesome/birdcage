package opencanary

import "testing"

// wantRangeCount is the number of entries logTypeRanges must have. If this
// test fails after adding or removing a range, add matching cases to
// TestServiceForLogTypeRangeBoundaries and TestServiceForLogTypeRangeMinMax
// below rather than bumping this number -- that is the whole point of the
// check.
const wantRangeCount = 23

func TestLogTypeRangesCount(t *testing.T) {
	if len(logTypeRanges) != wantRangeCount {
		t.Fatalf("len(logTypeRanges) = %d, want %d -- a range was added or removed without updating this test's cases (see the comment on wantRangeCount)", len(logTypeRanges), wantRangeCount)
	}
}

// TestLogTypeRangesDoNotOverlap guards against a range change that makes the
// mapping depend on slice iteration order: ServiceForLogType returns the
// first matching range, so two overlapping ranges would silently pick
// whichever comes first in logTypeRanges rather than reporting a conflict.
func TestLogTypeRangesDoNotOverlap(t *testing.T) {
	for i, a := range logTypeRanges {
		for j, b := range logTypeRanges {
			if i >= j {
				continue
			}
			if a.min <= b.max && b.min <= a.max {
				t.Errorf("range %d (%s, %d-%d) overlaps range %d (%s, %d-%d)", i, a.service, a.min, a.max, j, b.service, b.min, b.max)
			}
		}
	}
}

// TestServiceForLogTypeRangeMinMax proves each range's own minimum and
// maximum both resolve to the service that range names -- the core claim of
// the table, transcribed by hand from upstream OpenCanary's logger.py (see
// issue #19).
func TestServiceForLogTypeRangeMinMax(t *testing.T) {
	for _, r := range logTypeRanges {
		t.Run(r.service, func(t *testing.T) {
			if got := ServiceForLogType(&r.min); got != r.service {
				t.Errorf("ServiceForLogType(%d) = %q, want %q (range min)", r.min, got, r.service)
			}
			if got := ServiceForLogType(&r.max); got != r.service {
				t.Errorf("ServiceForLogType(%d) = %q, want %q (range max)", r.max, got, r.service)
			}
		})
	}
}

// TestServiceForLogTypeRangeBoundaries checks one below and one above every
// range. Most of these must be UnknownService, but a few ranges sit right
// next to another range (for example mssql's 9001-9002 sits between mysql's
// 8001 and mysql's second block at 9003), so this asserts the real adjacent
// service rather than assuming a gap everywhere.
func TestServiceForLogTypeRangeBoundaries(t *testing.T) {
	for _, r := range logTypeRanges {
		below := r.min - 1
		above := r.max + 1
		wantBelow := expectedService(below)
		wantAbove := expectedService(above)

		t.Run(r.service+"/below", func(t *testing.T) {
			if got := ServiceForLogType(&below); got != wantBelow {
				t.Errorf("ServiceForLogType(%d) = %q, want %q", below, got, wantBelow)
			}
		})
		t.Run(r.service+"/above", func(t *testing.T) {
			if got := ServiceForLogType(&above); got != wantAbove {
				t.Errorf("ServiceForLogType(%d) = %q, want %q", above, got, wantAbove)
			}
		})
	}
}

// expectedService is a from-scratch reimplementation of the range lookup,
// used only to compute what a boundary value ought to resolve to, so
// TestServiceForLogTypeRangeBoundaries does not have to hardcode which
// boundaries happen to be adjacent to another range.
func expectedService(logType int) string {
	for _, r := range logTypeRanges {
		if logType >= r.min && logType <= r.max {
			return r.service
		}
	}
	return UnknownService
}

// TestServiceForLogTypeFarOutsideEveryRange is the "wildly wrong logtype"
// case: a value nowhere near any known range must still map to
// UnknownService, not an empty string and not a panic.
func TestServiceForLogTypeFarOutsideEveryRange(t *testing.T) {
	cases := []int{0, -1, 500, 999, 20002, 98999, 99010, 1 << 30}
	for _, lt := range cases {
		if got := ServiceForLogType(&lt); got != UnknownService {
			t.Errorf("ServiceForLogType(%d) = %q, want %q", lt, got, UnknownService)
		}
	}
}

// TestServiceForLogTypeNilLogType is OpenCanary reporting no logtype at
// all -- the nil pointer ServiceForLogType explicitly accepts (see its own
// doc comment) -- must not panic and must fall back the same way an
// unmapped value does.
func TestServiceForLogTypeNilLogType(t *testing.T) {
	if got := ServiceForLogType(nil); got != UnknownService {
		t.Errorf("ServiceForLogType(nil) = %q, want %q", got, UnknownService)
	}
}

// TestSentinels pins the two sentinel values so a change to either is
// caught here rather than silently changing what a "field was absent"
// record looks like downstream.
func TestSentinels(t *testing.T) {
	// NoDestPort distinguishes "OpenCanary reported no dest_port" from port
	// 0, a real port. internal/agent/event/fields.go's ExtractFields
	// defaults DestPort to it before checking whether dst_port was present
	// in the JSON payload, and internal/ingest/parse.go and
	// cmd/mockingbird/intake.go use it the same way on the server side.
	if NoDestPort != -1 {
		t.Errorf("NoDestPort = %d, want -1", NoDestPort)
	}
	// NoSourceAddress is the empty string OpenCanary's own zero value
	// already produces for an absent src_host; internal/ingest/parse.go and
	// internal/agent/event/fields.go rely on that -- SourceIP is simply
	// never set rather than assigned this constant -- so this only pins the
	// value both sides document as that convention.
	if NoSourceAddress != "" {
		t.Errorf("NoSourceAddress = %q, want %q", NoSourceAddress, "")
	}
}

// TestIsBaseMatchesOnlyTheStartUpRange: issue #117 filters OpenCanary's
// start-up lines by the service name the 1000-1006 range produces and by
// nothing else, so every other range's service must read as not-base,
// and so must an empty or unknown service.
func TestIsBaseMatchesOnlyTheStartUpRange(t *testing.T) {
	for _, r := range logTypeRanges {
		lt := r.min
		got := IsBase(ServiceForLogType(&lt))
		want := r.min == 1000
		if got != want {
			t.Errorf("IsBase(ServiceForLogType(%d)=%q) = %v, want %v", r.min, r.service, got, want)
		}
	}
	for _, s := range []string{"", UnknownService, "Base", "base "} {
		if IsBase(s) {
			t.Errorf("IsBase(%q) = true, want false", s)
		}
	}
}
