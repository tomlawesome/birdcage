package poisoner

import (
	"fmt"
	"time"
)

// Profile is a canary's segment profile: which protocols it asks on, and
// in whose shape. Issue #86 decision 41 (owner, 2026-09-23) settled the
// three values and why -- a lone Windows-looking host on an all-Linux
// segment would stand out, so matching the segment matters as much as
// matching a client.
type Profile string

// The three profiles. The strings are the operator-facing values, so they
// are what the enrolment flag and the environment variable accept.
const (
	// ProfileWindows is the default: all three protocols, shaped like a
	// current Windows client.
	ProfileWindows Profile = "windows"

	// ProfileLinux is LLMNR and mDNS only, shaped the way
	// systemd-resolved and Avahi ask. No NBT-NS: a Linux host does not
	// speak it, and one host on an all-Linux segment that does would be
	// the most interesting thing on the wire.
	ProfileLinux Profile = "linux"

	// ProfileOff sends nothing, and therefore detects nothing, for an
	// operator who wants no bait traffic at all. The pace-matcher still
	// runs -- it only listens, and its counts are what a later change to
	// a sending profile would be paced by.
	ProfileOff Profile = "off"
)

// DefaultProfile is what a canary enrolled without one gets.
const DefaultProfile = ProfileWindows

// ParseProfile reads an operator-supplied profile name. An empty string is
// DefaultProfile; anything unrecognised is an error rather than a silent
// fallback, because the difference between the profiles is what the
// segment sees, and guessing it wrong is the giveaway this setting exists
// to avoid.
func ParseProfile(raw string) (Profile, error) {
	switch Profile(raw) {
	case "":
		return DefaultProfile, nil
	case ProfileWindows, ProfileLinux, ProfileOff:
		return Profile(raw), nil
	default:
		return "", fmt.Errorf("poisoner: unknown segment profile %q: use %q, %q or %q", raw, ProfileWindows, ProfileLinux, ProfileOff)
	}
}

// Shape is everything a profile decides about how a burst goes out. It is
// a value rather than a set of branches inside the sender so that a test
// can assert what a profile asks for without opening a socket, and so the
// per-protocol timings sit next to the citation for where they come from.
type Shape struct {
	// Protocols are the protocols a burst asks on, in the order it asks.
	Protocols []Protocol

	// LLMNRTries is how many times one LLMNR question goes out, counting
	// the first. RFC 4795 section 2.4 asks a sender to retransmit, and a
	// Windows client sends each question twice; a single unrepeated query
	// is one of the shapes the research note lists as a giveaway.
	LLMNRTries int

	// LLMNRRetryGap is the wait between those tries. RFC 4795 section
	// 2.4's own retransmission timeout.
	LLMNRRetryGap time.Duration

	// NBNSTries and NBNSRetryGap are the NBT-NS equivalents. RFC 1002
	// section 4.2.12's BCAST_REQ_RETRY_COUNT is 3, which is what Windows
	// sends; the gap is the ~750 ms a capture of Windows shows rather
	// than the RFC's own 250 ms default (issue #86's research note of
	// 2026-09-23, "three tries ~750 ms apart").
	NBNSTries    int
	NBNSRetryGap time.Duration

	// MDNSTries and MDNSRetryGap: RFC 6762 section 5.2 has a continuous
	// querier back off from one second, doubling. A one-shot lookup is
	// not that, and sends the question once or twice.
	MDNSTries    int
	MDNSRetryGap time.Duration

	// MDNSUnicastResponse sets the QU bit described at
	// mdnsUnicastResponseBit. Windows leaves it clear; a
	// systemd-resolved one-shot lookup sets it, which is RFC 6762
	// section 5.4's own recommendation for a one-shot query.
	MDNSUnicastResponse bool

	// QueryIPv6 asks the questions over IPv6 as well as IPv4 -- LLMNR's
	// ff02::1:3 and mDNS' ff02::fb. Best-effort: a container with no
	// IPv6 address simply has nowhere to send them, which is not a
	// failure.
	QueryIPv6 bool
}

// Shape returns what the profile asks for. Every protocol list and timing
// here is a shape claim, so it is the one place to change when #121's
// capture says a real client does something else.
func (p Profile) Shape() Shape {
	switch p {
	case ProfileLinux:
		return Shape{
			// systemd-resolved does LLMNR, Avahi does mDNS, and neither
			// speaks NBT-NS.
			Protocols:     []Protocol{ProtocolLLMNR, ProtocolMDNS},
			LLMNRTries:    llmnrTriesLinux,
			LLMNRRetryGap: llmnrRetryGap,
			MDNSTries:     mdnsTriesLinux,
			MDNSRetryGap:  mdnsRetryGap,
			// RFC 6762 section 5.4: a one-shot query SHOULD ask for a
			// unicast reply, which is what systemd-resolved's own
			// resolution does.
			MDNSUnicastResponse: true,
			QueryIPv6:           true,
		}
	case ProfileOff:
		return Shape{}
	default:
		return Shape{
			Protocols:     []Protocol{ProtocolLLMNR, ProtocolNBNS, ProtocolMDNS},
			LLMNRTries:    llmnrTriesWindows,
			LLMNRRetryGap: llmnrRetryGap,
			NBNSTries:     nbnsTries,
			NBNSRetryGap:  nbnsRetryGap,
			MDNSTries:     mdnsTriesWindows,
			MDNSRetryGap:  mdnsRetryGap,
			QueryIPv6:     true,
		}
	}
}

// Sends reports whether the profile puts anything on the wire at all.
func (p Profile) Sends() bool { return len(p.Shape().Protocols) > 0 }

// Asks reports whether the profile asks on proto.
func (p Profile) Asks(proto Protocol) bool {
	for _, have := range p.Shape().Protocols {
		if have == proto {
			return true
		}
	}
	return false
}
