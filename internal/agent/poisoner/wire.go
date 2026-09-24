package poisoner

import (
	"net"
	"time"
)

// The ports the three protocols use. All three are below 1024, so binding
// them needs the container's privileged-port floor lowered -- which
// build/mockingbird/Dockerfile's run shape already does with
// `--sysctl net.ipv4.ip_unprivileged_port_start=0` for OpenCanary's own
// low ports, and which applies to every process in the container's
// network namespace, this agent included.
const (
	// LLMNRPort is 5355 (RFC 4795 section 2).
	LLMNRPort = 5355

	// MDNSPort is 5353 (RFC 6762 section 2).
	MDNSPort = 5353

	// NBNSPort is 137, the NetBIOS Name Service port (RFC 1002 section
	// 4.2). NBT-NS is also the one protocol whose query has to be sent
	// *from* this port to look like Windows, which is why listen.go and
	// query.go go to the trouble of sharing it.
	NBNSPort = 137
)

// The multicast groups the two DNS-shaped protocols use.
var (
	// llmnrGroupV4 is 224.0.0.252 and llmnrGroupV6 is FF02::1:3 (RFC
	// 4795 section 2, and the IANA assignments it cites).
	llmnrGroupV4 = net.IPv4(224, 0, 0, 252)
	llmnrGroupV6 = net.ParseIP("ff02::1:3")

	// mdnsGroupV4 is 224.0.0.251 and mdnsGroupV6 is FF02::FB (RFC 6762
	// section 3).
	mdnsGroupV4 = net.IPv4(224, 0, 0, 251)
	mdnsGroupV6 = net.ParseIP("ff02::fb")
)

// IP time-to-live values. The research note of 2026-09-23 lists a wrong
// TTL among the things that give a bait away -- "IP TTL 64 where Windows
// sends 128 on unicast and 1 on link-local multicast" -- and for two of
// the three the value is not merely conventional but load-bearing, because
// a conforming responder checks it.
const (
	// llmnrMulticastTTL is 1. RFC 4795 section 2.5 requires a sender to
	// set the TTL to 1 and a responder to silently discard a query
	// arriving with any other value, so this is the difference between
	// being answered and being ignored, not just between looking right
	// and looking wrong.
	llmnrMulticastTTL = 1

	// mdnsMulticastTTL is 255. RFC 6762 section 11 requires it, and
	// requires a receiver to check it: the pair proves the packet has not
	// crossed a router, which is the whole security model of a
	// link-local protocol.
	mdnsMulticastTTL = 255

	// nbnsBroadcastTTL is 128, the default initial TTL a Windows host
	// puts on a unicast or broadcast IP packet (the research note's own
	// figure). NBT-NS has no RFC requirement here -- a subnet broadcast
	// does not leave the segment whatever its TTL -- so this value is
	// purely about the shape matching a capture.
	nbnsBroadcastTTL = 128
)

// Retry counts and gaps. Named here rather than inline in profile.go's
// Shape so that each carries its source next to the number.
const (
	// llmnrTriesWindows is two transmissions of each question. RFC 4795
	// section 2.4 requires retransmission; a Windows client sends each
	// LLMNR question twice, and the research note lists "LLMNR without
	// the AAAA twin ... no retries" among the giveaways.
	llmnrTriesWindows = 2

	// llmnrTriesLinux is also two: systemd-resolved retries an LLMNR
	// query as RFC 4795 section 2.4 asks.
	llmnrTriesLinux = 2

	// llmnrRetryGap is RFC 4795 section 2.4's retransmission timeout,
	// 100 ms.
	llmnrRetryGap = 100 * time.Millisecond

	// nbnsTries is three, RFC 1002 section 4.2.12's
	// BCAST_REQ_RETRY_COUNT, which is also what a Windows client sends.
	nbnsTries = 3

	// nbnsRetryGap is the ~750 ms between those three tries that issue
	// #86's research note took from a capture of Windows. The RFC's own
	// BCAST_REQ_RETRY_TIMEOUT is 250 ms; the capture is what the segment
	// will compare us against, so the capture wins.
	nbnsRetryGap = 750 * time.Millisecond

	// mdnsTriesWindows is one. A one-shot mDNS lookup is not RFC 6762
	// section 5.2's continuous querier, and Windows' own name resolution
	// asks once per address family.
	mdnsTriesWindows = 1

	// mdnsTriesLinux is two: a systemd-resolved one-shot lookup repeats
	// the question, which RFC 6762 section 5.2's own initial one-second
	// interval allows for.
	mdnsTriesLinux = 2

	// mdnsRetryGap is RFC 6762 section 5.2's initial retransmission
	// interval, one second.
	mdnsRetryGap = time.Second
)

// replyWindow is how long a query socket stays open listening for an
// answer after the last transmission of a burst.
//
// A real poisoner answers immediately -- it is racing the real host, and
// on a bait name there is no real host to race -- so this is generous
// rather than tight: it costs one idle socket for two seconds and covers a
// loaded attacker box.
const replyWindow = 2 * time.Second
