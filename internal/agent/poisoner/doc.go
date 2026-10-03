// Package poisoner catches an attacker running Responder, Inveigh or any
// other LLMNR/NBT-NS/mDNS poisoner by asking the local segment for a name
// nobody should answer, and treating any answer as an intrusion (issue
// #86).
//
// # Why an answer is proof
//
// When a Windows client cannot resolve a name in DNS it asks the local
// segment, unauthenticated: LLMNR, NBT-NS and -- on current Windows --
// mDNS. A poisoner answers every such question as if it were the host
// asked for, and the victim then authenticates to the attacker. The bait
// names this package asks for do not exist, so the only correct answer
// is silence. Anything that answers is hostile, which is what makes the
// false-positive rate near zero and the confidence near-certain.
//
// # What it sends
//
// encode.go holds three query encoders, each shaped like the client the
// segment expects to see rather than like a scanner:
//
//   - LLMNR (RFC 4795): DNS-format query to 224.0.0.252:5355 and
//     ff02::1:3, A and AAAA, retried, IP multicast TTL 1.
//   - NBT-NS (RFC 1001/1002): NetBIOS name query broadcast to the
//     subnet broadcast address on port 137, sent *from* port 137,
//     first-level-encoded name, three tries, IP TTL 128.
//   - mDNS (RFC 6762): DNS-format query for "name.local" to
//     224.0.0.251:5353, IP multicast TTL 255.
//
// profile.go decides which of the three run and in whose shape: the
// per-canary segment profile is "windows" (all three), "linux" (LLMNR
// and mDNS only, shaped the way systemd-resolved and Avahi ask -- a lone
// Windows-looking host on an all-Linux segment would stand out) or "off"
// (nothing sent, detection therefore off).
//
// Every byte value in encode.go carries the clause of the RFC or the
// capture note it comes from, because the whole value of the shape is
// that it is indistinguishable from a real client's: a query that is
// nearly right is a signature of its own.
//
// # Never answering, and the kernel quirk that enforces it
//
// pace.go needs a receive-only socket on 5355, 5353 and 137 to count how
// much the segment's own hosts ask (see below). A process listening on
// those ports is one setsockopt away from being a poisoner itself, so
// listen.go shuts every one of those sockets for writing the moment it
// opens them, and the kernel refuses any send from them afterwards --
// the guarantee is not that this code chooses not to answer, it is that
// it cannot.
//
// Linux returns ENOTCONN from shutdown() on an unconnected UDP socket,
// because an unconnected datagram socket has no connection to shut, but
// it still records the shutdown before returning that error -- so the
// send side really is closed and a later sendto fails with EPIPE.
// listen.go therefore treats ENOTCONN as success, and
// TestListenerRefusesSend proves the send fails on a real socket rather
// than trusting that reading.
//
// Replies to our own queries never arrive on those listeners. LLMNR and
// mDNS queries go out from an ephemeral port, so the answer comes back
// to that port. NBT-NS has to be sent from port 137 to look like
// Windows, which would collide -- so the listener binds the wildcard
// address and the query socket binds the interface's own unicast
// address, both with SO_REUSEADDR. Linux then delivers the broadcast
// queries the segment sends (destination the subnet broadcast address)
// only to the wildcard socket, and the unicast reply to our own query
// only to the more specific one. Neither socket can see the other's
// traffic and only the query socket can write.
//
// # Pace-matching
//
// A fixed interval is a signature: one host asking for the same name
// every ninety minutes, day and night, is the easiest thing on the
// segment to spot. So the rate is taken from the segment itself. The
// receive-only sockets count queries per source host over a rolling day
// and the canary matches the MEDIAN host, never the busiest -- matching
// the busiest would make the canary the loudest host on a quiet segment.
//
// The floor and the ceiling that bound that rate are guesses, marked as
// such here and at their constants: issue #121 replaces them with values
// measured from a capture.
//
// # Parsing a hostile reply
//
// The attack surface this package adds is one untrusted UDP reply. Go's
// bounds checks remove the memory-safety class that SIGRed
// (CVE-2020-1350) and dnsmasq's CVE-2017-14491 belong to; what is left
// is logic, and parse.go closes it: a datagram is capped at 512 bytes, a
// compression pointer must point strictly backwards (which rejects both
// a forward pointer and a self-loop), and the decoded name is bounded.
//
// Nothing in this package acts on the content of a reply. The alert
// names the bait name from this agent's own record of what it asked,
// keyed by the transaction id, not the name the packet claims; and the
// answering address is never connected to, because connecting is the
// trap the poisoner is setting -- it would hand the attacker an NTLM
// exchange, and a Linux client completing a Windows client's handshake
// would give the bait away.
//
// # What it never logs
//
// The bait names, ever, at any level. The whole point of deriving them
// from the operator's own naming style rather than shipping one is that
// there is nothing for an attacker to grep for, and this binary's stdout
// is readable by anyone who breaks into the box it runs on (see
// cmd/mockingbird's package comment). A hit logs the answering address
// -- which is the attacker's own -- and nothing else; the name, the
// protocol and the MAC travel in the event, to birdcage.
package poisoner
