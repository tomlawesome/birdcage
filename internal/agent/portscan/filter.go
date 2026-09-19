package portscan

import "golang.org/x/net/bpf"

// Every offset in this file is measured from the start of the IPv4
// header, which is the same view parse.go reads.
//
// That agreement is worth stating, because the usual advice about
// classic BPF on packet sockets says the opposite: a filter normally
// sees the frame including its link-layer header, which is why tcpdump's
// programs start by loading the EtherType at offset 12. That is true for
// SOCK_RAW and false here. af_packet.c's packet_rcv pushes the MAC
// header back on before running the filter only when the socket is not
// SOCK_DGRAM:
//
//	if (sk->sk_type != SOCK_DGRAM)
//	        skb_push(skb, skb->data - skb_mac_header(skb));
//	...
//	res = run_filter(skb, sk, snaplen);
//
// The capture socket is SOCK_DGRAM (capture_linux.go), so the filter and
// userspace see exactly the same bytes, starting at the IP header. A
// filter written against link-layer offsets loads the wrong bytes,
// matches nothing, and drops every packet -- which looks exactly like a
// quiet network. This was written the wrong way round first and found by
// running the built image against a real scan; the unit tests below
// passed throughout, because a VM will happily run a self-consistent
// program against whatever packets the test hands it.
//
// Switching to SOCK_RAW means adding 14 to every offset here and
// stripping the same 14 in parse.go. There is no reason to.
const (
	// ipVersionIHL holds the IP version in its high nibble and the
	// header length, in 4-byte words, in its low nibble.
	ipVersionIHLOffset = 0

	// ipVersionMask/ipVersionIPv4 test that high nibble. The socket is
	// bound to ETH_P_IP so nothing else should arrive, but the filter
	// checks rather than assumes -- it is three instructions, and it is
	// what makes the program correct on its own terms rather than only
	// in combination with the bind call.
	//
	// The IPv6 seam: ipVersionIPv6 (0x60) would branch to a second
	// protocol check at a fixed 40-byte header -- no IHL, so no
	// LoadMemShift -- plus an extension-header walk, and capture_linux.go
	// would bind ETH_P_ALL instead of ETH_P_IP. Nothing else in this
	// package assumes IPv4: the tracker keys on a netip.Addr and the
	// event carries dst_host as a string, so that change lands in this
	// file, parse.go and the bind call, and nowhere else.
	ipVersionMask = 0xf0
	ipVersionIPv4 = 0x40

	// ipFlagsFragOffset is the flags-and-fragment-offset field.
	ipFlagsFragOffset = 6

	// ipProtocolOffset is the transport protocol number.
	ipProtocolOffset = 9

	// tcpFlagsOffset is the TCP flags byte, measured from the start of
	// the TCP header. The filter reaches it by adding the X register,
	// which LoadMemShift has set to the IPv4 header length; parse.go
	// reaches it by slicing the packet at that same length.
	tcpFlagsOffset = 13
)

// IP protocol numbers and the IPv4 fragment-offset mask.
const (
	protoTCP = 6
	protoUDP = 17

	// fragmentOffsetMask is the low 13 bits of the flags-and-offset
	// field. A non-zero fragment offset means a continuation fragment
	// carrying no transport header, so there are no ports to read: the
	// filter drops it rather than letting the parser read whatever bytes
	// happen to sit at the port offsets. (An attacker who fragments
	// their scan therefore evades detection. That is a deliberate trade
	// -- reassembling fragments in the agent is exactly the unbounded
	// state this box must not hold -- and it is written down in
	// docs/enrolment.md rather than left as a surprise.)
	fragmentOffsetMask = 0x1fff
)

// TCP flag bits, and the mask/value pair expressing "a connection
// attempt, not a reply and not an established connection".
const (
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10

	// synMask/synValue: SYN set and ACK clear. Masking once and
	// comparing is one instruction pair rather than two branches, and
	// puts the intent in one place. SYN+ACK is a reply to something we
	// sent; ACK, RST and FIN belong to a connection already past its
	// SYN.
	synMask  = tcpFlagSYN | tcpFlagACK
	synValue = tcpFlagSYN
)

// snapLen is the RetConstant for an accepted packet: how many bytes the
// kernel may copy. Comfortably above any IPv4 header plus transport
// header, and bounded so a jumbo frame cannot enlarge one read.
const snapLen = 262144

// filterInstructions is the classic BPF program attached to the capture
// socket, in execution order. It is what stops a SYN flood costing a
// syscall and a scheduler wakeup per packet -- the reason the filter is
// here from the first commit rather than as a later optimisation.
//
// Written as a flat slice with the two returns last, because classic BPF
// jumps are forward-only relative skips: the skip counts are computed
// from named indices rather than written as literals, and filter_test.go
// runs the assembled program through bpf.NewVM against hand-built
// packets.
//
//	ldb  [0]                   ; version and IHL
//	and  #0xf0
//	jne  #0x40   -> drop       ; not IPv4
//	ldh  [6]                   ; flags and fragment offset
//	jset #0x1fff -> drop       ; continuation fragment, no ports to read
//	ldb  [9]                   ; protocol
//	jeq  #17     -> pass       ; UDP: every datagram is an attempt
//	jne  #6      -> drop       ; not TCP either
//	ldx  4*([0]&0xf)           ; X = IPv4 header length
//	ldb  [x + 13]              ; TCP flags
//	and  #0x12                 ; SYN|ACK
//	jeq  #0x02   -> pass       ; SYN set, ACK clear
//	ret  #0                    ; drop
//	ret  #262144               ; pass
func filterInstructions() []bpf.Instruction {
	const (
		iVersion    = 0
		iMaskVer    = 1
		jNotIPv4    = 2
		iFragField  = 3
		jFragment   = 4
		iProtocol   = 5
		jUDP        = 6
		jNotTCP     = 7
		iHeaderLen  = 8
		iTCPFlags   = 9
		iMaskFlags  = 10
		jSYNOnly    = 11
		iReturnDrop = 12
		iReturnPass = 13
	)
	// A classic BPF jump skips (target - jump - 1) instructions.
	skip := func(from, to int) uint8 { return uint8(to - from - 1) }

	return []bpf.Instruction{
		iVersion: bpf.LoadAbsolute{Off: ipVersionIHLOffset, Size: 1},
		iMaskVer: bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: ipVersionMask},
		jNotIPv4: bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: ipVersionIPv4, SkipTrue: skip(jNotIPv4, iReturnDrop)},

		iFragField: bpf.LoadAbsolute{Off: ipFlagsFragOffset, Size: 2},
		jFragment:  bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: fragmentOffsetMask, SkipTrue: skip(jFragment, iReturnDrop)},

		iProtocol: bpf.LoadAbsolute{Off: ipProtocolOffset, Size: 1},
		jUDP:      bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoUDP, SkipTrue: skip(jUDP, iReturnPass)},
		jNotTCP:   bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: protoTCP, SkipTrue: skip(jNotTCP, iReturnDrop)},

		iHeaderLen: bpf.LoadMemShift{Off: ipVersionIHLOffset},
		iTCPFlags:  bpf.LoadIndirect{Off: tcpFlagsOffset, Size: 1},
		iMaskFlags: bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: synMask},
		jSYNOnly:   bpf.JumpIf{Cond: bpf.JumpEqual, Val: synValue, SkipTrue: skip(jSYNOnly, iReturnPass)},

		iReturnDrop: bpf.RetConstant{Val: 0},
		iReturnPass: bpf.RetConstant{Val: snapLen},
	}
}

// assembleFilter turns filterInstructions into the raw instruction words
// SO_ATTACH_FILTER takes. bpf.Assemble is what validates the program --
// jumps in range, a return on every path -- so an error here is a
// programming mistake in filterInstructions, never anything an operator
// or an attacker can cause.
func assembleFilter() ([]bpf.RawInstruction, error) {
	return bpf.Assemble(filterInstructions())
}
