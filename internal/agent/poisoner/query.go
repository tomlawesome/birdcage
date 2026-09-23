package poisoner

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"
)

// question is one bait lookup as it goes on the wire: the datagram, and the
// transaction id that identifies its answer.
type question struct {
	id       uint16
	datagram []byte
}

// asked records what one burst put on the wire, so a reply can be matched
// to it without reading the reply's own claims about what it answers.
type asked struct {
	name  string
	proto Protocol
	ids   map[uint16]struct{}
}

// matches reports whether a parsed reply answers this lookup.
//
// Two ways in, because the two protocol families identify an answer
// differently. LLMNR and NBT-NS carry the transaction id back, which is the
// strong test: an id this agent minted and has not seen answered. mDNS
// cannot, because RFC 6762 section 18.1 pins a multicast query's id to
// zero, so for mDNS the test is the echoed name -- weaker, but a response
// naming a bait name is by construction a poisoning whoever it is aimed at.
func (a asked) matches(r reply) bool {
	if r.Answers == 0 {
		// A response with no answer records is not an answer. Responder
		// always sends one; an NXDOMAIN-shaped reply from something
		// well-behaved is the silence this detector expects.
		return false
	}
	if _, ours := a.ids[r.ID]; ours && r.ID != mdnsQueryID {
		return true
	}
	return r.Name == a.name
}

// buildQuestions renders the datagrams one bait lookup sends, in order,
// for the profile's shape.
//
// The tries are not built here -- the same datagram goes out again for a
// retry, transaction id included, which is what a retransmission is.
func buildQuestions(proto Protocol, name string, shape Shape, r *rand.Rand) ([]question, error) {
	switch proto {
	case ProtocolLLMNR:
		// A and AAAA, each with its own transaction id: a Windows client
		// asks both, and "LLMNR without the AAAA twin" is one of the
		// giveaways issue #86's research note lists.
		var out []question
		for _, qtype := range []uint16{typeA, typeAAAA} {
			id := uint16(r.Uint32())
			datagram, err := encodeLLMNRQuery(id, name, qtype)
			if err != nil {
				return nil, err
			}
			out = append(out, question{id: id, datagram: datagram})
		}
		return out, nil

	case ProtocolMDNS:
		var out []question
		for _, qtype := range []uint16{typeA, typeAAAA} {
			datagram, err := encodeMDNSQuery(name, qtype, shape.MDNSUnicastResponse)
			if err != nil {
				return nil, err
			}
			out = append(out, question{id: mdnsQueryID, datagram: datagram})
		}
		return out, nil

	case ProtocolNBNS:
		// One question only: NBT-NS has no address-family twin, and a
		// NetBIOS name query is a single NB question (RFC 1002 section
		// 4.2.12).
		id := uint16(r.Uint32())
		datagram, err := encodeNBNSQuery(id, name)
		if err != nil {
			return nil, err
		}
		return []question{{id: id, datagram: datagram}}, nil

	default:
		return nil, fmt.Errorf("poisoner: no encoder for protocol %q", proto)
	}
}

// tries returns how many times each of a protocol's questions goes out, and
// the gap between tries, for the given shape.
func tries(proto Protocol, shape Shape) (int, time.Duration) {
	switch proto {
	case ProtocolLLMNR:
		return shape.LLMNRTries, shape.LLMNRRetryGap
	case ProtocolNBNS:
		return shape.NBNSTries, shape.NBNSRetryGap
	case ProtocolMDNS:
		return shape.MDNSTries, shape.MDNSRetryGap
	default:
		return 0, 0
	}
}

// querySocket is one socket a burst asks from, together with where its
// questions go.
type querySocket struct {
	conn *net.UDPConn
	to   *net.UDPAddr
}

// openQuerySockets opens the sockets one protocol's lookup needs: the IPv4
// one always, and the IPv6 twin when the profile asks for it and the
// segment has an IPv6 address to send from.
//
// Every socket is opened fresh per lookup and closed when the lookup is
// done. That is deliberate rather than wasteful: a long-lived socket on a
// fixed ephemeral port would be one more thing about this host that stays
// the same between lookups, and an ephemeral port that changes is what a
// real client's successive lookups look like.
func openQuerySockets(proto Protocol, seg segment, shape Shape) ([]querySocket, error) {
	switch proto {
	case ProtocolLLMNR:
		return openMulticastSockets(llmnrGroupV4, llmnrGroupV6, LLMNRPort, llmnrMulticastTTL, seg, shape)
	case ProtocolMDNS:
		return openMulticastSockets(mdnsGroupV4, mdnsGroupV6, MDNSPort, mdnsMulticastTTL, seg, shape)
	case ProtocolNBNS:
		sock, err := openNBNSSocket(seg)
		if err != nil {
			return nil, err
		}
		return []querySocket{sock}, nil
	default:
		return nil, fmt.Errorf("poisoner: no socket for protocol %q", proto)
	}
}

// openMulticastSockets opens the LLMNR or mDNS query sockets: an ephemeral
// local port, the protocol's multicast TTL, and multicast loopback off so
// the pace-matcher never counts this canary's own questions.
func openMulticastSockets(groupV4, groupV6 net.IP, port, ttl int, seg segment, shape Shape) ([]querySocket, error) {
	var out []querySocket

	v4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: seg.IP, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("poisoner: open an IPv4 query socket: %w", err)
	}
	if err := setMulticastTTLv4(v4, ttl); err != nil {
		_ = v4.Close()
		return nil, err
	}
	out = append(out, querySocket{conn: v4, to: &net.UDPAddr{IP: groupV4, Port: port}})

	if !shape.QueryIPv6 || !seg.HasIPv6 || groupV6 == nil {
		return out, nil
	}
	v6, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 0})
	if err != nil {
		// No IPv6 here after all. The IPv4 half is a complete lookup on
		// its own, so this is not a failure worth returning.
		return out, nil
	}
	if err := setMulticastHopsV6(v6, ttl); err != nil {
		_ = v6.Close()
		return out, nil
	}
	out = append(out, querySocket{conn: v6, to: &net.UDPAddr{IP: groupV6, Port: port}})
	return out, nil
}

// openNBNSSocket opens the one socket in this package that has to bind a
// fixed low port: NBT-NS queries are sent from port 137, and a query from
// an ephemeral port instead is one of the giveaways issue #86's research
// note lists.
//
// It binds the interface's own unicast address rather than the wildcard, so
// it can share port 137 with the pace-matcher's wildcard listener: Linux
// then sends the unicast reply to our query here, and the segment's
// broadcast queries to the listener. Both sockets set SO_REUSEADDR, which
// is what makes the pair bindable at all.
func openNBNSSocket(seg segment) (querySocket, error) {
	if seg.IP == nil || seg.Broadcast == nil {
		return querySocket{}, errNoSegment
	}
	lc := net.ListenConfig{Control: controlSetReuseAddr}
	pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(seg.IP.String(), fmt.Sprint(NBNSPort)))
	if err != nil {
		return querySocket{}, fmt.Errorf("poisoner: bind %d to send NBT-NS from: %w", NBNSPort, err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return querySocket{}, errors.New("poisoner: NBT-NS socket is not a UDP connection")
	}
	if err := setTTLv4(conn, nbnsBroadcastTTL); err != nil {
		_ = conn.Close()
		return querySocket{}, err
	}
	return querySocket{conn: conn, to: &net.UDPAddr{IP: seg.Broadcast, Port: NBNSPort}}, nil
}

// lookup makes one bait lookup: it sends the protocol's questions the
// shape's number of times, then listens on the query sockets for
// replyWindow and returns every answer it heard.
//
// An answer is a hit. There is nothing to decide about it here -- the bait
// name does not exist, so the only correct response was silence.
func lookup(ctx context.Context, proto Protocol, name string, seg segment, shape Shape, r *rand.Rand, arpPath string) ([]Answer, error) {
	questions, err := buildQuestions(proto, name, shape, r)
	if err != nil {
		return nil, err
	}
	count, gap := tries(proto, shape)
	if count <= 0 || len(questions) == 0 {
		return nil, fmt.Errorf("poisoner: profile asks nothing on %s", proto)
	}

	sockets, err := openQuerySockets(proto, seg, shape)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, s := range sockets {
			_ = s.conn.Close()
		}
	}()

	record := asked{name: name, proto: proto, ids: make(map[uint16]struct{}, len(questions))}
	for _, q := range questions {
		record.ids[q.id] = struct{}{}
	}

	for try := 0; try < count; try++ {
		if try > 0 && !sleepCtx(ctx, gap) {
			return nil, ctx.Err()
		}
		for _, sock := range sockets {
			for _, q := range questions {
				if _, err := sock.conn.WriteToUDP(q.datagram, sock.to); err != nil {
					// One socket failing -- no route for the IPv6 twin,
					// most likely -- must not abandon the lookup on the
					// other. The reply loop below reports nothing, which
					// is the same as silence, and the caller's own
					// counters show the burst happened.
					continue
				}
			}
		}
	}

	return collectAnswers(ctx, sockets, record, arpPath, replyWindow)
}

// collectAnswers reads the query sockets until replyWindow expires,
// returning one Answer per distinct answering host.
//
// One per host, not one per datagram: a poisoner answers both the A and the
// AAAA question, and both retries of each, so a single attacker would
// otherwise produce four or six identical alerts from one lookup.
// window is how long to listen, a parameter rather than replyWindow directly
// so a test can prove the "nothing answered" path without waiting the real
// window out.
func collectAnswers(ctx context.Context, sockets []querySocket, record asked, arpPath string, window time.Duration) ([]Answer, error) {
	deadline := time.Now().Add(window)
	seen := make(map[string]struct{})
	var out []Answer
	buf := make([]byte, MaxDatagramLen)

	for _, sock := range sockets {
		local, localPort := localAddr(sock.conn)
		for {
			if ctx.Err() != nil {
				return out, nil
			}
			left := time.Until(deadline)
			if left <= 0 {
				break
			}
			if err := sock.conn.SetReadDeadline(time.Now().Add(left)); err != nil {
				break
			}
			n, src, err := sock.conn.ReadFromUDP(buf)
			if err != nil {
				// A timeout is the expected outcome: nothing answered,
				// which is what a healthy segment does.
				break
			}
			r, err := parseReplyFor(record.proto, buf[:n])
			if err != nil || !record.matches(r) {
				// Malformed, or not an answer to this lookup. Dropped
				// quietly: a log line per bad datagram on a port an
				// attacker can aim at would be the denial of service.
				continue
			}
			host := src.IP.String()
			if _, already := seen[host]; already {
				continue
			}
			seen[host] = struct{}{}
			out = append(out, Answer{
				Source:     host,
				SourcePort: src.Port,
				Protocol:   record.proto,
				Name:       record.name,
				MAC:        lookupMAC(arpPath, host),
				Local:      local,
				LocalPort:  localPort,
			})
		}
	}
	return out, nil
}

// parseReplyFor picks the parser a protocol's replies need.
func parseReplyFor(proto Protocol, b []byte) (reply, error) {
	if proto == ProtocolNBNS {
		return parseNBNSReply(b)
	}
	return parseDNSReply(b)
}

// localAddr reads a socket's own bound address, for the event's dst_host
// and dst_port -- the same fields, filled the same way, as
// internal/agent/snmp's emit.
//
// A nil connection yields an empty address rather than a panic: a test that
// exercises Detector.observe directly, without Open, has no socket, and that
// is not a programming error worth crashing the honeypot over -- the same
// call internal/agent/snmp's emit makes for the same reason.
func localAddr(conn *net.UDPConn) (string, int) {
	if conn == nil {
		return "", 0
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", 0
	}
	return local.IP.String(), local.Port
}

// sleepCtx waits for d, returning false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
