package probe

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// listenOneUDPDatagram starts a UDP listener and returns its port plus
// a channel carrying the first datagram it receives.
func listenOneUDPDatagram(t *testing.T) (port int, pktCh <-chan []byte) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ch := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		ch <- append([]byte(nil), buf[:n]...)
	}()

	_, portStr, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port, ch
}

func recvOrFail(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case pkt := <-ch:
		return pkt
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the datagram")
		return nil
	}
}

func TestProbeSNMP_PlantsMarkerAsCommunityString(t *testing.T) {
	port, pktCh := listenOneUDPDatagram(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeSNMP(ctx, "127.0.0.1", port, "marker-snmp"); err != nil {
		t.Fatalf("probeSNMP: %v", err)
	}

	pkt := recvOrFail(t, pktCh)
	// The community string is BER-encoded as an OCTET STRING (tag
	// 0x04) whose content is the marker; asserting on tag+length+value
	// together avoids a false match against marker bytes appearing
	// elsewhere by coincidence.
	want := append([]byte{0x04, byte(len("marker-snmp"))}, []byte("marker-snmp")...)
	if !bytes.Contains(pkt, want) {
		t.Errorf("packet % x does not contain the community-string TLV % x", pkt, want)
	}
}

func TestProbeTFTP_PlantsMarkerAsFilename(t *testing.T) {
	port, pktCh := listenOneUDPDatagram(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeTFTP(ctx, "127.0.0.1", port, "marker-tftp"); err != nil {
		t.Fatalf("probeTFTP: %v", err)
	}

	pkt := recvOrFail(t, pktCh)
	if pkt[0] != 0x00 || pkt[1] != 0x01 {
		t.Fatalf("opcode = % x, want RRQ (00 01)", pkt[:2])
	}
	if !bytes.HasPrefix(pkt[2:], []byte("marker-tftp\x00")) {
		t.Errorf("packet %q does not open with the marker as filename", pkt[2:])
	}
	if !bytes.HasSuffix(pkt, []byte("octet\x00")) {
		t.Errorf("packet %q does not end with the octet mode", pkt)
	}
}

func TestProbeSIP_PlantsMarkerInFromHeader(t *testing.T) {
	port, pktCh := listenOneUDPDatagram(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeSIP(ctx, "127.0.0.1", port, "marker-sip"); err != nil {
		t.Fatalf("probeSIP: %v", err)
	}

	pkt := string(recvOrFail(t, pktCh))
	if !strings.Contains(pkt, "From: <sip:marker-sip@") {
		t.Errorf("request %q does not carry the marker in its From header", pkt)
	}
}
