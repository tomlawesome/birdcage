package poisoner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// quietLogger is a logger that discards everything, for the tests that do not
// care what was logged. The ones that do care use captureLogger.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// captureLogger returns a logger writing into a buffer, and the buffer.
func captureLogger() (*slog.Logger, *strings.Builder) {
	var sb strings.Builder
	return slog.New(slog.NewTextHandler(&sb, &slog.HandlerOptions{Level: slog.LevelDebug})), &sb
}

// writeConf writes an OpenCanary configuration with the given node id and
// returns its path.
func writeConf(t *testing.T, nodeID string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opencanary.conf")
	body, err := json.Marshal(map[string]any{"device.node_id": nodeID})
	if err != nil {
		t.Fatalf("marshal the configuration: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write the configuration: %v", err)
	}
	return path
}

// collect returns a Submit that records every message, and the slice it
// records into.
func collect() (Submit, *[][]byte, *sync.Mutex) {
	var mu sync.Mutex
	var got [][]byte
	return func(message []byte) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, append([]byte(nil), message...))
		return nil
	}, &got, &mu
}

// TestNewSettlesTheProfileNamesAndPacing covers what New decides before any
// socket exists.
func TestNewSettlesTheProfileNamesAndPacing(t *testing.T) {
	submit, _, _ := collect()
	d, warnings := New(Config{
		ConfPath: writeConf(t, "fs-lon-05"),
		Hostname: "fs-lon-05",
		Now:      func() time.Time { return base },
	}, submit, quietLogger())
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if d.Profile() != DefaultProfile {
		t.Errorf("profile = %q, want the default %q", d.Profile(), DefaultProfile)
	}
	// Two derived neighbours plus wpad.
	if got := d.NameCount(); got != derivedNameCount+1 {
		t.Errorf("NameCount = %d, want %d", got, derivedNameCount+1)
	}
	if d.pace.FloorGap != DefaultFloorGap || d.pace.CeilingGap != DefaultCeilingGap {
		t.Errorf("pacing = %+v, want the defaults", d.pace)
	}
	if !d.names.contains(WPADName) {
		t.Errorf("the rotation does not include %q", WPADName)
	}
	// The canary's own name is never one it asks for.
	if d.names.contains("fs-lon-05") {
		t.Error("the rotation includes the canary's own hostname")
	}
}

// TestNewWarnsRatherThanFailing is the contract portscan.New and snmp.New
// state and this one repeats: everything the caller has to carry on past is a
// warning, not an error, because a canary that will not start reports
// nothing at all.
func TestNewWarnsRatherThanFailing(t *testing.T) {
	submit, _, _ := collect()

	t.Run("unreadable configuration", func(t *testing.T) {
		d, warnings := New(Config{
			ConfPath: filepath.Join(t.TempDir(), "absent.conf"),
			Hostname: "fs-lon-05",
		}, submit, quietLogger())
		if len(warnings) == 0 {
			t.Fatal("no warning for an unreadable configuration")
		}
		if d.nodeID != DefaultNodeID {
			t.Errorf("node id = %q, want the fallback %q", d.nodeID, DefaultNodeID)
		}
		// The warning has to say why it matters, not just that it happened:
		// two canaries sharing a node id share a rhythm.
		if !strings.Contains(warnings[0], "timing") && !strings.Contains(warnings[0], "names") {
			t.Errorf("the warning does not say what the fallback costs: %q", warnings[0])
		}
	})

	t.Run("hostname nothing can be derived from", func(t *testing.T) {
		d, warnings := New(Config{
			ConfPath: writeConf(t, "canary"),
			Hostname: "fileserver",
		}, submit, quietLogger())
		if len(warnings) == 0 {
			t.Fatal("no warning for a hostname with no trailing number")
		}
		if d.NameCount() != 1 {
			t.Errorf("NameCount = %d, want 1 (wpad alone)", d.NameCount())
		}
	})
}

// TestNewNeverPutsABaitNameInAWarning is this package's absolute rule: the
// bait only works while nobody knows which names it uses, and this binary's
// stdout is readable by whoever breaks into the box.
func TestNewNeverPutsABaitNameInAWarning(t *testing.T) {
	submit, _, _ := collect()
	operator, _, err := ParseNames("old-fs-01,printer-7")
	if err != nil {
		t.Fatalf("ParseNames: %v", err)
	}
	d, warnings := New(Config{
		ConfPath:      filepath.Join(t.TempDir(), "absent.conf"),
		Hostname:      "fileserver",
		OperatorNames: operator,
	}, submit, quietLogger())

	joined := strings.Join(warnings, " ")
	for _, name := range d.names {
		if name == WPADName {
			// wpad is a protocol name, not the operator's, and it is in this
			// package's own source anyway.
			continue
		}
		if strings.Contains(joined, name) {
			t.Errorf("a warning names the bait name %q: %q", name, joined)
		}
	}
}

// TestObserveCountsQueriesAndCatchesAnswers exercises the counting socket's
// two jobs at once: a query from another host is a pace sample, and a
// response naming a bait name is a hit -- which is how a poisoner that
// answers by multicast rather than unicast is caught.
func TestObserveCountsQueriesAndCatchesAnswers(t *testing.T) {
	submit, got, mu := collect()
	arp := writeARP(t, arpFixture)
	d, _ := New(Config{
		ConfPath: writeConf(t, "canary"),
		Hostname: "fs-lon-05",
		ARPPath:  arp,
		Now:      func() time.Time { return base },
	}, submit, quietLogger())
	// A known rotation, so the test does not depend on what was derived.
	d.names = Names{"fs-lon-02", WPADName}

	l := listener{proto: ProtocolLLMNR, port: LLMNRPort, conn: nil}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 66), Port: LLMNRPort}

	// Another host's query: counted, never an alert.
	query, err := encodeLLMNRQuery(0x1111, "someone-elses-host", typeA)
	if err != nil {
		t.Fatalf("encodeLLMNRQuery: %v", err)
	}
	d.observe(l, query, src)
	if queries, hosts := d.counter.Median(base); queries != 1 || hosts != 1 {
		t.Errorf("after one query, Median = (%d, %d), want (1, 1)", queries, hosts)
	}
	mu.Lock()
	alerts := len(*got)
	mu.Unlock()
	if alerts != 0 {
		t.Fatalf("another host's query produced %d alerts", alerts)
	}

	// A response for a bait name: an alert, and not counted as a query.
	answer := dnsResponse(0x2222, []byte{
		0x09, 'f', 's', '-', 'l', 'o', 'n', '-', '0', '2', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}, 1)
	d.observe(l, answer, src)
	mu.Lock()
	alerts = len(*got)
	var raw []byte
	if alerts > 0 {
		raw = (*got)[0]
	}
	mu.Unlock()
	if alerts != 1 {
		t.Fatalf("a response for a bait name produced %d alerts, want 1", alerts)
	}
	if queries, _ := d.counter.Median(base); queries != 1 {
		t.Errorf("the response was counted as a query: median is now %d", queries)
	}

	var out struct {
		SrcHost string `json:"src_host"`
		LogData struct {
			MAC      string `json:"MAC"`
			NAME     string `json:"NAME"`
			PROTOCOL string `json:"PROTOCOL"`
		} `json:"logdata"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the alert does not parse: %v", err)
	}
	if out.SrcHost != "10.0.0.66" || out.LogData.NAME != "fs-lon-02" ||
		out.LogData.PROTOCOL != string(ProtocolLLMNR) || out.LogData.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("alert = %+v, want the answering address, name, protocol and MAC", out)
	}
	if d.Answers() != 1 {
		t.Errorf("Answers() = %d, want 1", d.Answers())
	}
}

// TestObserveIgnoresAResponseForAnotherName proves the listener path is not a
// blanket "any response is a hit": a real mDNS response for a real host on
// the segment must not raise an alert.
func TestObserveIgnoresAResponseForAnotherName(t *testing.T) {
	submit, got, mu := collect()
	d, _ := New(Config{ConfPath: writeConf(t, "canary"), Hostname: "fs-lon-05", Now: func() time.Time { return base }}, submit, quietLogger())
	d.names = Names{"fs-lon-02", WPADName}

	l := listener{proto: ProtocolMDNS, port: MDNSPort}
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 20), Port: MDNSPort}

	for _, tc := range []struct {
		name     string
		question []byte
		answers  uint16
	}{
		{
			name: "a real host on the segment",
			question: []byte{
				0x07, 'p', 'r', 'i', 'n', 't', 'e', 'r', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
				0x00, 0x01, 0x00, 0x01,
			},
			answers: 1,
		},
		{
			// A response naming a bait name but carrying no answer record
			// is not an answer -- it is the silence this detector expects.
			name: "no answer records",
			question: []byte{
				0x09, 'f', 's', '-', 'l', 'o', 'n', '-', '0', '2', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
				0x00, 0x01, 0x00, 0x01,
			},
			answers: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.observe(l, dnsResponse(1, tc.question, tc.answers), src)
			mu.Lock()
			alerts := len(*got)
			mu.Unlock()
			if alerts != 0 {
				t.Errorf("%d alerts raised", alerts)
			}
		})
	}
}

// TestObserveDropsAShortDatagram covers the guard before the flags word is
// read, which is the only place a datagram shorter than a header could reach.
func TestObserveDropsAShortDatagram(t *testing.T) {
	submit, got, mu := collect()
	d, _ := New(Config{ConfPath: writeConf(t, "canary"), Hostname: "fs-lon-05", Now: func() time.Time { return base }}, submit, quietLogger())
	d.observe(listener{proto: ProtocolLLMNR}, []byte{0x00, 0x01}, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1)})
	mu.Lock()
	alerts := len(*got)
	mu.Unlock()
	if alerts != 0 {
		t.Errorf("a two-byte datagram produced %d alerts", alerts)
	}
	if queries, _ := d.counter.Median(base); queries != 0 {
		t.Errorf("a two-byte datagram was counted as a query: median %d", queries)
	}
}

// TestEmitLogsTheAddressAndNothingElse is the log rule, proved on the one
// line this package writes when it catches something.
func TestEmitLogsTheAddressAndNothingElse(t *testing.T) {
	log, buf := captureLogger()
	submit, _, _ := collect()
	d, _ := New(Config{ConfPath: writeConf(t, "canary"), Hostname: "fs-lon-05", Now: func() time.Time { return base }}, submit, log)

	d.emit(Answer{Source: "10.0.0.66", SourcePort: 5355, Protocol: ProtocolLLMNR, Name: "fs-lon-02", MAC: "aa:bb:cc:dd:ee:ff"})

	line := buf.String()
	if !strings.Contains(line, "10.0.0.66") {
		t.Errorf("the log line does not name the answering address: %q", line)
	}
	// The address is the attacker's own, so naming it tells them nothing.
	// The bait name is the one thing they must not learn from this box.
	if strings.Contains(line, "fs-lon-02") {
		t.Errorf("the log line names the bait name: %q", line)
	}
	if strings.Contains(line, "aa:bb:cc:dd:ee:ff") {
		t.Errorf("the log line names the MAC, which belongs in the event: %q", line)
	}
}

// TestCollectAnswersCatchesAFakePoisoner is the end-to-end catch, on
// loopback: a socket that answers a bait query the way Responder does --
// unicast, back to the querier's own port -- and the Answer that comes out of
// it carries every fact the alert needs.
//
// It uses collectAnswers directly with a loopback query socket rather than
// going through lookup, because lookup sends to a multicast group from a
// privileged port and a unit test must not need either (see
// build/mockingbird/Dockerfile's --sysctl note).
func TestCollectAnswersCatchesAFakePoisoner(t *testing.T) {
	// The canary's query socket.
	ours, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("open the query socket: %v", err)
	}
	defer func() { _ = ours.Close() }()

	// The poisoner, answering the LLMNR query's transaction id.
	poisonerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("open the poisoner's socket: %v", err)
	}
	defer func() { _ = poisonerConn.Close() }()

	const id = 0x4d2
	answer := dnsResponse(id, []byte{
		0x09, 'f', 's', '-', 'l', 'o', 'n', '-', '0', '2', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}, 1)
	// Responder answers immediately, twice over (once per address family).
	// Two identical answers must become one alert.
	for i := 0; i < 2; i++ {
		if _, err := poisonerConn.WriteToUDP(answer, ours.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("the poisoner could not answer: %v", err)
		}
	}

	record := asked{name: "fs-lon-02", proto: ProtocolLLMNR, ids: map[uint16]struct{}{id: {}}}
	sockets := []querySocket{{conn: ours}}
	answers, err := collectAnswers(context.Background(), sockets, record, writeARP(t, arpFixture), replyWindow)
	if err != nil {
		t.Fatalf("collectAnswers: %v", err)
	}
	if len(answers) != 1 {
		t.Fatalf("got %d answers, want 1 -- a poisoner answering twice must be one alert", len(answers))
	}
	a := answers[0]
	if a.Source != "127.0.0.1" {
		t.Errorf("Source = %q, want 127.0.0.1", a.Source)
	}
	if a.Protocol != ProtocolLLMNR {
		t.Errorf("Protocol = %q, want %q", a.Protocol, ProtocolLLMNR)
	}
	// The name comes from the agent's own record, not from the reply.
	if a.Name != "fs-lon-02" {
		t.Errorf("Name = %q, want the bait name this agent asked for", a.Name)
	}
	if a.LocalPort != ours.LocalAddr().(*net.UDPAddr).Port {
		t.Errorf("LocalPort = %d, want the query socket's own port", a.LocalPort)
	}
}

// TestCollectAnswersIgnoresSomethingElsesReply proves the transaction-id
// match is doing work: a response with an id this agent never minted, for a
// name it never asked, is not a hit.
func TestCollectAnswersIgnoresSomethingElsesReply(t *testing.T) {
	ours, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("open the query socket: %v", err)
	}
	defer func() { _ = ours.Close() }()

	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("open the second socket: %v", err)
	}
	defer func() { _ = other.Close() }()

	stray := dnsResponse(0x9999, []byte{
		0x07, 'p', 'r', 'i', 'n', 't', 'e', 'r', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}, 1)
	if _, err := other.WriteToUDP(stray, ours.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send the stray reply: %v", err)
	}
	// And a malformed one, which must be dropped rather than alerted on.
	if _, err := other.WriteToUDP([]byte{0xff}, ours.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send the malformed reply: %v", err)
	}

	record := asked{name: "fs-lon-02", proto: ProtocolLLMNR, ids: map[uint16]struct{}{0x4d2: {}}}
	// A short window: the claim is that nothing here matches, not that the
	// full two seconds elapse.
	answers, err := collectAnswers(context.Background(), []querySocket{{conn: ours}}, record, "", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("collectAnswers: %v", err)
	}
	if len(answers) != 0 {
		t.Errorf("got %d answers, want none: %+v", len(answers), answers)
	}
}

// TestCollectAnswersStopsWhenCancelled proves the reply window does not hold
// shutdown up.
func TestCollectAnswersStopsWhenCancelled(t *testing.T) {
	ours, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("open the query socket: %v", err)
	}
	defer func() { _ = ours.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := collectAnswers(ctx, []querySocket{{conn: ours}}, asked{proto: ProtocolLLMNR}, "", replyWindow); err != nil {
		t.Fatalf("collectAnswers: %v", err)
	}
	if took := time.Since(start); took > replyWindow/2 {
		t.Errorf("a cancelled context still waited %v", took)
	}
}

// TestBuildQuestionsAsksBothAddressFamilies is the shape claim a capture
// would check: an LLMNR lookup asks A and AAAA, with a distinct transaction
// id each, and an mDNS lookup asks both with the zero id RFC 6762 requires.
func TestBuildQuestionsAsksBothAddressFamilies(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	shape := ProfileWindows.Shape()

	llmnr, err := buildQuestions(ProtocolLLMNR, "fs-lon-02", shape, r)
	if err != nil {
		t.Fatalf("buildQuestions(llmnr): %v", err)
	}
	if len(llmnr) != 2 {
		t.Fatalf("an LLMNR lookup built %d questions, want 2 (A and its AAAA twin)", len(llmnr))
	}
	if llmnr[0].id == llmnr[1].id {
		t.Error("the A and AAAA questions share a transaction id")
	}

	mdns, err := buildQuestions(ProtocolMDNS, "fs-lon-02", shape, r)
	if err != nil {
		t.Fatalf("buildQuestions(mdns): %v", err)
	}
	if len(mdns) != 2 {
		t.Fatalf("an mDNS lookup built %d questions, want 2", len(mdns))
	}
	for i, q := range mdns {
		if q.id != mdnsQueryID {
			t.Errorf("mDNS question %d has id %#x, want zero (RFC 6762 18.1)", i, q.id)
		}
	}

	nbns, err := buildQuestions(ProtocolNBNS, "fs-lon-02", shape, r)
	if err != nil {
		t.Fatalf("buildQuestions(nbns): %v", err)
	}
	if len(nbns) != 1 {
		t.Errorf("a NBT-NS lookup built %d questions, want 1", len(nbns))
	}

	if _, err := buildQuestions("smtp", "fs-lon-02", shape, r); err == nil {
		t.Error("buildQuestions accepted a protocol it has no encoder for")
	}
}

// TestAskedMatches covers the reply-matching rule for both protocol
// families, including the reason mDNS cannot use the transaction id.
func TestAskedMatches(t *testing.T) {
	record := asked{name: "fs-lon-02", proto: ProtocolLLMNR, ids: map[uint16]struct{}{0x4d2: {}}}
	tests := []struct {
		name string
		r    reply
		want bool
	}{
		{name: "our id, an answer", r: reply{ID: 0x4d2, Name: "anything", Answers: 1}, want: true},
		{name: "our id, no answer", r: reply{ID: 0x4d2, Name: "fs-lon-02", Answers: 0}, want: false},
		{name: "our name, another id", r: reply{ID: 0x999, Name: "fs-lon-02", Answers: 1}, want: true},
		{name: "neither", r: reply{ID: 0x999, Name: "printer", Answers: 1}, want: false},
		// The zero id is every mDNS querier's, so it proves nothing on its
		// own: the name has to carry the match.
		{name: "the zero id alone", r: reply{ID: mdnsQueryID, Name: "printer", Answers: 1}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := record.matches(tc.r); got != tc.want {
				t.Errorf("matches(%+v) = %v, want %v", tc.r, got, tc.want)
			}
		})
	}

	// An mDNS record, whose ids are all the zero one.
	mdns := asked{name: "wpad", proto: ProtocolMDNS, ids: map[uint16]struct{}{mdnsQueryID: {}}}
	if !mdns.matches(reply{ID: mdnsQueryID, Name: "wpad", Answers: 1}) {
		t.Error("an mDNS answer naming the bait name was not matched")
	}
	if mdns.matches(reply{ID: mdnsQueryID, Name: "printer", Answers: 1}) {
		t.Error("an mDNS answer for another name was matched")
	}
}

// TestOffProfileSendsNothing is decision 41's third value: no bait queries,
// and therefore no detection, but the pace-matcher still runs.
func TestOffProfileSendsNothing(t *testing.T) {
	submit, _, _ := collect()
	d, _ := New(Config{
		Profile:  ProfileOff,
		ConfPath: writeConf(t, "canary"),
		Hostname: "fs-lon-05",
	}, submit, quietLogger())
	if len(d.shape.Protocols) != 0 {
		t.Errorf("the off profile would send on %v", d.shape.Protocols)
	}

	warnings, err := d.Open()
	if err != nil {
		t.Skipf("no socket could be opened on this host: %v (warnings: %v)", err, warnings)
	}
	defer func() {
		// Open leaves the listeners bound; Run is what closes them, so close
		// them here instead.
		for _, l := range d.listeners {
			_ = l.conn.Close()
		}
	}()
	if d.CanSend() {
		t.Error("CanSend() is true for the off profile")
	}
	// The pace-matcher runs in all three profiles (decision 41), so at least
	// one counting socket must have opened -- or the host refused all three,
	// which is a skip rather than a failure.
	if d.Listening() == 0 {
		t.Skipf("this host bound none of the three low ports: %v", warnings)
	}
	// A run with nothing to send still returns cleanly when cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := d.Run(ctx); err != nil {
		t.Errorf("Run: %v", err)
	}
	if d.Bursts() != 0 {
		t.Errorf("the off profile made %d bursts", d.Bursts())
	}
}

// TestRunBeforeOpenIsReported is the contract portscan.Run and snmp.Run
// state: calling Run without a successful Open is a programming error,
// reported rather than papered over.
func TestRunBeforeOpenIsReported(t *testing.T) {
	submit, _, _ := collect()
	d, _ := New(Config{ConfPath: writeConf(t, "canary"), Hostname: "fs-lon-05"}, submit, quietLogger())
	if err := d.Run(context.Background()); err == nil {
		t.Fatal("Run before Open returned no error")
	}
}

// TestPaceReportSaysWhereTheRateCameFrom is what the startup line and #121's
// later measurement read.
func TestPaceReportSaysWhereTheRateCameFrom(t *testing.T) {
	submit, _, _ := collect()
	now := base
	d, _ := New(Config{
		ConfPath: writeConf(t, "canary"),
		Hostname: "fs-lon-05",
		Pace:     PaceSettings{FloorGap: 24 * time.Hour, CeilingGap: time.Second, Hours: AllHours()},
		Now:      func() time.Time { return now },
	}, submit, quietLogger())

	quiet := d.Pace()
	if quiet.Matched {
		t.Error("a silent segment reported a matched rate")
	}
	if quiet.Gap != d.pace.FloorGap {
		t.Errorf("a silent segment's gap is %v, want the floor %v", quiet.Gap, d.pace.FloorGap)
	}

	for _, host := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		for i := 0; i < 70; i++ {
			d.counter.Observe(host, now)
		}
	}
	busy := d.Pace()
	if !busy.Matched {
		t.Error("a segment with four talking hosts did not match")
	}
	if busy.Hosts != 4 || busy.MedianQueries != 70 {
		t.Errorf("report = %+v, want 4 hosts at a median of 70", busy)
	}
	if busy.Gap >= quiet.Gap {
		t.Errorf("a busy segment's gap %v is not shorter than a quiet one's %v", busy.Gap, quiet.Gap)
	}
}

// TestWaitForWorkingHoursReturnsImmediatelyInHours and its cancelled twin
// cover the gate that keeps a canary from asking at three in the morning.
func TestWaitForWorkingHoursReturnsImmediatelyInHours(t *testing.T) {
	submit, _, _ := collect()
	inHours := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC) // a Wednesday
	d, _ := New(Config{
		ConfPath: writeConf(t, "canary"),
		Hostname: "fs-lon-05",
		Now:      func() time.Time { return inHours },
	}, submit, quietLogger())

	start := time.Now()
	if !d.waitForWorkingHours(context.Background()) {
		t.Fatal("waitForWorkingHours refused a time inside the window")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("waiting inside the window took %v", took)
	}

	// Outside the window, a cancelled context gets out rather than sleeping
	// until morning.
	night := time.Date(2026, 9, 23, 3, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return night }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if d.waitForWorkingHours(ctx) {
		t.Error("waitForWorkingHours ignored a cancelled context")
	}
}

// TestLookupOnceRefusesWhenNothingToSendFrom covers the three ways a
// self-test's bait probe can have nowhere to go. All three must be an
// error rather than an empty answer list, because an empty list means
// "asked, and nothing answered" -- the self-test's PASS -- and a canary
// that never asked must never report that.
func TestLookupOnceRefusesWhenNothingToSendFrom(t *testing.T) {
	submit, _, _ := collect()

	t.Run("a nil detector", func(t *testing.T) {
		// The road off. A caller holding this in an interface cannot spot
		// it by comparing against nil, so the method has to.
		var d *Detector
		if _, err := d.LookupOnce(context.Background(), "", ""); !errors.Is(err, ErrNotSending) {
			t.Errorf("err = %v, want ErrNotSending", err)
		}
	})

	t.Run("the off profile", func(t *testing.T) {
		d, _ := New(Config{Profile: ProfileOff, ConfPath: writeConf(t, "canary"), Hostname: "fs-lon-05"}, submit, quietLogger())
		if _, err := d.LookupOnce(context.Background(), "", ""); !errors.Is(err, ErrNotSending) {
			t.Errorf("err = %v, want ErrNotSending", err)
		}
	})

	t.Run("open never found a segment", func(t *testing.T) {
		d, _ := New(Config{ConfPath: writeConf(t, "canary"), Hostname: "fs-lon-05"}, submit, quietLogger())
		// canSend is only set by Open; a detector that never opened has
		// nothing to send from.
		if _, err := d.LookupOnce(context.Background(), "", ""); !errors.Is(err, ErrNotSending) {
			t.Errorf("err = %v, want ErrNotSending", err)
		}
	})
}

// TestLookupOnceRefusesAProtocolTheProfileDoesNotUse: a self-test that
// claimed to have asked over NBT-NS while actually asking over mDNS would
// be proving the wrong thing, so the substitution is refused rather than
// made silently.
func TestLookupOnceRefusesAProtocolTheProfileDoesNotUse(t *testing.T) {
	submit, _, _ := collect()
	d, _ := New(Config{Profile: ProfileLinux, ConfPath: writeConf(t, "canary"), Hostname: "fs-lon-05"}, submit, quietLogger())
	// Pretend Open succeeded, so the refusal under test is the protocol
	// one rather than ErrNotSending.
	d.canSend = true

	if _, err := d.LookupOnce(context.Background(), ProtocolNBNS, "fs-lon-02"); err == nil {
		t.Error("the linux profile accepted a NBT-NS lookup")
	} else if errors.Is(err, ErrNotSending) {
		t.Errorf("err = %v, want a protocol refusal", err)
	}
	// And an unusable name is refused before anything is sent.
	if _, err := d.LookupOnce(context.Background(), ProtocolLLMNR, "bad_name"); err == nil {
		t.Error("an unusable bait name was accepted")
	}
}
