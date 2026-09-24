package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/event"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
	"github.com/tomlawesome/birdcage/internal/agent/smbaudit"
	"github.com/tomlawesome/birdcage/internal/agent/tailer"
)

// capturedAuditLines is what the real build/smb-lure image wrote into
// /audit/smb.log on 2026-09-23 while a real smbclient fetched one file:
// the start-up banner and its continuation line, then the closes for the
// share root, the directory and the file itself.
//
// The three closes are one visit, so they are one alert (#123). The number
// every test below waits for is that one, not the three lines.
var capturedAuditLines = []string{
	`[2026/09/23 21:59:09.210719,  0]   smbd version 4.23.8 started.`,
	`  Copyright Andrew Tridgell and the Samba Team 1992-2025`,
	`[2026/09/23 22:01:53.984095,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
	`[2026/09/23 22:01:53.984907,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT`,
	`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
}

// newTestSMBRoad builds a road over a fresh audit file in a fresh state
// directory, and returns the road, the audit file's path and the state
// directory.
func newTestSMBRoad(t *testing.T, in *Intake) (*smbAuditRoad, string, string) {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "smb.log")
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	t.Setenv(envSMBAuditPath, auditPath)
	// Nothing in the test environment has an OpenCanary configuration, so
	// the road falls back to the default node id -- which is what a
	// canary whose configuration is unreadable does too.
	t.Setenv(envOpenCanaryConf, filepath.Join(dir, "no-such-opencanary.conf"))

	road, inv := newSMBAuditRoad(Config{StateDir: stateDir}, in, discardLogger())
	if road == nil {
		t.Fatal("newSMBAuditRoad returned no road with an audit file configured")
	}
	if !inv.Active {
		t.Error("the inventory says the road is off with an audit file configured")
	}
	return road, auditPath, stateDir
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open audit file: %v", err)
	}
	defer func() { _ = f.Close() }()
	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatalf("write audit line: %v", err)
		}
	}
}

// runRoadUntil runs the road until want events are queued, or the
// deadline passes, then cancels and waits for it to stop.
func runRoadUntil(t *testing.T, road *smbAuditRoad, in *Intake, want int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSMBAuditRoad(ctx, road, discardLogger())
	}()

	deadline := time.Now().Add(5 * time.Second)
	for in.Queue.Depth() < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// TestSMBAuditRoadOffWhenUnset: a canary deployed without the lure has no
// audit file to read, and that is not a fault -- no road, and the one
// startup line says so.
func TestSMBAuditRoadOffWhenUnset(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})
	t.Setenv(envSMBAuditPath, "")

	road, inv := newSMBAuditRoad(Config{StateDir: t.TempDir()}, in, discardLogger())
	if road != nil {
		t.Error("a road was built with no audit file configured")
	}
	if inv.Active {
		t.Error("the inventory says the road is active with no audit file configured")
	}
	if got := inv.line(); got != "smb audit road off" {
		t.Errorf("startup line = %q", got)
	}
	if got := (smbAuditInventory{Active: true}).line(); got != "smb audit road active" {
		t.Errorf("active startup line = %q", got)
	}

	// And running a nil road is a no-op rather than a panic, which is
	// what lets main start the same goroutine either way.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runSMBAuditRoad(ctx, nil, discardLogger())
}

// TestSMBAuditRoadQueuesAnAccessWithShareAndPath is the whole point of
// the road: a real audit line becomes an smb alert naming the share and
// the file.
func TestSMBAuditRoadQueuesAnAccessWithShareAndPath(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 64, MaxBytes: 1 << 20})
	road, auditPath, _ := newTestSMBRoad(t, in)

	writeLines(t, auditPath, capturedAuditLines)
	// One alert: the three closes of one file fetch collapse into the
	// longest path, and the banner is not an event at all (#123).
	runRoadUntil(t, road, in, 1)

	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1 -- one visit is one alert", got)
	}
	var paths []string
	for _, queued := range in.Queue.Peek(1) {
		fields, err := event.ExtractFields(queued.Payload)
		if err != nil {
			t.Fatalf("ExtractFields on a queued event: %v", err)
		}
		if fields.Service != "smb" {
			t.Errorf("service = %q, want smb", fields.Service)
		}
		if fields.SourceIP != "172.21.0.3" {
			t.Errorf("src_host = %q, want the client address from the line", fields.SourceIP)
		}
		var decoded struct {
			LogData map[string]string `json:"logdata"`
		}
		if err := json.Unmarshal(queued.Payload, &decoded); err != nil {
			t.Fatalf("decode a queued event: %v", err)
		}
		if got := decoded.LogData["SHARENAME"]; got != "public" {
			t.Errorf("SHARENAME = %q, want public", got)
		}
		paths = append(paths, decoded.LogData["FILENAME"])
	}
	wantPath := "/srv/shares/public/IT/vpn-setup.pdf"
	found := false
	for _, p := range paths {
		if p == wantPath {
			found = true
		}
	}
	if !found {
		t.Errorf("no queued event named %s; got %v", wantPath, paths)
	}
	if got := road.Events(); got != 1 {
		t.Errorf("road.Events() = %d, want 1", got)
	}
	if got := road.Unreadable(); got != 0 {
		t.Errorf("road.Unreadable() = %d, want 0", got)
	}
	if got := road.Collapsed(); got != 2 {
		t.Errorf("road.Collapsed() = %d, want the 2 directory closes folded away", got)
	}
}

// TestSMBAuditRoadReadsWhatWasWrittenBeforeItStarted is the regression
// against the reason OpenCanary's own smb module was not used (#78's
// note, finding 3): its watcher seeks to end-of-file, so anything written
// before it attached is gone. Everything in this test was written before
// the road ran.
func TestSMBAuditRoadReadsWhatWasWrittenBeforeItStarted(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 64, MaxBytes: 1 << 20})
	road, auditPath, _ := newTestSMBRoad(t, in)

	writeLines(t, auditPath, capturedAuditLines)
	// A pause, so there is no chance the road's first read happens to
	// coincide with the write.
	time.Sleep(50 * time.Millisecond)
	runRoadUntil(t, road, in, 1)

	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1 -- lines written before the road started must not be lost", got)
	}
}

// TestSMBAuditRoadResumesWhereItLeftOff: the saved position is what makes
// a restart cost nothing. The second road reads only what arrived while
// nothing was reading.
func TestSMBAuditRoadResumesWhereItLeftOff(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 64, MaxBytes: 1 << 20})
	road, auditPath, stateDir := newTestSMBRoad(t, in)

	writeLines(t, auditPath, capturedAuditLines)
	runRoadUntil(t, road, in, 1)
	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("first run queued %d events, want 1", got)
	}

	// The position must have reached disk by the time the road stopped:
	// run saves on its way out, not only on its ticker.
	if _, err := os.Stat(filepath.Join(stateDir, smbPositionFileName)); err != nil {
		t.Fatalf("no saved position after the road stopped: %v", err)
	}

	// A fresh queue and a fresh road over the same audit file and state
	// directory: a restarted process.
	restarted, _ := newTestIntake(t, queue.Config{MaxEvents: 64, MaxBytes: 1 << 20})
	second, inv := newSMBAuditRoad(Config{StateDir: stateDir}, restarted, discardLogger())
	if second == nil || !inv.Active {
		t.Fatal("the restarted road was not built")
	}

	writeLines(t, auditPath, []string{
		`[2026/09/23 22:05:00.000001,  1]   root|172.21.0.3|backup|close|ok|/srv/shares/backup/router-config.txt`,
	})
	runRoadUntil(t, second, restarted, 1)

	if got := restarted.Queue.Depth(); got != 1 {
		t.Fatalf("after the restart the queue holds %d events, want only the one new line", got)
	}
	var decoded struct {
		LogData map[string]string `json:"logdata"`
	}
	if err := json.Unmarshal(restarted.Queue.Peek(1)[0].Payload, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := decoded.LogData["FILENAME"]; got != "/srv/shares/backup/router-config.txt" {
		t.Errorf("the restarted road read %q, want only the line written after the restart", got)
	}
}

// TestSMBAuditRoadRereadIsNotADuplicateAlert: the position is saved on a
// short timer rather than per line, so a crash can leave lines already
// queued behind the saved position. Re-reading them has to be free --
// the same bytes, so the same id, so the queue drops the second copy.
func TestSMBAuditRoadRereadIsNotADuplicateAlert(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 64, MaxBytes: 1 << 20})
	road, auditPath, stateDir := newTestSMBRoad(t, in)

	writeLines(t, auditPath, capturedAuditLines)
	runRoadUntil(t, road, in, 1)
	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("first run queued %d events, want 1", got)
	}

	// Throw the saved position away, the worst case a crash can produce,
	// and read the whole file again into the same queue.
	if err := os.Remove(filepath.Join(stateDir, smbPositionFileName)); err != nil {
		t.Fatalf("remove saved position: %v", err)
	}
	again, inv := newSMBAuditRoad(Config{StateDir: stateDir}, in, discardLogger())
	if again == nil || !inv.Active {
		t.Fatal("the second road was not built")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runSMBAuditRoad(ctx, again, discardLogger())

	if got := in.Queue.Depth(); got != 1 {
		t.Errorf("queue depth = %d after re-reading the whole file, want 1 -- a re-read visit must mint the id it already had", got)
	}
}

// TestSMBAuditRoadReportsAShiftedLineRatherThanMisreadingIt: the openat
// shape is what #78's note found; the road has to queue it as an
// unparseable-line event, with no path, rather than reporting the "r" flag
// as the file somebody opened.
func TestSMBAuditRoadReportsAShiftedLineRatherThanMisreadingIt(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 64, MaxBytes: 1 << 20})
	road, auditPath, _ := newTestSMBRoad(t, in)

	writeLines(t, auditPath, []string{
		`[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|public|openat|ok|r|/srv/shares/public/IT/vpn-setup.pdf`,
	})
	runRoadUntil(t, road, in, 1)

	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1 -- a line the parse refuses is still an event", got)
	}
	var decoded struct {
		LogData map[string]string `json:"logdata"`
	}
	if err := json.Unmarshal(in.Queue.Peek(1)[0].Payload, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := decoded.LogData["AUDITEVENT"]; got != smbaudit.KindUnparseable.Wording() {
		t.Errorf("AUDITEVENT = %q, want %q", got, smbaudit.KindUnparseable.Wording())
	}
	if got := decoded.LogData["FILENAME"]; got != "" {
		t.Errorf("FILENAME = %q, want empty -- a refused line must not report a path", got)
	}
	if got := road.Unreadable(); got != 1 {
		t.Errorf("road.Unreadable() = %d, want 1", got)
	}
}

// TestSMBAuditRoadQueuesAPanicAsItsOwnKind: decision 9's separate wording.
func TestSMBAuditRoadQueuesAPanicAsItsOwnKind(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 64, MaxBytes: 1 << 20})
	road, auditPath, _ := newTestSMBRoad(t, in)

	writeLines(t, auditPath, []string{
		`[2026/09/23 22:06:57.659891,  0]   PANIC (pid 1): sys_setgroups failed in 4.23.8`,
	})
	runRoadUntil(t, road, in, 1)

	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
	var decoded struct {
		LogData map[string]string `json:"logdata"`
	}
	if err := json.Unmarshal(in.Queue.Peek(1)[0].Payload, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := decoded.LogData["AUDITEVENT"]; got != smbaudit.KindPanic.Wording() {
		t.Errorf("AUDITEVENT = %q, want %q", got, smbaudit.KindPanic.Wording())
	}
	if road.Events() != 1 {
		t.Errorf("road.Events() = %d, want 1", road.Events())
	}
}

// TestSubmitSMBEventQueuesWithTheSameIDTheOtherRoadsWouldMint mirrors the
// port-scan and snmp roads' equivalent tests: the id has to be the same
// kind of value, in the same format, as every other road's.
func TestSubmitSMBEventQueuesWithTheSameIDTheOtherRoadsWouldMint(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	ev, ok := smbaudit.Parse([]byte(`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/x`))
	if !ok {
		t.Fatal("Parse returned no event")
	}
	message, err := smbaudit.Encode(ev, "mockingbird")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if err := in.SubmitSMBEvent(context.Background(), message); err != nil {
		t.Fatalf("SubmitSMBEvent: %v", err)
	}
	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
	queued := in.Queue.Peek(1)[0]

	wantID, err := event.IDFromEmittedMessage(message)
	if err != nil {
		t.Fatalf("IDFromEmittedMessage: %v", err)
	}
	if queued.ID != wantID {
		t.Errorf("queued id %s, want %s", queued.ID, wantID)
	}
	if len(queued.ID) != 64 {
		t.Errorf("id %q is %d characters, want the 64 birdcage validates", queued.ID, len(queued.ID))
	}
	if string(queued.Payload) != string(message) {
		t.Errorf("queued payload was altered:\n got: %s\nwant: %s", queued.Payload, message)
	}
}

// TestSubmitSMBEventAppendsNoLedgerEntry is #48 decision 3 applied to
// this road: the ledger tracks positions in OpenCanary's log file, and
// this line was never in it.
func TestSubmitSMBEventAppendsNoLedgerEntry(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	before := in.Ledger().Len()
	for _, share := range []string{"public", "backup", "scans"} {
		ev, _ := smbaudit.Parse([]byte(`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|` + share + `|close|ok|/srv/shares/` + share))
		message, err := smbaudit.Encode(ev, "mockingbird")
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if err := in.SubmitSMBEvent(context.Background(), message); err != nil {
			t.Fatalf("SubmitSMBEvent: %v", err)
		}
	}
	if got := in.Ledger().Len(); got != before {
		t.Errorf("ledger length %d, want it unchanged at %d", got, before)
	}
}

// TestSubmitSMBEventStopsOnShutdown: the audit file is the durable store,
// so a full queue blocks rather than dropping -- and when the process is
// stopping instead, the push is abandoned and the caller is told, so the
// line is read again next start rather than acknowledged unsent.
func TestSubmitSMBEventStopsOnShutdown(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 1, MaxBytes: 1 << 20})

	first, _ := smbaudit.Parse([]byte(`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/a`))
	body, err := smbaudit.Encode(first, "mockingbird")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := in.SubmitSMBEvent(context.Background(), body); err != nil {
		t.Fatalf("SubmitSMBEvent: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	second, _ := smbaudit.Parse([]byte(`[2026/09/23 22:01:53.987125,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/b`))
	body2, err := smbaudit.Encode(second, "mockingbird")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := in.SubmitSMBEvent(ctx, body2); err == nil {
		t.Error("SubmitSMBEvent returned no error on a full queue with a cancelled context")
	}
	if got := in.Queue.Depth(); got != 1 {
		t.Errorf("queue depth = %d, want the one event that was accepted", got)
	}
}

// newBareSMBRoad builds a road with a stub submit, so the paths that only
// happen when queueing fails can be exercised directly.
func newBareSMBRoad(t *testing.T, submit func(context.Context, []byte) error) (*smbAuditRoad, string) {
	t.Helper()
	stateDir := t.TempDir()
	return &smbAuditRoad{
		positions: queue.NewPositionStore(filepath.Join(stateDir, smbPositionFileName)),
		submit:    submit,
		nodeID:    smbaudit.DefaultNodeID,
		log:       discardLogger(),
		collapser: smbaudit.NewCollapser(smbaudit.CollapseConfig{}),
	}, stateDir
}

var oneAuditLine = tailer.Line{
	Data: []byte(`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/x`),
	Pos:  queue.Position{Inode: 7, Offset: 120},
}

// onePanicLine is a line the collapser never holds (#123: panics are never
// collapsed), so handle reaches the queue with it on the first call --
// which is what the tests about queueing failures need.
var onePanicLine = tailer.Line{
	Data: []byte(`[2026/09/23 22:06:57.659891,  0]   PANIC (pid 1): sys_setgroups failed in 4.23.8`),
	Pos:  queue.Position{Inode: 7, Offset: 240},
}

// TestSMBAuditRoadAcknowledgesALineItCouldNotQueue: a push that failed for
// a reason other than shutdown is reported, and the line is still
// acknowledged -- reading it again would fail the same way for ever, and a
// road stuck on one line reports nothing about any later one.
func TestSMBAuditRoadAcknowledgesALineItCouldNotQueue(t *testing.T) {
	road, _ := newBareSMBRoad(t, func(context.Context, []byte) error {
		return errors.New("queue refused it")
	})

	road.handle(context.Background(), onePanicLine)

	if got := road.Events(); got != 0 {
		t.Errorf("road.Events() = %d, want 0 -- nothing was queued", got)
	}
	if got := (queue.Position{Inode: road.pendingInode.Load(), Offset: int64(road.pending.Load())}); got != onePanicLine.Pos {
		t.Errorf("pending position = %+v, want the position after the line", got)
	}
}

// TestSMBAuditRoadDoesNotAcknowledgeOnShutdown is #48's fail-closed rule
// applied here: a line abandoned because the process is stopping must be
// read again next start, so its position must not be recorded.
func TestSMBAuditRoadDoesNotAcknowledgeOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	road, _ := newBareSMBRoad(t, func(ctx context.Context, _ []byte) error { return ctx.Err() })

	road.handle(ctx, onePanicLine)

	if got := road.pending.Load(); got != 0 {
		t.Errorf("pending offset = %d, want 0 -- an abandoned line must not be acknowledged", got)
	}
}

// TestSMBAuditRoadSavesOnlyWhatMoved: the periodic save must not rewrite a
// position that has not changed, and must not write anything at all before
// the first line.
func TestSMBAuditRoadSavesOnlyWhatMoved(t *testing.T) {
	road, stateDir := newBareSMBRoad(t, func(context.Context, []byte) error { return nil })
	positionPath := filepath.Join(stateDir, smbPositionFileName)

	// Nothing read yet: nothing to save.
	road.savePosition(discardLogger())
	if _, err := os.Stat(positionPath); !os.IsNotExist(err) {
		t.Errorf("a position file exists before any line was read (err %v)", err)
	}

	road.handle(context.Background(), onePanicLine)
	road.savePosition(discardLogger())
	info, err := os.Stat(positionPath)
	if err != nil {
		t.Fatalf("no position file after a line was read: %v", err)
	}

	// A second save with nothing new must be a no-op rather than another
	// write-fsync-rename.
	road.savePosition(discardLogger())
	again, err := os.Stat(positionPath)
	if err != nil {
		t.Fatalf("stat after the second save: %v", err)
	}
	if !again.ModTime().Equal(info.ModTime()) {
		t.Error("the position file was rewritten for a position that had not moved")
	}
}

// TestSMBAuditRoadKeepsGoingWhenThePositionCannotBeSaved: #48's
// fail-closed rule for an unwritable position -- keep forwarding, report
// it, and re-read from the last written position on restart.
func TestSMBAuditRoadKeepsGoingWhenThePositionCannotBeSaved(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root ignores the directory mode this test sets")
	}
	road, stateDir := newBareSMBRoad(t, func(context.Context, []byte) error { return nil })
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatalf("chmod state dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) })

	road.handle(context.Background(), onePanicLine)
	road.savePosition(discardLogger())

	if (road.saved != queue.Position{}) {
		t.Errorf("saved position = %+v, want it unchanged after a failed write", road.saved)
	}
	// And the road is still willing to try again next tick.
	road.savePosition(discardLogger())
}

// TestSMBAuditRoadReadsFromTheStartWhenThePositionIsUnreadable: a
// corrupted position file is a reason to re-read, never to skip.
func TestSMBAuditRoadReadsFromTheStartWhenThePositionIsUnreadable(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 64, MaxBytes: 1 << 20})
	road, auditPath, stateDir := newTestSMBRoad(t, in)

	if err := os.WriteFile(filepath.Join(stateDir, smbPositionFileName), []byte("not a position record"), 0o600); err != nil {
		t.Fatalf("write a corrupt position: %v", err)
	}
	writeLines(t, auditPath, capturedAuditLines)
	runRoadUntil(t, road, in, 1)

	if got := in.Queue.Depth(); got != 1 {
		t.Errorf("queue depth = %d, want 1 -- an unreadable position must re-read the file, not skip it", got)
	}
}

// TestSMBAuditRoadHoldsThePositionWhileAVisitIsOpen: a line that has been
// read but not yet turned into an event must not be behind the saved
// position, or a crash would lose it. The position only moves once the
// collapser is holding nothing (#123).
func TestSMBAuditRoadHoldsThePositionWhileAVisitIsOpen(t *testing.T) {
	road, _ := newBareSMBRoad(t, func(context.Context, []byte) error { return nil })

	road.handle(context.Background(), oneAuditLine)
	if got := road.pending.Load(); got != 0 {
		t.Fatalf("pending offset = %d while a visit is still open, want 0", got)
	}

	// The tick that releases the quiet visit is also what lets the
	// position move.
	time.Sleep(smbaudit.DefaultCollapseWindow)
	road.release(context.Background())
	if got := road.pending.Load(); got != uint64(oneAuditLine.Pos.Offset) {
		t.Errorf("pending offset = %d after the visit was released, want %d", got, oneAuditLine.Pos.Offset)
	}
	if got := road.Events(); got != 1 {
		t.Errorf("road.Events() = %d, want the released access", got)
	}
}

// TestSMBAuditRoadKeepsTwoFilesAsTwoAlerts is the other half of #123: the
// collapsing is about the walk to a file, never about how much a visitor
// did.
func TestSMBAuditRoadKeepsTwoFilesAsTwoAlerts(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 64, MaxBytes: 1 << 20})
	road, auditPath, _ := newTestSMBRoad(t, in)

	writeLines(t, auditPath, []string{
		`[2026/09/23 22:01:53.100000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
		`[2026/09/23 22:01:53.200000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT`,
		`[2026/09/23 22:01:53.300000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
		`[2026/09/23 22:01:53.400000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/HR`,
		`[2026/09/23 22:01:53.500000,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/HR/salaries-2025.xlsx`,
	})
	runRoadUntil(t, road, in, 2)

	if got := in.Queue.Depth(); got != 2 {
		t.Fatalf("queue depth = %d, want 2 -- two files opened is two alerts", got)
	}
	var paths []string
	for _, queued := range in.Queue.Peek(2) {
		var decoded struct {
			LogData map[string]string `json:"logdata"`
		}
		if err := json.Unmarshal(queued.Payload, &decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
		paths = append(paths, decoded.LogData["FILENAME"])
	}
	for _, want := range []string{
		"/srv/shares/public/IT/vpn-setup.pdf",
		"/srv/shares/public/HR/salaries-2025.xlsx",
	} {
		found := false
		for _, got := range paths {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("no alert named %s; got %v", want, paths)
		}
	}
}
