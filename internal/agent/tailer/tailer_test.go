package tailer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// testPollInterval is short enough to keep these tests fast, and long
// enough to be reliable under CI scheduling jitter and -race's slowdown.
const testPollInterval = 15 * time.Millisecond

// collector runs Follow in the background and gives tests a
// goroutine-safe way to wait for and inspect emitted lines.
type collector struct {
	mu    sync.Mutex
	lines []Line
}

func (c *collector) emit(l Line) {
	// Copy Data out: lineReader's line slices are only valid until the
	// next feed call, which for the live file can happen concurrently
	// with a test goroutine inspecting c.lines below.
	cp := Line{Data: append([]byte(nil), l.Data...), Pos: l.Pos}
	c.mu.Lock()
	c.lines = append(c.lines, cp)
	c.mu.Unlock()
}

func (c *collector) snapshot() []Line {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Line, len(c.lines))
	copy(out, c.lines)
	return out
}

// waitFor polls until want lines have been collected or the deadline
// passes, failing the test on timeout.
func (c *collector) waitFor(t *testing.T, want int) []Line {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.snapshot(); len(got) >= want {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d lines, got %d: %q", want, len(c.snapshot()), dataOf(c.snapshot()))
	return nil
}

func dataOf(lines []Line) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = string(l.Data)
	}
	return out
}

// followHandle bundles what a test needs from a backgrounded Follow call:
// the collected lines, and (once stop has been called) the ResumeResult
// the initial catch-up scan produced.
type followHandle struct {
	*collector
	result ResumeResult
}

// startFollow launches Follow in the background and returns a handle plus
// a stop func that cancels it, waits for return, and populates
// handle.result.
func startFollow(t *testing.T, path string, cfg Config, resumeFrom queue.Position, hasResume bool) (*followHandle, func()) {
	t.Helper()
	if cfg.PollInterval == 0 {
		cfg.PollInterval = testPollInterval
	}
	tl := New(path, cfg)
	h := &followHandle{collector: &collector{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		result, err := tl.Follow(ctx, resumeFrom, hasResume, h.emit)
		h.result = result
		done <- err
	}()
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("Follow returned unexpected error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Follow did not return after cancel")
		}
	}
	return h, stop
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", path, err)
	}
	ino, ok := lstatInode(fi)
	if !ok {
		t.Fatalf("no inode available for %s", path)
	}
	return ino
}

func TestTailer_FollowsGrowingLiveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c, stop := startFollow(t, path, Config{}, queue.Position{}, false)
	defer stop()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.WriteString("one\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := c.waitFor(t, 1)
	if string(got[0].Data) != "one" {
		t.Fatalf("line = %q, want \"one\"", got[0].Data)
	}

	if _, err := f.WriteString("two\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	got = c.waitFor(t, 2)
	if string(got[1].Data) != "two" {
		t.Fatalf("line = %q, want \"two\"", got[1].Data)
	}
}

func TestTailer_ResumeFromPositionScansRotatedSibling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log")

	// Build a directory that looks like it does right after a completed
	// rotation: an already-rotated sibling holding two lines, and a live
	// file holding one more.
	if err := os.WriteFile(path, []byte("old1\nold2\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rotatedInode := inodeOf(t, path)
	rotatedPath := filepath.Join(dir, "opencanary.log.1")
	if err := os.Rename(path, rotatedPath); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := os.WriteFile(path, []byte("new1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Acknowledged position: right after "old1\n" in the now-rotated
	// file. Only old2 and new1 are unacknowledged.
	resumeFrom := queue.Position{Inode: rotatedInode, Offset: int64(len("old1\n"))}

	h, stop := startFollow(t, path, Config{}, resumeFrom, true)

	got := h.waitFor(t, 2)
	if string(got[0].Data) != "old2" {
		t.Fatalf("first replayed line = %q, want \"old2\" (must not re-deliver old1)", got[0].Data)
	}
	if string(got[1].Data) != "new1" {
		t.Fatalf("second replayed line = %q, want \"new1\"", got[1].Data)
	}
	stop()
	if !h.result.PositionFound {
		t.Fatalf("PositionFound = false, want true (resumeFrom's inode was located on the rotated sibling)")
	}
}

func TestTailer_ResumePositionNotFoundFallsBackRatherThanSkipping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log")
	if err := os.WriteFile(path, []byte("only1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// A position naming an inode nothing on disk has -- e.g. the file it
	// pointed at rotated out past the recovery window before this agent
	// ever got to see it.
	resumeFrom := queue.Position{Inode: 0xDEADBEEF, Offset: 5}

	h, stop := startFollow(t, path, Config{}, resumeFrom, true)

	got := h.waitFor(t, 1)
	if string(got[0].Data) != "only1" {
		t.Fatalf("line = %q, want \"only1\" (fallback must still read what's available, never skip it)", got[0].Data)
	}
	stop()
	if h.result.PositionFound {
		t.Fatalf("PositionFound = true, want false (resumeFrom's inode does not exist on disk)")
	}
}

func TestTailer_RotationMidRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log")
	if err := os.WriteFile(path, []byte("line1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c, stop := startFollow(t, path, Config{}, queue.Position{}, false)
	defer stop()

	c.waitFor(t, 1)

	// Append a second line, then rotate: rename the file away (with the
	// new line already in it, possibly not yet read by the tailer) and
	// create a fresh file at the original path.
	if err := appendToFile(path, "line2\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := os.Rename(path, filepath.Join(dir, "opencanary.log.1")); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := os.WriteFile(path, []byte("line3\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got := c.waitFor(t, 3)
	want := []string{"line1", "line2", "line3"}
	for i, w := range want {
		if string(got[i].Data) != w {
			t.Fatalf("lines = %q, want %v", dataOf(got), want)
		}
	}
	if got[0].Pos.Inode == got[2].Pos.Inode {
		t.Fatalf("line1 and line3 report the same inode, want different (line3 is from the post-rotation file)")
	}
}

func TestTailer_InodeReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log")
	if err := os.WriteFile(path, []byte("line1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c, stop := startFollow(t, path, Config{}, queue.Position{}, false)
	defer stop()

	got := c.waitFor(t, 1)
	firstInode := got[0].Pos.Inode

	// Replace the file outright (no rotated-away copy kept anywhere) --
	// e.g. an atomic rename from a temp file, giving the same path a new
	// inode with no history.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := os.WriteFile(path, []byte("line2\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got = c.waitFor(t, 2)
	if string(got[1].Data) != "line2" {
		t.Fatalf("lines = %q, want line2 second", dataOf(got))
	}
	if got[1].Pos.Inode == firstInode {
		t.Fatalf("replacement file reported the same inode as the original, want different")
	}
}

func TestTailer_BriefAbsence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log")
	if err := os.WriteFile(path, []byte("line1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c, stop := startFollow(t, path, Config{}, queue.Position{}, false)
	defer stop()

	c.waitFor(t, 1)

	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// Give the follow loop a few poll cycles to observe the absence and
	// keep retrying without giving up.
	time.Sleep(5 * testPollInterval)

	if err := os.WriteFile(path, []byte("line2\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got := c.waitFor(t, 2)
	if string(got[1].Data) != "line2" {
		t.Fatalf("lines = %q, want line2 after the file reappears", dataOf(got))
	}
}

func TestTailer_TruncationInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log")
	if err := os.WriteFile(path, []byte("aaaa\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tl := New(path, Config{PollInterval: testPollInterval})
	c := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = tl.Follow(ctx, queue.Position{}, false, c.emit)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	c.waitFor(t, 1)

	// Write an unterminated partial line and give the follower a chance
	// to read it into its pending state before truncating underneath it.
	if err := appendToFile(path, "partial-no-newline"); err != nil {
		t.Fatalf("append: %v", err)
	}
	time.Sleep(5 * testPollInterval)

	if err := os.Truncate(path, 0); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if err := appendToFile(path, "bbbb\n"); err != nil {
		t.Fatalf("append: %v", err)
	}

	got := c.waitFor(t, 2)
	if string(got[1].Data) != "bbbb" {
		t.Fatalf("lines = %q, want bbbb after truncation, never the discarded partial", dataOf(got))
	}

	deadline := time.Now().Add(2 * time.Second)
	for tl.DiscardedPartialLines() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if tl.DiscardedPartialLines() == 0 {
		t.Fatalf("DiscardedPartialLines() = 0, want at least 1 (the truncated partial line)")
	}
}

func TestTailer_ConcurrentWriterRace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c, stop := startFollow(t, path, Config{}, queue.Position{}, false)
	defer stop()

	const n = 200
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Errorf("OpenFile: %v", err)
			return
		}
		defer func() { _ = f.Close() }()
		for i := 0; i < n; i++ {
			if _, err := f.WriteString("x\n"); err != nil {
				t.Errorf("write: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	c.waitFor(t, n)
}

// TestTailer_LogReadOK_DefaultsOKBeforeFirstAttempt is gap 2's documented
// "before the first read attempt" case: a freshly built Tailer that has
// never had Follow called on it must not read as failing, the same
// direction internal/store/health.go's notDelivering resolves a nil
// self-report -- "has nothing to say yet" is not "not delivering".
func TestTailer_LogReadOK_DefaultsOKBeforeFirstAttempt(t *testing.T) {
	tl := New(filepath.Join(t.TempDir(), "opencanary.log"), Config{})
	if !tl.LogReadOK() {
		t.Fatal("LogReadOK() = false before Follow's first read attempt, want true (untried must not read as failing)")
	}
}

// TestTailer_LogReadOK_HealthyFollowReportsOK is gap 2's required
// positive case: a Tailer successfully following a live, readable file
// reports LogReadOK() true. Built the same manual way as
// TestTailer_TruncationInPlace, rather than via startFollow, since this
// test needs direct access to the *Tailer to call LogReadOK() on it.
func TestTailer_LogReadOK_HealthyFollowReportsOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tl := New(path, Config{PollInterval: testPollInterval})
	c := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = tl.Follow(ctx, queue.Position{}, false, c.emit)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	if err := appendToFile(path, "one\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	c.waitFor(t, 1)

	if !tl.LogReadOK() {
		t.Fatal("LogReadOK() = false after a successful follow, want true")
	}
}

// TestTailer_LogReadOK_UnopenableReportsNotOKThenRecovers is gap 2's
// required negative and recovery cases together: a log that cannot be
// opened at all reports LogReadOK() false, and once it appears and is
// successfully read, LogReadOK() flips back to true.
func TestTailer_LogReadOK_UnopenableReportsNotOKThenRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "opencanary.log") // deliberately never created yet

	tl := New(path, Config{PollInterval: testPollInterval})
	c := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = tl.Follow(ctx, queue.Position{}, false, c.emit)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	deadline := time.Now().Add(2 * time.Second)
	for tl.LogReadOK() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if tl.LogReadOK() {
		t.Fatal("LogReadOK() = true for a log that has never existed, want false")
	}

	if err := os.WriteFile(path, []byte("one\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	c.waitFor(t, 1)

	deadline = time.Now().Add(2 * time.Second)
	for !tl.LogReadOK() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !tl.LogReadOK() {
		t.Fatal("LogReadOK() = false after the log appeared and was read, want true (recovery)")
	}
}

func appendToFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.WriteString(s)
	return err
}
