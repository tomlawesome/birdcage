package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
	"github.com/tomlawesome/birdcage/internal/selftest"
)

// smbListener answers every connection with reply (nil: closes without
// answering) and returns its port.
func smbListener(t *testing.T, reply []byte) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() }) // test teardown; nothing left to act on a close error
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }() // test teardown; nothing left to act on a close error
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 512)
				_, _ = c.Read(buf)
				if reply != nil {
					_, _ = c.Write(reply)
				}
			}()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(p)
	return port
}

func smbParams(port int, marker string) selftest.Params {
	return selftest.Params{
		RunID:   "run-smb",
		Address: "127.0.0.1",
		Targets: []selftest.Target{{Service: "smb", DestPort: port, Marker: marker}},
	}
}

var smbReply = append([]byte{0x00, 0x00, 0x00, 0x08}, []byte("\xfeSMB\x00\x00\x00\x00")...)

// TestRunAgentHandledTargetReportsSMBReachableOnSuccess (#243): the lure
// answers an SMB2 NEGOTIATE, so the agent reports "reachable", carrying the
// target's marker in its own result event and nowhere else.
func TestRunAgentHandledTargetReportsSMBReachableOnSuccess(t *testing.T) {
	log, buf := captureLogger()
	defer swapSelftestLog(log)()
	in, _ := newTestIntake(t, queue.Config{})

	params := smbParams(smbListener(t, smbReply), "m-smb-ok")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runAgentHandledTarget(ctx, in, &fakeBait{}, params, params.Targets[0])

	got := queuedResult(t, in)
	if got.LogType != LogTypeSelfTestResult {
		t.Errorf("logtype = %d, want %d", got.LogType, LogTypeSelfTestResult)
	}
	if got.LogData.OUTCOME != "reachable" {
		t.Errorf("OUTCOME = %q, want %q", got.LogData.OUTCOME, "reachable")
	}
	if got.LogData.TARGET != "smb" {
		t.Errorf("TARGET = %q, want smb", got.LogData.TARGET)
	}
	if got.LogData.MARKER != "m-smb-ok" {
		t.Errorf("MARKER = %q, want the marker birdcage minted", got.LogData.MARKER)
	}
	if strings.Contains(buf.String(), "m-smb-ok") {
		t.Errorf("the log names the marker: %q", buf.String())
	}
}

// TestRunAgentHandledTargetReportsNothingForSMBOnFailure: a lure that does
// not answer is reported by silence, so the run fails at its deadline --
// the failed-services list then names smb. Nothing is queued, and a
// bait lookup never runs for it.
func TestRunAgentHandledTargetReportsNothingForSMBOnFailure(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, p, _ := net.SplitHostPort(dead.Addr().String())
	deadPort, _ := strconv.Atoi(p)
	_ = dead.Close() // freeing the port is the point

	tests := []struct {
		name string
		port int
	}{
		{"nothing listening", deadPort},
		{"listener answers something that is not SMB", smbListener(t, []byte("HTTP/1.1 400 Bad Request\r\n\r\n"))},
		{"listener closes without replying", smbListener(t, nil)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := captureLogger()
			defer swapSelftestLog(log)()
			in, _ := newTestIntake(t, queue.Config{})

			bait := &fakeBait{}
			params := smbParams(tc.port, "m-smb-fail")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			runAgentHandledTarget(ctx, in, bait, params, params.Targets[0])

			if got := in.Queue.Depth(); got != 0 {
				t.Errorf("queue depth = %d, want 0 -- a failed reachability check reports nothing", got)
			}
			if bait.calls != 0 {
				t.Error("a poisoner bait lookup ran for the smb target")
			}
		})
	}
}

// TestSNMPUp (#243): the heartbeat's SNMPUp comes from the listener's own
// state. It is empty (nil, not false) when SNMP detection is off, so a
// canary that never had SNMP never grows an snmp self-test target.
func TestSNMPUp(t *testing.T) {
	if got := snmpUp(snmpInventory{SNMPActive: false}); got != nil {
		t.Errorf("snmpUp(off) = %v, want nil", *got)
	}
	got := snmpUp(snmpInventory{SNMPActive: true})
	if got == nil || !*got {
		t.Errorf("snmpUp(active) = %v, want true", got)
	}
}

// TestOpenCanaryProbeSMBLure (#243): the lure's heartbeat flag is empty
// unless MOCKINGBIRD_SMB_AUDIT_PATH is set; otherwise a bare connection to
// 445 decides it, through the probe's own dial.
func TestOpenCanaryProbeSMBLure(t *testing.T) {
	newProbe := func(t *testing.T) (*openCanaryProbe, *probeDialRecorder) {
		t.Helper()
		log, _ := captureLogger()
		p := newOpenCanaryProbe(fastReadinessConfig(writeConf(t, map[string]int{"ftp": 21})), log)
		rd := &probeDialRecorder{}
		p.dial = rd.dial
		p.listening = fakeListening()
		return p, rd
	}

	t.Run("no audit path means no opinion and no connection", func(t *testing.T) {
		t.Setenv(envSMBAuditPath, "")
		p, rd := newProbe(t)
		if got := p.ProbeSMBLure(context.Background()); got != nil {
			t.Errorf("ProbeSMBLure() = %v, want nil with %s unset", *got, envSMBAuditPath)
		}
		if rd.saw("127.0.0.1:445") {
			t.Error("dialled 445 on a canary with no SMB lure")
		}
	})

	t.Run("lure answering is true", func(t *testing.T) {
		t.Setenv(envSMBAuditPath, "/smb-audit/audit.log")
		p, rd := newProbe(t)
		got := p.ProbeSMBLure(context.Background())
		if got == nil || !*got {
			t.Fatalf("ProbeSMBLure() = %v, want true", got)
		}
		if !rd.saw("127.0.0.1:445") {
			t.Errorf("did not dial 127.0.0.1:445, dialled %v", rd.dialed)
		}
	})

	t.Run("refused connection is false, not nil", func(t *testing.T) {
		t.Setenv(envSMBAuditPath, "/smb-audit/audit.log")
		p, _ := newProbe(t)
		p.dial = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}
		got := p.ProbeSMBLure(context.Background())
		if got == nil || *got {
			t.Errorf("ProbeSMBLure() = %v, want false", got)
		}
	})
}
