package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/queue"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/selftest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// sshFixtureEvent builds an OpenCanary-shaped ssh event (logtype 4000
// new connection, 4001 version exchange, 4002 login attempt) from
// srcAddr:srcPort. Only 4002 carries the probe's username, so only its
// raw can carry the marker (#239).
func sshFixtureEvent(logtype int, srcAddr string, srcPort int, username string) string {
	logdata := `{}`
	switch logtype {
	case 4001:
		logdata = `{"REMOTEVERSION": "SSH-2.0-Go"}`
	case 4002:
		logdata = fmt.Sprintf(`{"USERNAME": %q, "PASSWORD": "birdcage-selftest"}`, username)
	}
	return fmt.Sprintf(`{"dst_host": "203.0.113.9", "dst_port": 22, "logdata": %s, "logtype": %d, "node_id": "canary-a", "src_host": %q, "src_port": %d, "local_time": "2026-01-01 00:00:00.000000", "utc_time": "2026-01-01 00:00:00.000000"}`, logdata, logtype, srcAddr, srcPort)
}

// mintSSHTargetAgainstRealDB is mintAttributedTargetAgainstRealDB's ssh
// counterpart: one ssh (marked grade) target at addr, minted against the
// database the real ingest handler reads from.
func mintSSHTargetAgainstRealDB(t *testing.T, database *db.DB, addr string, now time.Time, ttl time.Duration) string {
	t.Helper()
	if err := store.SetCanaryLastSeenAddr(context.Background(), database, testCanaryID, addr); err != nil {
		t.Fatalf("SetCanaryLastSeenAddr: %v", err)
	}
	cmd, err := store.MintSelfTestCommand(context.Background(), database, store.NewSelfTestIndex(), testCanaryID, addr,
		[]store.SelfTestTarget{{Service: "ssh", DestPort: 22}}, now, now.Add(ttl))
	if err != nil {
		t.Fatalf("MintSelfTestCommand: %v", err)
	}
	params, err := selftest.DecodeParams([]byte(cmd.Params))
	if err != nil {
		t.Fatalf("decode minted params: %v", err)
	}
	return params.Targets[0].Marker
}

// pushSSH queues one ssh event through the webhook road, the same
// intake path observeClaim sits on, and returns nothing: the claim
// tracker sees it exactly as it would a live OpenCanary event.
func pushSSH(t *testing.T, in *Intake, logtype int, addr string, port int, username string) {
	t.Helper()
	if err := in.webhookHandler(wrapWebhook(t, sshFixtureEvent(logtype, addr, port, username))); err != nil {
		t.Fatalf("webhookHandler(%d): %v", logtype, err)
	}
}

// TestSSHConnectionEventsAllReachBirdcageSynthetic is #239's end-to-end
// proof: 4000, 4001 and 4002 of the probe's one ssh connection (same
// src_host and src_port), pushed through intake and the sender to the
// real ingest handler, are all stored synthetic, and the canary's
// visitor history has nothing for that source.
//
// Required of the builder: (*claimWindow).setSourcePort(port int) -- the
// ssh probe's own source port, known once its connection is open -- and
// the ssh window claiming every held event whose src_host is the window's
// address and src_port that port.
func TestSSHConnectionEventsAllReachBirdcageSynthetic(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, testCanaryID)
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, testCanaryID)

		addr := "198.51.100.5"
		const port = 50123
		now := time.Now().UTC()
		marker := mintSSHTargetAgainstRealDB(t, database, addr, now, time.Hour)

		in, _ := newTestIntake(t, queue.Config{})
		w := in.claims.startWindow("ssh", addr, marker)
		pushSSH(t, in, 4000, addr, port, "")
		pushSSH(t, in, 4001, addr, port, "")
		w.setSourcePort(port)
		pushSSH(t, in, 4002, addr, port, marker)
		in.claims.resolveWindow(w)

		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go runSenderLoop(runCtx, c, newTokenStoreForTest(token), in, newPacer())

		alerts := waitForAlertCount(t, database, testCanaryID, 3, alertWaitBound)
		if len(alerts) != 3 {
			t.Fatalf("got %d alerts, want 3", len(alerts))
		}
		for _, a := range alerts {
			if !a.Synthetic {
				t.Errorf("alert %+v is real, want every event of the self-test connection synthetic", a)
			}
		}
		visitors, err := store.ListVisitors(ctx(), database, time.Now(), store.VisitorFilter{}, nil)
		if err != nil {
			t.Fatalf("ListVisitors: %v", err)
		}
		for _, v := range visitors {
			if v.SourceIP == addr {
				t.Errorf("visitor history has an entry for the canary's own address: %+v", v)
			}
		}
	})
}

// TestSSHEventFromAnotherSourcePortIsNotClaimed: an event from the
// canary's own address but a different source port, inside the same
// window, is not part of the probe's connection and stays real.
func TestSSHEventFromAnotherSourcePortIsNotClaimed(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		enrollCanary(t, database, testCanaryID)
		c, _ := newIngestServer(t, database)
		token := mintToken(t, database, testCanaryID)

		addr := "198.51.100.5"
		const port, otherPort = 50123, 50124
		now := time.Now().UTC()
		marker := mintSSHTargetAgainstRealDB(t, database, addr, now, time.Hour)

		in, _ := newTestIntake(t, queue.Config{})
		w := in.claims.startWindow("ssh", addr, marker)
		pushSSH(t, in, 4000, addr, port, "")
		pushSSH(t, in, 4000, addr, otherPort, "")
		w.setSourcePort(port)
		pushSSH(t, in, 4002, addr, port, marker)
		in.claims.resolveWindow(w)

		runCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go runSenderLoop(runCtx, c, newTokenStoreForTest(token), in, newPacer())

		alerts := waitForAlertCount(t, database, testCanaryID, 3, alertWaitBound)
		for _, a := range alerts {
			other := strings.Contains(a.Raw, fmt.Sprintf(`"src_port": %d`, otherPort))
			if other && a.Synthetic {
				t.Errorf("the event from source port %d was claimed: %+v", otherPort, a)
			}
			if !other && !a.Synthetic {
				t.Errorf("an event of the probe's own connection (port %d) is real: %+v", port, a)
			}
		}
	})
}

// TestSSHClaimWindowClaimsOnlyTheProbesConnection is the tracker-level
// rule behind the two tests above, with no database: after
// resolveWindow every held ssh event with the window's address and the
// probe's port is claimed (three of them, not "exactly one"), and an
// event from the same address and another port, or another address with
// the same port, is not.
func TestSSHClaimWindowClaimsOnlyTheProbesConnection(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{})
	addr := "198.51.100.5"
	w := in.claims.startWindow("ssh", addr, "the-marker")

	pushSSH(t, in, 4000, addr, 50123, "")
	pushSSH(t, in, 4001, addr, 50123, "")
	pushSSH(t, in, 4002, addr, 50123, "the-marker")
	pushSSH(t, in, 4000, addr, 50124, "")           // other port
	pushSSH(t, in, 4000, "203.0.113.77", 50123, "") // other address
	w.setSourcePort(50123)
	in.claims.resolveWindow(w)

	events := in.Queue.Peek(10)
	if len(events) != 5 {
		t.Fatalf("queue holds %d events, want 5", len(events))
	}
	claimed := 0
	for _, qe := range events {
		if in.claims.pending(qe.ID) {
			t.Errorf("event %s still pending after resolve", qe.ID)
		}
		f := fieldsOrFallback(qe.Payload)
		_, ok := in.claims.marker(qe.ID)
		want := f.SourceIP == addr && f.SourcePort == 50123
		if ok != want {
			t.Errorf("event %s (src %s:%d): claimed = %v, want %v", qe.ID, f.SourceIP, f.SourcePort, ok, want)
		}
		if ok {
			claimed++
		}
	}
	if claimed != 3 {
		t.Errorf("%d events claimed, want 3", claimed)
	}
}
