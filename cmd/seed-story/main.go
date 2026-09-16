// Command seed-story fills a fresh SQLite database with the round-6
// sweep-night data story -- the same four canaries, heartbeats and hits
// as frontend/src/dev/fixtures/night.json (ADR-0004's acceptance case) --
// so frontend/e2e/smoke.spec.mjs (issue #39) has something real to load
// the built birdcage binary against, rather than a hand-typed copy of the
// fixture that would drift from it.
//
// Every timestamp in the fixture is shifted by the same offset (real now
// minus the fixture's own "now") before it's written, so the sweep -- the
// fixture's still-arriving visitor -- lands in the last 15 minutes
// however long ago the fixture itself was captured, and the story's
// relative timing (the repeat knocker's six distinct days, the touch
// three weeks back) is preserved rather than reconstructed by hand.
//
// Usage: go run ./cmd/seed-story <sqlite-db-path>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// fixtureCanary and fixtureTrace mirror just the fields of
// frontend/src/dev/fixtures/night.json this script needs -- the
// canaries' registry shape, and the trace's per-canary beats and hits.
type fixtureCanary struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Lane  string `json:"lane"`
	Ports string `json:"ports"`
}

type fixtureHit struct {
	At      time.Time `json:"at"`
	Visitor string    `json:"visitor"`
	Service string    `json:"service"`
	Tried   string    `json:"tried"`
}

type fixtureTraceCanary struct {
	ID    string       `json:"id"`
	Beats []time.Time  `json:"beats"`
	Hits  []fixtureHit `json:"hits"`
}

type fixture struct {
	Canaries struct {
		Canaries []fixtureCanary `json:"canaries"`
	} `json:"canaries"`
	Trace struct {
		Now      time.Time            `json:"now"`
		Canaries []fixtureTraceCanary `json:"canaries"`
	} `json:"trace"`
}

// insertAlertQuery matches store.InsertAlertIfNew's column list, minus
// event_id -- store is read-only over the alerts table for everything
// else (see internal/store/store.go's package doc), so this seed script
// writes the same statement directly rather than adding a second write
// path to that package.
const insertAlertQuery = `
INSERT INTO alerts (instance_id, source_ip, dest_port, service, raw, received_at)
VALUES (?, ?, ?, ?, ?, ?)`

// receivedAtLayout matches internal/store's own private receivedAtLayout
// (time.RFC3339Nano) -- every TEXT timestamp column in this database is
// written in this layout, and a mismatch here would make the store
// package's julianday()-based range comparisons misread these rows.
const receivedAtLayout = time.RFC3339Nano

// servicePort maps the services night.json's hits actually use to the
// canary port each was recorded against, for the alerts.dest_port column
// -- store.wellKnownPortNames' display-string mapping runs the other way
// and is unexported, so this is the small reverse slice this script
// needs, not a copy of the whole table.
var servicePort = map[string]int{
	"ftp":    21,
	"ssh":    22,
	"telnet": 23,
	"http":   80,
	"smb":    445,
	"mysql":  3306,
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: seed-story <sqlite-db-path>")
		os.Exit(1)
	}
	dbPath := os.Args[1]

	fx, err := loadFixture()
	if err != nil {
		log.Fatalf("seed-story: load fixture: %v", err)
	}

	ctx := context.Background()
	database, err := db.Open(dbPath)
	if err != nil {
		log.Fatalf("seed-story: open database: %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			log.Fatalf("seed-story: close database: %v", err)
		}
	}()
	if err := db.Migrate(ctx, database); err != nil {
		log.Fatalf("seed-story: migrate database: %v", err)
	}

	now := time.Now().UTC()
	shift := now.Sub(fx.Trace.Now)
	enrolledAt := now.Add(-30 * 24 * time.Hour)

	for _, c := range fx.Canaries.Canaries {
		if err := store.InsertCanary(ctx, database, store.Canary{
			ID:         c.ID,
			Name:       c.Name,
			Lane:       c.Lane,
			Ports:      rawPorts(c.Ports),
			EnrolledAt: enrolledAt,
		}); err != nil {
			log.Fatalf("seed-story: insert canary %s: %v", c.ID, err)
		}
	}

	for _, tc := range fx.Trace.Canaries {
		// Oldest first: RecordHeartbeat sets last_heartbeat_at to
		// whichever call came last, unconditionally (no max check), so
		// the fixture's newest-first beat order must be reversed here
		// or the canary would end up looking silent.
		beats := append([]time.Time(nil), tc.Beats...)
		for i, j := 0, len(beats)-1; i < j; i, j = i+1, j-1 {
			beats[i], beats[j] = beats[j], beats[i]
		}
		for _, beat := range beats {
			if err := store.RecordHeartbeat(ctx, database, tc.ID, beat.Add(shift)); err != nil {
				log.Fatalf("seed-story: record heartbeat for %s: %v", tc.ID, err)
			}
		}

		for _, h := range tc.Hits {
			raw, err := hitRaw(h.Service, h.Tried)
			if err != nil {
				log.Fatalf("seed-story: build raw for %s hit: %v", tc.ID, err)
			}
			_, err = database.ExecContext(ctx, insertAlertQuery,
				tc.ID, h.Visitor, servicePort[h.Service], h.Service, raw,
				h.At.Add(shift).UTC().Format(receivedAtLayout))
			if err != nil {
				log.Fatalf("seed-story: insert alert for %s: %v", tc.ID, err)
			}
		}
	}

	fmt.Printf("seeded %s: %d canaries, now shifted by %s\n", dbPath, len(fx.Canaries.Canaries), shift)
}

// loadFixture reads frontend/src/dev/fixtures/night.json relative to this
// source file's own location (via runtime.Caller), not the process's
// working directory -- so `go run ./cmd/seed-story` and `go test` invoking
// this package both find it regardless of where they were started from.
func loadFixture() (*fixture, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("could not determine this source file's own path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	path := filepath.Join(repoRoot, "frontend", "src", "dev", "fixtures", "night.json")

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var fx fixture
	if err := json.Unmarshal(data, &fx); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &fx, nil
}

// rawPorts reverses store.portsDisplay's "ssh 22 · http 80 · smb 445"
// presentation string back to the raw comma-separated port list
// InsertCanary's Ports field expects ("22,80,445") -- the fixture only
// carries the display form (it's what the frontend actually reads), so
// this seed script is the one place that needs the reverse.
func rawPorts(display string) string {
	parts := strings.Split(display, " · ")
	ports := make([]string, 0, len(parts))
	for _, p := range parts {
		fields := strings.Fields(p)
		if len(fields) == 2 {
			ports = append(ports, fields[1])
		}
	}
	return strings.Join(ports, ",")
}

// hitRaw builds a minimal alerts.raw value that store.triedFor's own
// extractLogData/logString parsing (internal/store/visitor.go) reads
// back correctly for service -- a bare {"logdata": {...}} JSON object is
// enough, since extractLogData looks for the first '{' byte and decodes
// from there, the same as a real OpenCanary log payload but without the
// syslog envelope this script has no need to fabricate.
func hitRaw(service, tried string) (string, error) {
	logdata := map[string]string{}
	switch service {
	case "ssh", "telnet", "ftp", "mysql":
		username, password, _ := strings.Cut(tried, " / ")
		if password == "(empty)" {
			password = ""
		}
		logdata["USERNAME"] = username
		logdata["PASSWORD"] = password
	case "http":
		logdata["PATH"] = tried
	// smb and anything else: triedFor falls back to a fixed label
	// ("smb", or the bare service name) when SHARENAME is absent, so an
	// empty logdata object is enough.
	default:
	}
	b, err := json.Marshal(map[string]any{"logdata": logdata})
	if err != nil {
		return "", err
	}
	return string(b), nil
}
