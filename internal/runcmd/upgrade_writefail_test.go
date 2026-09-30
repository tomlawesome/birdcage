package runcmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agentkind"
)

var errWriteFailed = errors.New("write failed")

// failAfterWriter accepts n writes, then fails every write after them.
type failAfterWriter struct {
	n   int
	out strings.Builder
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.n == 0 {
		return 0, errWriteFailed
	}
	w.n--
	return w.out.Write(p)
}

// TestUpgradeStopsAtTheFirstFailedWrite fails the writer at every write
// in turn, for every script shape. An operator pastes this script into a
// shell, so a failed write must come back as an error, never as a
// shorter script that looks whole -- a script cut off after the removal
// lines would leave a canary with its containers gone and nothing
// started.
func TestUpgradeStopsAtTheFirstFailedWrite(t *testing.T) {
	base := UpgradeInput{
		UpgradeToken:    testUpgradeToken,
		AdvertiseHost:   "canary.example.com",
		EnrolPort:       "8444",
		Pin:             "sha256/abc123",
		AgentImage:      "agent:latest",
		HolderImage:     "holder:latest",
		OpenCanaryImage: "opencanary:latest",
		SMBLureImage:    "smb-lure:latest",
		SMBWorkgroup:    "WORKGROUP",
		SMBShares:       []string{"public", "backup", "scans"},
	}
	shapes := map[string]UpgradeInput{}
	for name, lure := range map[string]*bool{"lure on": boolPtr(true), "lure off": boolPtr(false), "lure unknown": nil} {
		in := base
		in.Kind = agentkind.Honeypot
		in.SMBLure = lure
		shapes["honeypot, "+name] = in
	}
	scanner := base
	scanner.Kind = agentkind.Scanner
	shapes["scanner"] = scanner

	for name, in := range shapes {
		t.Run(name, func(t *testing.T) {
			var whole strings.Builder
			if err := Upgrade(&whole, in); err != nil {
				t.Fatalf("Upgrade: %v", err)
			}
			for n := 0; ; n++ {
				w := &failAfterWriter{n: n}
				err := Upgrade(w, in)
				if err == nil {
					if w.out.String() != whole.String() {
						t.Fatalf("n=%d: no error, but the script differs from the whole one", n)
					}
					if n == 0 {
						t.Fatal("wrote nothing at all")
					}
					return
				}
				if !errors.Is(err, errWriteFailed) {
					t.Fatalf("n=%d: err = %v, want the write error", n, err)
				}
				if n > 10000 {
					t.Fatal("never finished")
				}
			}
		})
	}
}
