// SPDX-License-Identifier: LicenseRef-Birdcage-Noncommercial-1.0

package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// Issue #164: a line logged with Always passes a raised threshold; every
// other line still follows it.
func TestAlwaysPassesTheThreshold(t *testing.T) {
	var buf bytes.Buffer
	h := &handler{w: &buf, level: slog.LevelError, color: false, mu: &sync.Mutex{}}
	log := slog.New(h).With(slog.String("component", "auth"))

	log.Warn("ordinary warning")
	log.Log(Always(context.Background()), slog.LevelWarn, "code line")

	out := buf.String()
	if strings.Contains(out, "ordinary warning") {
		t.Errorf("ordinary Warn line written at level error:\n%s", out)
	}
	if !strings.Contains(out, "code line") {
		t.Errorf("Always line missing at level error:\n%s", out)
	}
}
