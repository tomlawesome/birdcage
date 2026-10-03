package probe

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestProbeRDP_PlantsMarkerAsMstshashCookie(t *testing.T) {
	port, lineCh := acceptOneAndRead(t, "")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeRDP(ctx, "127.0.0.1", port, "marker-rdp"); err != nil {
		t.Fatalf("probeRDP: %v", err)
	}

	select {
	case line := <-lineCh:
		if !strings.Contains(line, "Cookie: mstshash=marker-rdp") {
			t.Errorf("packet %q does not carry the marker as the mstshash cookie", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the connection request")
	}
}
