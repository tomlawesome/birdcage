package web

import (
	"io/fs"
	"net/http/httptest"
	"testing"
)

// TestDistFSAlwaysCompilesAndOpens is the property .gitkeep exists for:
// the embed pattern must match something on a fresh clone where
// nothing has been built, or the whole module stops compiling. If this
// test is running at all the compile-time half already held, so what's
// left to check is that fs.Sub finds the directory rather than
// erroring.
func TestDistFSAlwaysCompilesAndOpens(t *testing.T) {
	if _, err := DistFS(); err != nil {
		t.Fatalf("DistFS() = %v, want no error even with an unbuilt dist/", err)
	}
}

// TestHasUIFollowsIndexHTML pins HasUI to the one thing it claims to
// report, without hardcoding whether a frontend has actually been
// built in this checkout -- that's a property of the checkout, not
// the code.
func TestHasUIFollowsIndexHTML(t *testing.T) {
	dist, err := DistFS()
	if err != nil {
		t.Fatal(err)
	}
	_, statErr := fs.Stat(dist, "index.html")
	built := statErr == nil

	if got := HasUI(); got != built {
		t.Errorf("HasUI() = %v, but index.html present = %v -- these must agree", got, built)
	}
}

// TestHandlerNeverErrorsOnAnUnbuiltDist mirrors HasUI's property for
// Handler: go build must succeed against a fresh clone, and so must
// constructing the handler that main.go mounts at "/".
func TestHandlerNeverErrorsOnAnUnbuiltDist(t *testing.T) {
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler() = %v, want no error even with an unbuilt dist/", err)
	}

	// Whatever dist/ contains right now, the handler must respond
	// without panicking -- this is the same request main.go's rootMux
	// will forward for any path outside /api/.
	req := httptest.NewRequest("GET", "/some/client-route", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == 0 {
		t.Fatal("Handler did not write a response")
	}
}
