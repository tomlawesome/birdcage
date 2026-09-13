// Package web embeds the built frontend (frontend/, issue #36) into the
// birdcage binary so the dashboard ships as part of the same
// self-contained executable as the API and the syslog bridge.
//
// dist/ is gitignored except for an empty committed .gitkeep, which
// exists only because go:embed requires its pattern to match at least
// one file at compile time -- the `all:` prefix is what makes a dotfile
// count (mikroview's own web/embed.go carries the same trick, and the
// same reasoning against ever committing a real build in its place).
// Running `npm run build` in frontend/ and copying its output here
// (see the README's "run the frontend" section) fills the directory
// with the real UI before the final `go build`.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// DistFS returns the embedded frontend build, rooted at dist/ so paths
// match what an http.FileServer expects ("index.html", not
// "dist/index.html").
func DistFS() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}

// HasUI reports whether a frontend was actually built into this binary.
// `go build` on a fresh clone succeeds with nothing in dist/ but
// .gitkeep, which is the point of .gitkeep -- so the binary is valid
// and the UI simply is not there. Without this the only symptom is a
// 404 (or, worse, a directory listing of the placeholder) on every
// page load, which reads as a broken install rather than a build step
// that was skipped.
func HasUI() bool {
	dist, err := DistFS()
	if err != nil {
		return false
	}
	if _, err := fs.Stat(dist, "index.html"); err != nil {
		return false
	}
	return true
}

// Handler serves the embedded frontend at "/". Any request whose path
// doesn't match a real file in dist/ falls back to index.html (an SPA
// fallback) so a client-side route -- e.g. a bookmarked or refreshed
// /visitors -- resolves to the app shell rather than a 404. The caller
// mounts this only under "/"; it never sees a request under "/api/",
// so it never needs to steer around that prefix itself.
func Handler() (http.Handler, error) {
	dist, err := DistFS()
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "." || clean == "" {
			clean = "index.html"
		}
		if info, err := fs.Stat(dist, clean); err != nil || info.IsDir() {
			fallback := new(http.Request)
			*fallback = *r
			fallback.URL.Path = "/"
			fileServer.ServeHTTP(w, fallback)
			return
		}
		fileServer.ServeHTTP(w, r)
	}), nil
}
