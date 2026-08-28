// Package db opens birdcage's SQLite database and applies its schema
// migrations.
package db

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

// Open opens the SQLite database at path using the pure-Go
// modernc.org/sqlite driver. The file is created on first use; sql.Open
// itself does not touch the disk, so call Migrate (or any query) to
// surface configuration errors.
//
// Two settings guard against SQLITE_BUSY under concurrent access:
//   - database/sql pools multiple connections by default, and this
//     driver's default rollback-journal mode gives any connection that
//     reads while another is mid-write an immediate SQLITE_BUSY, with no
//     retry. SetMaxOpenConns(1) forces all access (the ingest server's
//     inserts and any future reader, e.g. the dashboard in #3) through a
//     single connection, so database/sql itself serializes access and
//     SQLite never sees concurrent connections to race.
//   - busy_timeout is set defensively on top of that, so any lock SQLite
//     itself still needs to wait on (e.g. during a checkpoint) is retried
//     for up to 5s instead of failing immediately, rather than relying
//     solely on the single-connection invariant above.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
