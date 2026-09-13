// Package db opens birdcage's database -- SQLite (the default) or
// Postgres, selected by DATABASE_URL -- and applies its schema
// migrations.
package db

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Engine identifies which database backend a *DB is driving. A handful
// of queries (internal/store's received_at range comparisons) are not
// expressible identically on both engines and switch on this.
type Engine int

const (
	SQLite Engine = iota
	Postgres
)

func (e Engine) String() string {
	if e == Postgres {
		return "postgres"
	}
	return "sqlite"
}

// DB wraps *sql.DB together with which Engine it is driving. Its
// Exec/Query/QueryRow methods (and their Context variants) shadow the
// embedded *sql.DB's own, rebinding "?" placeholders to Postgres' "$1,
// $2, ..." style first when Engine is Postgres -- every query in this
// codebase is written with "?", the SQLite convention, and modernc's
// SQLite driver accepts "$1"-style just as well (verified empirically
// rather than assumed, per AGENTS.md), so a single rebind at this one
// seam is enough to make every caller's SQL portable without a
// per-query dialect branch.
type DB struct {
	*sql.DB
	Engine Engine
}

func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, d.rebind(query), args...)
}

func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, d.rebind(query), args...)
}

func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, d.rebind(query), args...)
}

func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	return d.ExecContext(context.Background(), query, args...)
}

func (d *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return d.QueryContext(context.Background(), query, args...)
}

func (d *DB) QueryRow(query string, args ...any) *sql.Row {
	return d.QueryRowContext(context.Background(), query, args...)
}

func (d *DB) rebind(query string) string {
	if d.Engine != Postgres {
		return query
	}
	return Rebind(query)
}

// Rebind rewrites every "?" placeholder in query to Postgres' "$1, $2,
// ..." positional style, in order of appearance, skipping "?" characters
// inside single-quoted string literals (a doubled quote mark is the
// standard SQL escape for a literal quote inside one). None of
// birdcage's own SQL contains a literal "?" inside a string, but the
// scan is literal-aware anyway rather than assuming that stays true.
func Rebind(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	inString := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\'':
			inString = !inString
			b.WriteByte(c)
		case c == '?' && !inString:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Open opens the database identified by databaseURL and returns it
// unmigrated -- call Migrate (or any query) to surface configuration
// errors, since sql.Open itself never touches the network or disk.
//
// databaseURL selects the engine:
//   - "" (unset) or a bare path with no recognized scheme: SQLite at
//     that path (or at the caller's own default, e.g. cmd/birdcage's
//     "birdcage.db", if databaseURL is empty and the caller passes its
//     own default through instead) -- this is the pre-Postgres default
//     and its behavior is unchanged.
//   - "sqlite:PATH": SQLite at PATH.
//   - "postgres://..." or "postgresql://...": Postgres via
//     github.com/jackc/pgx/v5's database/sql stdlib adapter.
func Open(databaseURL string) (*DB, error) {
	switch {
	case strings.HasPrefix(databaseURL, "postgres://"), strings.HasPrefix(databaseURL, "postgresql://"):
		return openPostgres(databaseURL)
	case strings.HasPrefix(databaseURL, "sqlite:"):
		return openSQLite(strings.TrimPrefix(databaseURL, "sqlite:"))
	default:
		// Empty, or a bare filesystem path: SQLite, same as before
		// DATABASE_URL existed.
		return openSQLite(databaseURL)
	}
}

// openSQLite opens the SQLite database at path using the pure-Go
// modernc.org/sqlite driver. The file is created on first use.
//
// Two settings guard against SQLITE_BUSY under concurrent access:
//   - database/sql pools multiple connections by default, and this
//     driver's default rollback-journal mode gives any connection that
//     reads while another is mid-write an immediate SQLITE_BUSY, with no
//     retry. SetMaxOpenConns(1) forces all access (the ingest server's
//     inserts and any future reader, e.g. the dashboard in #3) through a
//     single connection, so database/sql itself serializes access and
//     SQLite never sees concurrent connections to race. This constraint
//     is SQLite-specific: Postgres handles concurrent connections
//     natively and openPostgres below does not apply it.
//   - busy_timeout is set defensively on top of that, so any lock SQLite
//     itself still needs to wait on (e.g. during a checkpoint) is retried
//     for up to 5s instead of failing immediately, rather than relying
//     solely on the single-connection invariant above.
func openSQLite(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	return &DB{DB: sqlDB, Engine: SQLite}, nil
}

// openPostgres opens a Postgres database via pgx's database/sql stdlib
// adapter (github.com/jackc/pgx/v5/stdlib), registered as driver
// "pgx" by that package's own init(). pgx/v5 was chosen over
// lib/pq (unmaintained since 2021) and the older jackc/pgx v4: it is
// pure Go (no cgo, matching the SQLite driver's build story into a
// CGO_ENABLED=0 distroless image), actively maintained, and the
// standard choice for Go+Postgres as of 2026.
func openPostgres(databaseURL string) (*DB, error) {
	sqlDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	return &DB{DB: sqlDB, Engine: Postgres}, nil
}
