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

// Conn is the minimal query surface a store/audit function needs, so it
// can be handed either a plain *DB or an in-flight *Tx from Begin and
// behave identically either way -- the seam that lets a caller (e.g.
// ingest's rotation handler, issue #32 item 10) run a mint and an audit
// append as one all-or-nothing unit instead of mint-then-undo.
type Conn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Tx wraps *sql.Tx the same way DB wraps *sql.DB: every "?" placeholder
// is rebound to Postgres' "$1, $2, ..." style when the underlying engine
// is Postgres. Distinct from the *sql.Tx returned by the embedded
// *sql.DB.BeginTx (which migrate.go uses directly, pre-dating this type,
// with its own manual per-query rebind calls) -- that existing call is
// untouched by this addition.
type Tx struct {
	*sql.Tx
	engine Engine
}

func (t *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, t.rebind(query), args...)
}

func (t *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, t.rebind(query), args...)
}

// QueryContext rebinds exactly as the two methods above do. The embedded
// *sql.Tx has a QueryContext of its own, which does NOT rebind -- a
// multi-row read inside a transaction had to be shadowed here or it
// would send "?" placeholders straight to Postgres (issue #56's
// per-tick reconcile reads every open state period inside its own
// transaction).
func (t *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, t.rebind(query), args...)
}

func (t *Tx) rebind(query string) string {
	if t.engine != Postgres {
		return query
	}
	return Rebind(query)
}

// Begin starts a transaction on d, returning a *Tx whose ExecContext and
// QueryRowContext rebind exactly as *DB's do, so a Conn-typed function
// works unchanged whether it is handed d itself or a transaction on it.
func (d *DB) Begin(ctx context.Context) (*Tx, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &Tx{Tx: tx, engine: d.Engine}, nil
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
