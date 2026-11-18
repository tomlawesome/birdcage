package store

import (
	"context"
	"fmt"

	"github.com/tomlawesome/birdcage/internal/db"
)

// DatabaseHistory is what makes a database "not new" for the restore
// guard (issue #164, note 63632): enrolled agents, findings, or
// birdcage's own audit rows. Settings alone do not count, since an
// operator may set them before the first start.
type DatabaseHistory struct {
	Agents, Findings, AuditRows int
}

// InUse reports whether the database holds any of that history.
func (h DatabaseHistory) InUse() bool {
	return h.Agents > 0 || h.Findings > 0 || h.AuditRows > 0
}

// ReadDatabaseHistory counts the rows DatabaseHistory looks at.
func ReadDatabaseHistory(ctx context.Context, conn db.Conn) (DatabaseHistory, error) {
	var h DatabaseHistory
	for _, c := range []struct {
		table string
		n     *int
	}{{"agents", &h.Agents}, {"findings", &h.Findings}, {"audit_log", &h.AuditRows}} {
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+c.table).Scan(c.n); err != nil {
			return DatabaseHistory{}, fmt.Errorf("count %s: %w", c.table, err)
		}
	}
	return h, nil
}
