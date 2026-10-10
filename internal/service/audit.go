package service

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditService writes the spec-5.5 audit trail (DB-first; Kafka deferred).
// Every admin/auth action appends one row queryable by actor + time (AC-5-7).
type AuditService struct {
	pool *pgxpool.Pool
}

func NewAuditService(pool *pgxpool.Pool) *AuditService {
	return &AuditService{pool: pool}
}

// Log records one audit row. detail may be nil. Never fails the caller's
// request — a broken audit sink must not break login/admin actions.
func (a *AuditService) Log(ctx context.Context, actor, action, target, ip string, detail map[string]any) {
	if a == nil || a.pool == nil {
		return
	}
	var d []byte
	if detail != nil {
		d, _ = json.Marshal(detail)
	}
	_, _ = a.pool.Exec(ctx,
		`INSERT INTO auth.audit_log (actor, action, target, ip, detail) VALUES ($1,$2,$3,$4,$5)`,
		actor, action, nullIfEmpty(target), nullIfEmpty(ip), nullIfEmpty(string(d)),
	)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
