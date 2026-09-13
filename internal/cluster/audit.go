package cluster

import (
	"context"
	"fmt"
	"time"

	core "github.com/gantry-tools/gantry-core/cluster"
)

func (s *Service) Audit(ctx context.Context, actorUserID, organizationID int64, action, target, requestID string) error {
	if action == "" {
		return nil
	}
	detail := ""
	if requestID != "" {
		detail = fmt.Sprintf("request_id=%s", requestID)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO security_audit(actor_user_id,organization_id,action,target,detail,created_at) VALUES(?,?,?,?,?,?)`, actorUserID, organizationID, action, target, detail, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Service) RecentAudit(ctx context.Context, limit int) ([]core.AuditView, error) {
	if limit < 1 || limit > 100 {
		limit = 25
	}
	rows, err := s.db.QueryContext(ctx, `SELECT created_at,action,target,detail FROM security_audit WHERE action LIKE 'cluster.%' ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.AuditView{}
	for rows.Next() {
		var at, action, nodeID, detail string
		if err := rows.Scan(&at, &action, &nodeID, &detail); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339Nano, at)
		out = append(out, core.AuditView{At: t, Action: action, NodeID: nodeID, Detail: detail})
	}
	return out, rows.Err()
}
