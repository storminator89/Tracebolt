package lanstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"localrmm/internal/lantrust"
	"localrmm/internal/managerstatus"
)

func (s *Store) ManagerStatus(ctx context.Context) managerstatus.ProbeResult {
	if s == nil {
		return managerstatus.ProbeResult{State: managerstatus.Unavailable}
	}
	return managerstatus.SQLiteProbe(ctx, s.db, func(ctx context.Context, c *sql.Conn) (managerstatus.ProbeResult, error) {
		rows, err := c.QueryContext(ctx, "SELECT id,fingerprint,substr(body,1,65537) FROM lan_agents ORDER BY id LIMIT ?", lantrust.MaxAgents+1)
		if err != nil {
			return managerstatus.ProbeResult{}, err
		}
		count := 0
		for rows.Next() {
			var id, fp string
			var body []byte
			var agent lantrust.Agent
			if err = rows.Scan(&id, &fp, &body); err != nil {
				break
			}
			if len(body) > 65536 || json.Unmarshal(body, &agent) != nil || agent.ID != id || agent.FingerprintSHA256 != fp {
				err = ErrStorage
				break
			}
			count++
		}
		if err == nil {
			err = rows.Err()
		}
		_ = rows.Close()
		if err != nil {
			return managerstatus.ProbeResult{}, err
		}
		if count > lantrust.MaxAgents {
			return managerstatus.ProbeResult{State: managerstatus.Invalid}, nil
		}
		rows, err = c.QueryContext(ctx, "SELECT agent_id,sequence,generated_at,collected_at,received_at,payload_hash,body FROM lan_samples LIMIT 1")
		if err != nil {
			return managerstatus.ProbeResult{}, err
		}
		err = rows.Close()
		result := managerstatus.ProbeResult{State: managerstatus.OK, Capacity: &managerstatus.CapacityMetrics{Used: count, Limit: lantrust.MaxAgents}}
		if count == lantrust.MaxAgents {
			result.State = managerstatus.Full
		}
		return result, err
	})
}
