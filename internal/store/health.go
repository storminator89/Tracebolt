package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/health"
	"time"
)

const healthSchema = `CREATE TABLE IF NOT EXISTS health_devices(id TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=131072 AND json_valid(body)))`

// HealthState is derived operator state, deliberately separate from the enrolled
// credential/telemetry ledger. One bounded record is retained per pilot device.
func (s *Store) HealthState(ctx context.Context, id string) (health.State, error) {
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT body FROM health_devices WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return health.New(), nil
	}
	if err != nil {
		return health.State{}, err
	}
	return decodeHealth(raw)
}
func decodeHealth(raw []byte) (health.State, error) {
	var state health.State
	if len(raw) == 0 || len(raw) > health.MaxStateBytes || json.Unmarshal(raw, &state) != nil || state.Validate() != nil {
		return health.State{}, health.ErrInvalid
	}
	return state, nil
}
func (s *Store) HealthStates(ctx context.Context) (map[string]health.State, error) {
	rows, e := s.db.QueryContext(ctx, "SELECT id,body FROM health_devices LIMIT 26")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := map[string]health.State{}
	for rows.Next() {
		var id string
		var raw []byte
		if e = rows.Scan(&id, &raw); e != nil {
			return nil, e
		}
		state, e := decodeHealth(raw)
		if e != nil {
			return nil, e
		}
		out[id] = state
		if len(out) > 25 {
			return nil, health.ErrInvalid
		}
	}
	return out, rows.Err()
}
func (s *Store) UpdateHealth(ctx context.Context, id string, fn func(*health.State) error) (health.State, error) {
	return s.updateHealth(ctx, id, func(h *health.State) ([]health.Incident, error) { return nil, fn(h) })
}

// EvaluateHealth captures exact evaluator transitions before history pruning.
func (s *Store) EvaluateHealth(ctx context.Context, input health.Input, now time.Time) (health.State, error) {
	return s.updateHealth(ctx, input.DeviceID, func(h *health.State) ([]health.Incident, error) { return h.EvaluateTransitions(input, now), nil })
}
func (s *Store) updateHealth(ctx context.Context, id string, fn func(*health.State) ([]health.Incident, error)) (health.State, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return health.State{}, e
	}
	defer tx.Rollback()
	state := health.New()
	var raw []byte
	e = tx.QueryRowContext(ctx, "SELECT body FROM health_devices WHERE id=?", id).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		var count int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM health_devices").Scan(&count); e != nil {
			return state, e
		}
		if count >= 25 {
			return state, health.ErrInvalid
		}
	} else if e != nil {
		return state, e
	} else {
		state, e = decodeHealth(raw)
		if e != nil {
			return state, e
		}
	}
	before := append([]health.Incident{}, state.Incidents...)
	transitions, e := fn(&state)
	if e != nil {
		return state, e
	}
	if e = state.Validate(); e != nil {
		return state, e
	}
	body, e := json.Marshal(state)
	if e != nil || len(body) > health.MaxStateBytes {
		return state, health.ErrInvalid
	}
	if _, e = tx.ExecContext(ctx, "INSERT INTO health_devices(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", id, body); e != nil {
		return state, e
	}
	if e = recoverHealthAnalyses(ctx, tx, id, state, transitions); e != nil {
		return state, e
	}
	if e = enqueueHealthAlarms(ctx, tx, id, before, state, transitions); e != nil {
		return state, e
	}
	if e = tx.Commit(); e != nil {
		return state, e
	}
	return state, nil
}
