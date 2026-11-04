package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/alarmdelivery"
	"localrmm/internal/health"
)

// Existing v1 reads remain nonmutating. Once a schedule exists, every observed
// manager time is durably fenced before it can affect display or dispatch.
func (s *Store) HealthStateAt(ctx context.Context, id string, now time.Time, clocks ...func() time.Time) (health.State, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return health.State{}, err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT body FROM health_devices WHERE id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return health.New(), nil
	}
	if err != nil {
		return health.State{}, err
	}
	state, err := decodeHealth(raw)
	if err != nil {
		return state, err
	}
	if len(clocks) > 0 {
		if len(clocks) != 1 || clocks[0] == nil {
			return health.State{}, health.ErrInvalid
		}
		fresh := clocks[0]().UTC()
		if fresh.Before(now) {
			return health.State{}, health.ErrInvalid
		}
		now = fresh
	}
	if err = observeHealthMaintenance(ctx, tx, id, &state, now); err != nil {
		return health.State{}, err
	}
	if err = consumeScheduledOpenings(ctx, tx, id, state, now); err != nil {
		return health.State{}, err
	}
	if err = tx.Commit(); err != nil {
		return health.State{}, err
	}
	return state, nil
}
func observeHealthMaintenance(ctx context.Context, tx *sql.Tx, id string, state *health.State, now time.Time) error {
	if state.Schedule == nil {
		return nil
	}
	if err := state.ObserveMaintenance(now); err != nil {
		return err
	}
	if state.Validate() != nil {
		return health.ErrInvalid
	}
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > health.MaxStateBytes {
		return health.ErrInvalid
	}
	_, err = tx.ExecContext(ctx, `UPDATE health_devices SET body=? WHERE id=?`, raw, id)
	return err
}

// Read all queued openings, not just due ones. Original payload time retains
// nanosecond early-end boundaries; the outbox's millisecond index is not enough.
func consumeScheduledOpenings(ctx context.Context, tx *sql.Tx, id string, state health.State, now time.Time) error {
	if state.Schedule == nil {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,body FROM alarm_outbox WHERE device=? AND state='queued' AND transition='opened' LIMIT ?`, id, alarmdelivery.MaxPending+1)
	if err != nil {
		return err
	}
	type item struct {
		id string
		at time.Time
	}
	items := []item{}
	for rows.Next() {
		var key string
		var raw []byte
		var p alarmdelivery.Payload
		if rows.Scan(&key, &raw) != nil || len(raw) > alarmdelivery.MaxPayloadBytes || json.Unmarshal(raw, &p) != nil || p.EventID != key || p.DeviceID != id || p.Transition != "opened" || p.TransitionAt.IsZero() {
			rows.Close()
			return health.ErrInvalid
		}
		items = append(items, item{key, p.TransitionAt})
		if len(items) > alarmdelivery.MaxPending {
			rows.Close()
			return health.ErrInvalid
		}
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, x := range items {
		if state.ScheduledOpeningSuppressed(x.at, now) {
			if _, err = tx.ExecContext(ctx, `UPDATE alarm_outbox SET state='suppressed',code='maintenance',finished=? WHERE id=? AND state='queued'`, now.UnixMilli(), x.id); err != nil {
				return err
			}
		}
	}
	return nil
}
func observeScheduledHealthAlarms(ctx context.Context, tx *sql.Tx, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,body FROM health_devices WHERE json_extract(body,'$.version')=2 LIMIT 26`)
	if err != nil {
		return err
	}
	type item struct {
		id    string
		state health.State
	}
	items := []item{}
	for rows.Next() {
		var id string
		var raw []byte
		if rows.Scan(&id, &raw) != nil {
			rows.Close()
			return health.ErrInvalid
		}
		state, e := decodeHealth(raw)
		if e != nil {
			rows.Close()
			return e
		}
		items = append(items, item{id, state})
		if len(items) > 25 {
			rows.Close()
			return health.ErrInvalid
		}
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, x := range items {
		now, err = health.MaintenanceNow(ctx, now)
		if err != nil {
			return err
		}
		if err = observeHealthMaintenance(ctx, tx, x.id, &x.state, now); err != nil {
			return err
		}
		if err = consumeScheduledOpenings(ctx, tx, x.id, x.state, now); err != nil {
			return err
		}
	}
	return nil
}
