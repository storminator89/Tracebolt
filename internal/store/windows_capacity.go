package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
)

// This isolated table never feeds health analyses or alarm delivery.
const windowsCapacitySchema = `CREATE TABLE IF NOT EXISTS windows_capacity_devices(id TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=131072 AND json_valid(body)))`

func decodeWindowsCapacity(id string, raw []byte) (windowscapacity.State, error) {
	state, err := windowscapacity.Decode(raw)
	if err != nil || state.DeviceID != id || !windowscontact.ValidDeviceID(id) {
		return windowscapacity.State{}, windowscapacity.ErrInvalid
	}
	return state, nil
}

// WindowsCapacityState performs no writes, resets or pruning. Missing state is
// unknown; malformed retained history is an error and is never replaced.
func (s *Store) WindowsCapacityState(ctx context.Context, id string) (windowscapacity.State, error) {
	if !windowscontact.ValidDeviceID(id) {
		return windowscapacity.State{}, windowscapacity.ErrInvalid
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT body FROM windows_capacity_devices WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return windowscapacity.New(), nil
	}
	if err != nil {
		return windowscapacity.State{}, err
	}
	return decodeWindowsCapacity(id, raw)
}

func (s *Store) WindowsCapacityStates(ctx context.Context) (map[string]windowscapacity.State, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,body FROM windows_capacity_devices ORDER BY id LIMIT 26")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]windowscapacity.State{}
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		state, err := decodeWindowsCapacity(id, raw)
		if err != nil {
			return nil, err
		}
		out[id] = state
		if len(out) > windowscapacity.MaxDevices {
			return nil, windowscapacity.ErrInvalid
		}
	}
	return out, rows.Err()
}

// EvaluateWindowsCapacity atomically loads, evaluates, validates, prunes and
// stores exactly one device. Cancellation and all errors leave its ledger intact.
// The process epoch is supplied by the manager monitor and is never authority.
func (s *Store) EvaluateWindowsCapacity(ctx context.Context, input windowscapacity.Input, now time.Time, epoch string) (windowscapacity.State, error) {
	return s.updateWindowsCapacity(ctx, input.DeviceID, func(state *windowscapacity.State) error { return state.Evaluate(input, now, epoch) })
}
func (s *Store) ConfigureWindowsCapacity(ctx context.Context, input windowscapacity.Input, enabled bool, threshold int, expected uint64, now time.Time, guard ...func() error) (windowscapacity.State, error) {
	return s.updateWindowsCapacity(ctx, input.DeviceID, func(state *windowscapacity.State) error {
		return state.Configure(input, enabled, threshold, expected, now)
	}, guard...)
}
func (s *Store) updateWindowsCapacity(ctx context.Context, id string, update func(*windowscapacity.State) error, guard ...func() error) (windowscapacity.State, error) {
	if !windowscontact.ValidDeviceID(id) {
		return windowscapacity.State{}, windowscapacity.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return windowscapacity.State{}, err
	}
	defer tx.Rollback()
	state := windowscapacity.New()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM windows_capacity_devices").Scan(&count); err != nil {
		return windowscapacity.State{}, err
	}
	if count > windowscapacity.MaxDevices {
		return windowscapacity.State{}, windowscapacity.ErrInvalid
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT body FROM windows_capacity_devices WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		if count >= windowscapacity.MaxDevices {
			return windowscapacity.State{}, windowscapacity.ErrInvalid
		}
	} else if err != nil {
		return windowscapacity.State{}, err
	} else {
		state, err = decodeWindowsCapacity(id, raw)
		if err != nil {
			return windowscapacity.State{}, err
		}
	}
	if err = runPolicyGuards(ctx, guard); err != nil {
		return windowscapacity.State{}, err
	}
	beforeNotifications := capacityNotificationEpisodes(state, "disk")
	if err = update(&state); err != nil {
		return windowscapacity.State{}, err
	}
	if state.DeviceID != id {
		return windowscapacity.State{}, windowscapacity.ErrInvalid
	}
	body, err := windowscapacity.Encode(state)
	if err != nil {
		return windowscapacity.State{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO windows_capacity_devices(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", id, body); err != nil {
		return windowscapacity.State{}, err
	}
	if err = enqueueWindowsNotifications(ctx, tx, beforeNotifications, capacityNotificationEpisodes(state, "disk")); err != nil {
		return windowscapacity.State{}, err
	}
	if err = runPolicyGuards(ctx, guard); err != nil {
		return windowscapacity.State{}, err
	}
	if err = tx.Commit(); err != nil {
		return windowscapacity.State{}, err
	}
	return state, nil
}

// Guards run after acquiring the single SQLite connection and immediately before
// commit. They may inspect live clocks/session cancellation only; acquiring the
// enrollment database here would invert the existing lock order.
func runPolicyGuards(ctx context.Context, guards []func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, guard := range guards {
		if guard == nil {
			return windowscapacity.ErrInvalid
		}
		if err := guard(); err != nil {
			return err
		}
	}
	return nil
}
