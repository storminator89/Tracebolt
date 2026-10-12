package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsservicehealth"
)

// This isolated table never feeds health analyses or alarm delivery.
const windowsServiceSchema = `CREATE TABLE IF NOT EXISTS windows_service_devices(id TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=262144 AND json_valid(body)))`

func decodeWindowsService(id string, raw []byte) (windowsservicehealth.State, error) {
	state, err := windowsservicehealth.Decode(raw)
	if err != nil || state.DeviceID != id || !windowscontact.ValidDeviceID(id) {
		return windowsservicehealth.State{}, windowsservicehealth.ErrInvalid
	}
	return state, nil
}

// WindowsServiceState performs no writes, resets or pruning. Missing state is
// unknown; malformed retained history is an error and is never replaced.
func (s *Store) WindowsServiceState(ctx context.Context, id string) (windowsservicehealth.State, error) {
	if !windowscontact.ValidDeviceID(id) {
		return windowsservicehealth.State{}, windowsservicehealth.ErrInvalid
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT body FROM windows_service_devices WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return windowsservicehealth.New(), nil
	}
	if err != nil {
		return windowsservicehealth.State{}, err
	}
	return decodeWindowsService(id, raw)
}

func (s *Store) WindowsServiceStates(ctx context.Context) (map[string]windowsservicehealth.State, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,body FROM windows_service_devices ORDER BY id LIMIT 26")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]windowsservicehealth.State{}
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		state, err := decodeWindowsService(id, raw)
		if err != nil {
			return nil, err
		}
		out[id] = state
		if len(out) > windowsservicehealth.MaxDevices {
			return nil, windowsservicehealth.ErrInvalid
		}
	}
	return out, rows.Err()
}

// EvaluateWindowsService atomically loads, evaluates, validates, prunes and
// stores exactly one device. Cancellation and all errors leave its ledger intact.
// The process epoch is supplied by the manager monitor and is never authority.
func (s *Store) EvaluateWindowsService(ctx context.Context, input windowsservicehealth.Input, now time.Time, epoch string) (windowsservicehealth.State, error) {
	return s.updateWindowsService(ctx, input.DeviceID, func(state *windowsservicehealth.State) error { return state.Evaluate(input, now, epoch) })
}
func (s *Store) ConfigureWindowsService(ctx context.Context, input windowsservicehealth.Input, enabled bool, names []string, expected uint64, now time.Time) (windowsservicehealth.State, error) {
	return s.updateWindowsService(ctx, input.DeviceID, func(state *windowsservicehealth.State) error {
		return state.Configure(input, enabled, names, expected, now)
	})
}
func (s *Store) updateWindowsService(ctx context.Context, id string, update func(*windowsservicehealth.State) error) (windowsservicehealth.State, error) {
	if !windowscontact.ValidDeviceID(id) {
		return windowsservicehealth.State{}, windowsservicehealth.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return windowsservicehealth.State{}, err
	}
	defer tx.Rollback()
	state := windowsservicehealth.New()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM windows_service_devices").Scan(&count); err != nil {
		return windowsservicehealth.State{}, err
	}
	if count > windowsservicehealth.MaxDevices {
		return windowsservicehealth.State{}, windowsservicehealth.ErrInvalid
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT body FROM windows_service_devices WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		if count >= windowsservicehealth.MaxDevices {
			return windowsservicehealth.State{}, windowsservicehealth.ErrInvalid
		}
	} else if err != nil {
		return windowsservicehealth.State{}, err
	} else {
		state, err = decodeWindowsService(id, raw)
		if err != nil {
			return windowsservicehealth.State{}, err
		}
	}
	beforeNotifications := serviceNotificationEpisodes(state)
	if err = update(&state); err != nil {
		return windowsservicehealth.State{}, err
	}
	if state.DeviceID != id {
		return windowsservicehealth.State{}, windowsservicehealth.ErrInvalid
	}
	body, err := windowsservicehealth.Encode(state)
	if err != nil {
		return windowsservicehealth.State{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO windows_service_devices(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", id, body); err != nil {
		return windowsservicehealth.State{}, err
	}
	if err = enqueueWindowsNotifications(ctx, tx, beforeNotifications, serviceNotificationEpisodes(state)); err != nil {
		return windowsservicehealth.State{}, err
	}
	if err = tx.Commit(); err != nil {
		return windowsservicehealth.State{}, err
	}
	return state, nil
}
