package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsresource"
)

// No migration or default row derives a resource opt-in from a disk policy.
const windowsResourceSchema = `CREATE TABLE IF NOT EXISTS windows_resource_devices(id TEXT NOT NULL, metric TEXT NOT NULL CHECK(metric IN ('cpu','memory')), body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=131072 AND json_valid(body)), PRIMARY KEY(id,metric))`

func decodeWindowsResource(id string, kind windowsresource.Kind, raw []byte) (windowsresource.State, error) {
	state, err := windowsresource.Decode(raw, kind)
	if err != nil || state.Assessment.DeviceID != id || !windowscontact.ValidDeviceID(id) {
		return windowsresource.State{}, windowscapacity.ErrInvalid
	}
	return state, nil
}
func (s *Store) WindowsResourceState(ctx context.Context, id string, kind windowsresource.Kind) (windowsresource.State, error) {
	if !windowscontact.ValidDeviceID(id) || !windowsresource.ValidKind(kind) {
		return windowsresource.State{}, windowscapacity.ErrInvalid
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT body FROM windows_resource_devices WHERE id=? AND metric=?", id, kind).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return windowsresource.New(kind), nil
	}
	if err != nil {
		return windowsresource.State{}, err
	}
	return decodeWindowsResource(id, kind, raw)
}
func (s *Store) WindowsResourceStates(ctx context.Context) ([]windowsresource.State, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,metric,body FROM windows_resource_devices ORDER BY id,metric LIMIT 51")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []windowsresource.State{}
	devices := map[string]bool{}
	for rows.Next() {
		var id string
		var kind windowsresource.Kind
		var raw []byte
		if err = rows.Scan(&id, &kind, &raw); err != nil {
			return nil, err
		}
		state, err := decodeWindowsResource(id, kind, raw)
		if err != nil {
			return nil, err
		}
		out = append(out, state)
		devices[id] = true
		if len(out) > 2*windowscapacity.MaxDevices || len(devices) > windowscapacity.MaxDevices {
			return nil, windowscapacity.ErrInvalid
		}
	}
	return out, rows.Err()
}
func (s *Store) ConfigureWindowsResource(ctx context.Context, in windowscapacity.Input, kind windowsresource.Kind, enabled bool, threshold int, expected uint64, now time.Time, guard ...func() error) (windowsresource.State, error) {
	return s.updateWindowsResource(ctx, in.DeviceID, kind, func(state *windowsresource.State) error {
		return state.Configure(in, kind, enabled, threshold, expected, now)
	}, guard...)
}
func (s *Store) EvaluateWindowsResource(ctx context.Context, in windowscapacity.Input, kind windowsresource.Kind, now time.Time, epoch string) (windowsresource.State, error) {
	return s.updateWindowsResource(ctx, in.DeviceID, kind, func(state *windowsresource.State) error { return state.Evaluate(in, kind, now, epoch) })
}
func (s *Store) updateWindowsResource(ctx context.Context, id string, kind windowsresource.Kind, update func(*windowsresource.State) error, guard ...func() error) (windowsresource.State, error) {
	if !windowscontact.ValidDeviceID(id) || !windowsresource.ValidKind(kind) {
		return windowsresource.State{}, windowscapacity.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return windowsresource.State{}, err
	}
	defer tx.Rollback()
	var count, devices, known int
	if err = tx.QueryRowContext(ctx, "SELECT count(*),count(DISTINCT id),count(CASE WHEN id=? THEN 1 END) FROM windows_resource_devices", id).Scan(&count, &devices, &known); err != nil {
		return windowsresource.State{}, err
	}
	if count > 2*windowscapacity.MaxDevices || devices > windowscapacity.MaxDevices {
		return windowsresource.State{}, windowscapacity.ErrInvalid
	}
	state := windowsresource.New(kind)
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT body FROM windows_resource_devices WHERE id=? AND metric=?", id, kind).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		if count >= 2*windowscapacity.MaxDevices || known == 0 && devices >= windowscapacity.MaxDevices {
			return windowsresource.State{}, windowscapacity.ErrInvalid
		}
	} else if err != nil {
		return windowsresource.State{}, err
	} else {
		state, err = decodeWindowsResource(id, kind, raw)
		if err != nil {
			return windowsresource.State{}, err
		}
	}
	if err = runPolicyGuards(ctx, guard); err != nil {
		return windowsresource.State{}, err
	}
	beforeNotifications := capacityNotificationEpisodes(state.Assessment, string(kind))
	if err = update(&state); err != nil {
		return windowsresource.State{}, err
	}
	if state.Metric != kind || state.Assessment.DeviceID != id {
		return windowsresource.State{}, windowscapacity.ErrInvalid
	}
	body, err := windowsresource.Encode(state)
	if err != nil {
		return windowsresource.State{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO windows_resource_devices(id,metric,body) VALUES(?,?,?) ON CONFLICT(id,metric) DO UPDATE SET body=excluded.body", id, kind, body); err != nil {
		return windowsresource.State{}, err
	}
	if err = enqueueWindowsNotifications(ctx, tx, beforeNotifications, capacityNotificationEpisodes(state.Assessment, string(kind))); err != nil {
		return windowsresource.State{}, err
	}
	if err = runPolicyGuards(ctx, guard); err != nil {
		return windowsresource.State{}, err
	}
	if err = tx.Commit(); err != nil {
		return windowsresource.State{}, err
	}
	return state, nil
}
