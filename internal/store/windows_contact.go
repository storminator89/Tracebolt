package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"localrmm/internal/windowscontact"
)

// This isolated table never feeds health analyses or alarm delivery.
const windowsContactSchema = `CREATE TABLE IF NOT EXISTS windows_contact_devices(id TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=131072 AND json_valid(body)))`

func decodeWindowsContact(id string, raw []byte) (windowscontact.State, error) {
	state, err := windowscontact.Decode(raw)
	if err != nil || state.DeviceID != id || !windowscontact.ValidDeviceID(id) {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	return state, nil
}

// WindowsContactState performs no writes, resets or pruning. Missing state is
// unknown; malformed retained history is an error and is never replaced.
func (s *Store) WindowsContactState(ctx context.Context, id string) (windowscontact.State, error) {
	if !windowscontact.ValidDeviceID(id) {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT body FROM windows_contact_devices WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return windowscontact.New(), nil
	}
	if err != nil {
		return windowscontact.State{}, err
	}
	return decodeWindowsContact(id, raw)
}

func (s *Store) WindowsContactStates(ctx context.Context) (map[string]windowscontact.State, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,body FROM windows_contact_devices ORDER BY id LIMIT 26")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]windowscontact.State{}
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		state, err := decodeWindowsContact(id, raw)
		if err != nil {
			return nil, err
		}
		out[id] = state
		if len(out) > windowscontact.MaxDevices {
			return nil, windowscontact.ErrInvalid
		}
	}
	return out, rows.Err()
}

// EvaluateWindowsContact atomically loads, evaluates, validates, prunes and
// stores exactly one device. Cancellation and all errors leave its ledger intact.
// The process epoch is supplied by the manager monitor and is never authority.
func (s *Store) EvaluateWindowsContact(ctx context.Context, input windowscontact.Input, now time.Time, epoch string) (windowscontact.State, error) {
	if !windowscontact.ValidDeviceID(input.DeviceID) {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return windowscontact.State{}, err
	}
	defer tx.Rollback()
	state := windowscontact.New()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM windows_contact_devices").Scan(&count); err != nil {
		return windowscontact.State{}, err
	}
	if count > windowscontact.MaxDevices {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, "SELECT body FROM windows_contact_devices WHERE id=?", input.DeviceID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		if count >= windowscontact.MaxDevices {
			return windowscontact.State{}, windowscontact.ErrInvalid
		}
	} else if err != nil {
		return windowscontact.State{}, err
	} else {
		state, err = decodeWindowsContact(input.DeviceID, raw)
		if err != nil {
			return windowscontact.State{}, err
		}
	}
	if err = state.Evaluate(input, now, epoch); err != nil {
		return windowscontact.State{}, err
	}
	body, err := windowscontact.Encode(state)
	if err != nil {
		return windowscontact.State{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO windows_contact_devices(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", input.DeviceID, body); err != nil {
		return windowscontact.State{}, err
	}
	if err = tx.Commit(); err != nil {
		return windowscontact.State{}, err
	}
	return state, nil
}
