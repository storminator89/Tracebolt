package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"localrmm/internal/windowscontact"
)

// This isolated contact ledger never feeds Linux health analyses. Existing
// Windows notification consumers retain their separate explicit source approval.
const windowsContactSchema = `CREATE TABLE IF NOT EXISTS windows_contact_devices(id TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=131072 AND json_valid(body)));
CREATE TABLE IF NOT EXISTS windows_contact_policy_used(id TEXT PRIMARY KEY)`

type contactReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

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
	return readWindowsContactState(ctx, s.db, id)
}

func readWindowsContactState(ctx context.Context, q contactReader, id string) (windowscontact.State, error) {
	if !windowscontact.ValidDeviceID(id) {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	var used int
	if err := q.QueryRowContext(ctx, "SELECT count(*) FROM windows_contact_policy_used WHERE id=?", id).Scan(&used); err != nil {
		return windowscontact.State{}, err
	}
	var raw []byte
	err := q.QueryRowContext(ctx, "SELECT body FROM windows_contact_devices WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		if used != 0 {
			return windowscontact.State{}, windowscontact.ErrInvalid
		}
		return windowscontact.New(), nil
	}
	if err != nil {
		return windowscontact.State{}, err
	}
	state, err := decodeWindowsContact(id, raw)
	if err != nil || (state.Policy != nil) != (used == 1) {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	return state, nil
}

func (s *Store) WindowsContactStates(ctx context.Context) (map[string]windowscontact.State, error) {
	return readWindowsContactStates(ctx, s.db)
}

func readWindowsContactStates(ctx context.Context, q contactReader) (map[string]windowscontact.State, error) {
	var missing int
	if err := q.QueryRowContext(ctx, "SELECT count(*) FROM windows_contact_policy_used WHERE id NOT IN (SELECT id FROM windows_contact_devices)").Scan(&missing); err != nil || missing != 0 {
		return nil, windowscontact.ErrInvalid
	}
	rows, err := q.QueryContext(ctx, "SELECT d.id,d.body,(SELECT count(*) FROM windows_contact_policy_used p WHERE p.id=d.id) FROM windows_contact_devices d ORDER BY d.id LIMIT 26")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]windowscontact.State{}
	for rows.Next() {
		var id string
		var raw []byte
		var used int
		if err = rows.Scan(&id, &raw, &used); err != nil {
			return nil, err
		}
		state, err := decodeWindowsContact(id, raw)
		if err != nil || (state.Policy != nil) != (used == 1) {
			return nil, windowscontact.ErrInvalid
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
	state, err := readWindowsContactState(ctx, tx, input.DeviceID)
	if err != nil {
		return windowscontact.State{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM windows_contact_devices").Scan(&count); err != nil {
		return windowscontact.State{}, err
	}
	if count > windowscontact.MaxDevices {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	if state.DeviceID == "" {
		if count >= windowscontact.MaxDevices {
			return windowscontact.State{}, windowscontact.ErrInvalid
		}
	}
	beforeNotifications := contactNotificationEpisodes(state)
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
	if err = enqueueWindowsNotifications(ctx, tx, beforeNotifications, contactNotificationEpisodes(state)); err != nil {
		return windowscontact.State{}, err
	}
	if err = tx.Commit(); err != nil {
		return windowscontact.State{}, err
	}
	return state, nil
}
