package store

import (
	"context"
	"time"

	"localrmm/internal/windowscontact"
)

// ConfigureWindowsContact changes only the manager's missed-report grace.
// The caller holds the existing enrollment-to-operator identity lease. No
// incident evaluation or notification transition occurs in this transaction.
func (s *Store) ConfigureWindowsContact(ctx context.Context, in windowscontact.Input, request windowscontact.PolicyRequest, epoch string, clock func() time.Time, guard func(time.Time) error) (windowscontact.State, error) {
	if clock == nil || guard == nil || !windowscontact.ValidDeviceID(in.DeviceID) {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return windowscontact.State{}, err
	}
	defer tx.Rollback()
	started := clock().UTC()
	if err = guard(started); err != nil {
		return windowscontact.State{}, err
	}
	original, err := readWindowsContactState(ctx, tx, in.DeviceID)
	if err != nil {
		return windowscontact.State{}, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM windows_contact_devices").Scan(&count); err != nil {
		return windowscontact.State{}, err
	}
	if count > windowscontact.MaxDevices || count == windowscontact.MaxDevices && original.DeviceID == "" {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	state := original
	at := clock().UTC()
	if at.Before(started) {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	if err = state.Configure(in, request, at, epoch); err != nil {
		return windowscontact.State{}, err
	}
	raw, err := windowscontact.Encode(state)
	if err != nil {
		return windowscontact.State{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO windows_contact_policy_used(id) VALUES(?)", in.DeviceID); err != nil {
		return windowscontact.State{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO windows_contact_devices(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", in.DeviceID, raw); err != nil {
		return windowscontact.State{}, err
	}
	end := clock().UTC()
	if end.Before(at) {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	if err = guard(end); err != nil {
		return windowscontact.State{}, err
	}
	final := clock().UTC()
	if final.Before(end) {
		return windowscontact.State{}, windowscontact.ErrInvalid
	}
	if err = original.Configure(in, request, final, epoch); err != nil {
		return windowscontact.State{}, err
	}
	if err = ctx.Err(); err != nil {
		return windowscontact.State{}, err
	}
	if err = tx.Commit(); err != nil {
		return windowscontact.State{}, err
	}
	return state, nil
}
