package store

import (
	"context"
	"database/sql"
	"time"

	"localrmm/internal/enrollmentcrypto"
	watch "localrmm/internal/windowsprocesswatch"
)

// The separate used marker makes missing used policy state fail closed. A GET
// cannot create a marker or a default-off policy. No observations are persisted.
const windowsProcessWatchSchema = `CREATE TABLE IF NOT EXISTS windows_process_watch_used(id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS windows_process_watch_devices(id TEXT PRIMARY KEY REFERENCES windows_process_watch_used(id), body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=32768 AND json_valid(body)))`

type processWatchReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readWindowsProcessWatch(ctx context.Context, q processWatchReader, id string) (watch.State, error) {
	if !enrollmentcrypto.ValidID(id, "agent_") {
		return watch.State{}, watch.ErrInvalid
	}
	var used, states int
	if e := q.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM windows_process_watch_used WHERE id=?),(SELECT count(*) FROM windows_process_watch_devices WHERE id=?)`, id, id).Scan(&used, &states); e != nil {
		return watch.State{}, e
	}
	if used != states {
		return watch.State{}, watch.ErrInvalid
	}
	if used == 0 {
		return watch.New(), nil
	}
	var raw []byte
	if e := q.QueryRowContext(ctx, `SELECT body FROM windows_process_watch_devices WHERE id=?`, id).Scan(&raw); e != nil {
		return watch.State{}, e
	}
	state, e := watch.Decode(raw)
	if e != nil || state.DeviceID != id {
		return watch.State{}, watch.ErrInvalid
	}
	return state, nil
}
func (s *Store) WindowsProcessWatchState(ctx context.Context, id string) (watch.State, error) {
	return readWindowsProcessWatch(ctx, s.db, id)
}

// ConfigureWindowsProcessWatch requires the caller's enrollment-to-operator
// lease. Both the source and session are checked after SQL waits and at commit.
func (s *Store) ConfigureWindowsProcessWatch(ctx context.Context, in watch.Input, request watch.Request, clock func() time.Time, guard func(time.Time) error) (watch.State, error) {
	if clock == nil || guard == nil {
		return watch.State{}, watch.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return watch.State{}, e
	}
	defer tx.Rollback()
	at := clock().UTC()
	if e = guard(at); e != nil {
		return watch.State{}, e
	}
	original, e := readWindowsProcessWatch(ctx, tx, in.DeviceID)
	if e != nil {
		return watch.State{}, e
	}
	var used, states int
	if e = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM windows_process_watch_used),(SELECT count(*) FROM windows_process_watch_devices)`).Scan(&used, &states); e != nil {
		return watch.State{}, e
	}
	if used != states || used > watch.MaxDevices || used == watch.MaxDevices && original.DeviceID == "" {
		return watch.State{}, watch.ErrInvalid
	}
	state := original
	at = clock().UTC()
	if e = state.Configure(in, request, at); e != nil {
		return watch.State{}, e
	}
	raw, e := watch.Encode(state)
	if e != nil {
		return watch.State{}, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO windows_process_watch_used(id) VALUES(?)`, in.DeviceID); e != nil {
		return watch.State{}, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO windows_process_watch_devices(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`, in.DeviceID, raw); e != nil {
		return watch.State{}, e
	}
	end := clock().UTC()
	if end.Before(at) {
		return watch.State{}, watch.ErrInvalid
	}
	if e = guard(end); e != nil {
		return watch.State{}, e
	}
	end = clock().UTC()
	if end.Before(at) {
		return watch.State{}, watch.ErrInvalid
	}
	if e = original.Configure(in, request, end); e != nil {
		return watch.State{}, e
	}
	if e = ctx.Err(); e != nil {
		return watch.State{}, e
	}
	if e = tx.Commit(); e != nil {
		return watch.State{}, e
	}
	return state, nil
}
