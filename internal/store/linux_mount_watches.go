package store

import (
	"context"
	"database/sql"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/linuxmountwatch"
	"time"
)

const linuxMountWatchSchema = `CREATE TABLE IF NOT EXISTS linux_mount_watches(id TEXT PRIMARY KEY,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=131072));CREATE TABLE IF NOT EXISTS linux_mount_watch_markers(id TEXT PRIMARY KEY)`

var ErrLinuxMountWatchUnavailable = errors.New("linux mount watch storage unavailable")
var ErrLinuxMountWatchSession = errors.New("linux mount watch session ended")

func (s *Store) loadLinuxMountWatches(ctx context.Context, tx *sql.Tx, id string) (*linuxmountwatch.State, bool, error) {
	var records, markers int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM linux_mount_watches`).Scan(&records) != nil || tx.QueryRowContext(ctx, `SELECT count(*) FROM linux_mount_watch_markers`).Scan(&markers) != nil || records != markers || records > linuxmountwatch.MaxDevices {
		return nil, false, ErrLinuxMountWatchUnavailable
	}
	var mismatch int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT id FROM linux_mount_watches EXCEPT SELECT id FROM linux_mount_watch_markers)`).Scan(&mismatch) != nil || mismatch != 0 {
		return nil, false, ErrLinuxMountWatchUnavailable
	}
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT body FROM linux_mount_watches WHERE id=?`, id).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return linuxmountwatch.New(id), false, nil
	}
	if e != nil {
		return nil, false, e
	}
	state, e := linuxmountwatch.Decode(raw)
	if e != nil || state.DeviceID != id {
		return nil, false, ErrLinuxMountWatchUnavailable
	}
	return state, true, nil
}

// Reads validate the used marker and canonical ledger; they never create, prune,
// evaluate, acknowledge or enable monitoring.
func (s *Store) LinuxMountWatchState(ctx context.Context, id string) (*linuxmountwatch.State, error) {
	if !enrollmentcrypto.ValidID(id, "agent_") {
		return nil, linuxmountwatch.ErrInvalid
	}
	if s.linuxMountWatchBlocked.Load() {
		return nil, ErrLinuxMountWatchUnavailable
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.linuxMountWatchBlocked.Store(true)
		return nil, ErrLinuxMountWatchUnavailable
	}
	defer tx.Rollback()
	if s.linuxMountWatchBlocked.Load() {
		return nil, ErrLinuxMountWatchUnavailable
	}
	state, _, e := s.loadLinuxMountWatches(ctx, tx, id)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.linuxMountWatchBlocked.Store(true)
		return nil, ErrLinuxMountWatchUnavailable
	}
	if s.linuxMountWatchBlocked.Load() {
		return nil, ErrLinuxMountWatchUnavailable
	}
	return state, nil
}
func (s *Store) LinuxMountWatchStates(ctx context.Context) (map[string]*linuxmountwatch.State, error) {
	if s.linuxMountWatchBlocked.Load() {
		return nil, ErrLinuxMountWatchUnavailable
	}
	rows, e := s.db.QueryContext(ctx, `SELECT id FROM linux_mount_watches ORDER BY id LIMIT 26`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			return nil, ErrLinuxMountWatchUnavailable
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil || rows.Close() != nil || len(ids) > linuxmountwatch.MaxDevices {
		return nil, ErrLinuxMountWatchUnavailable
	}
	out := map[string]*linuxmountwatch.State{}
	for _, id := range ids {
		state, e := s.LinuxMountWatchState(ctx, id)
		if e != nil {
			return nil, e
		}
		out[id] = state
	}
	return out, nil
}

func (s *Store) UpdateLinuxMountWatches(ctx context.Context, in linuxmountwatch.Input, command *linuxmountwatch.Command, evaluate bool, clock func() time.Time, guard func(time.Time) error) (*linuxmountwatch.State, time.Time, error) {
	if !enrollmentcrypto.ValidID(in.DeviceID, "agent_") || clock == nil || guard == nil || evaluate && command != nil {
		return nil, time.Time{}, linuxmountwatch.ErrInvalid
	}
	fail := func() (*linuxmountwatch.State, time.Time, error) {
		s.linuxMountWatchBlocked.Store(true)
		return nil, time.Time{}, ErrLinuxMountWatchUnavailable
	}
	if s.linuxMountWatchBlocked.Load() {
		return nil, time.Time{}, ErrLinuxMountWatchUnavailable
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		if ctx.Err() != nil {
			return nil, time.Time{}, ctx.Err()
		}
		return fail()
	}
	defer tx.Rollback()
	if s.linuxMountWatchBlocked.Load() {
		return nil, time.Time{}, ErrLinuxMountWatchUnavailable
	}
	state, exists, e := s.loadLinuxMountWatches(ctx, tx, in.DeviceID)
	if e != nil {
		if ctx.Err() != nil {
			return nil, time.Time{}, ctx.Err()
		}
		return fail()
	}
	now := clock().UTC()
	if e = guard(now); e != nil {
		return nil, now, e
	}
	if command != nil {
		e = linuxmountwatch.Apply(state, in, *command, now)
	} else if evaluate {
		if _, started := s.linuxMountWatchStarted.Load(in.DeviceID); !started {
			linuxmountwatch.Interrupt(state)
		}
		e = linuxmountwatch.Evaluate(state, in, now)
	}
	if e != nil {
		return nil, now, e
	}
	// A default-off read/evaluation never adopts or creates state.
	if command == nil && (!evaluate || !exists) {
		return state, now, nil
	}
	raw, e := linuxmountwatch.Encode(state)
	if e != nil {
		return fail()
	}
	if !exists {
		var n int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM linux_mount_watches`).Scan(&n) != nil {
			return fail()
		}
		if n >= linuxmountwatch.MaxDevices {
			return nil, now, ErrLimit
		}
	}
	if s.linuxMountWatchBlocked.Load() {
		return nil, now, ErrLinuxMountWatchUnavailable
	}
	if e = guard(now); e != nil {
		return nil, now, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO linux_mount_watches(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`, in.DeviceID, raw); e != nil {
		return fail()
	}
	if !exists {
		if _, e = tx.ExecContext(ctx, `INSERT INTO linux_mount_watch_markers(id) VALUES(?)`, in.DeviceID); e != nil {
			return fail()
		}
	}
	if s.linuxMountWatchBlocked.Load() {
		return nil, now, ErrLinuxMountWatchUnavailable
	}
	if e = guard(now); e != nil {
		return nil, now, e
	}
	if e = tx.Commit(); e != nil {
		return fail()
	}
	if evaluate {
		s.linuxMountWatchStarted.Store(in.DeviceID, true)
	}
	return state, now, nil
}

// InterruptLinuxMountWatch may only remove confidence after a failed monitor
// source transaction. It cannot configure policy, collect evidence, acknowledge,
// recover, prune or create a record, and requires no newly inferred host grant.
func (s *Store) InterruptLinuxMountWatch(ctx context.Context, id string) (result error) {
	defer func() {
		if result != nil {
			s.linuxMountWatchBlocked.Store(true)
		}
	}()
	if !enrollmentcrypto.ValidID(id, "agent_") {
		return linuxmountwatch.ErrInvalid
	}
	if s.linuxMountWatchBlocked.Load() {
		return ErrLinuxMountWatchUnavailable
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	state, exists, e := s.loadLinuxMountWatches(ctx, tx, id)
	if e != nil {
		s.linuxMountWatchBlocked.Store(true)
		return ErrLinuxMountWatchUnavailable
	}
	if !exists {
		return nil
	}
	linuxmountwatch.Interrupt(state)
	raw, e := linuxmountwatch.Encode(state)
	if e != nil {
		s.linuxMountWatchBlocked.Store(true)
		return ErrLinuxMountWatchUnavailable
	}
	if s.linuxMountWatchBlocked.Load() {
		return ErrLinuxMountWatchUnavailable
	}
	if _, e = tx.ExecContext(ctx, `UPDATE linux_mount_watches SET body=? WHERE id=?`, raw, id); e != nil {
		return e
	}
	if s.linuxMountWatchBlocked.Load() {
		return ErrLinuxMountWatchUnavailable
	}
	return tx.Commit()
}
