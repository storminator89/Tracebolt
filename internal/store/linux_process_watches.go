package store

import (
	"context"
	"database/sql"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/linuxprocesswatch"
	"time"
)

const linuxProcessWatchSchema = `CREATE TABLE IF NOT EXISTS linux_process_watches(id TEXT PRIMARY KEY,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=196608));CREATE TABLE IF NOT EXISTS linux_process_watch_markers(id TEXT PRIMARY KEY)`

var ErrLinuxProcessWatchUnavailable = errors.New("linux process watch storage unavailable")
var ErrLinuxProcessWatchSession = errors.New("linux process watch session ended")

func (s *Store) loadLinuxProcessWatches(ctx context.Context, tx *sql.Tx, id string) (*linuxprocesswatch.State, bool, error) {
	var records, markers int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM linux_process_watches`).Scan(&records) != nil || tx.QueryRowContext(ctx, `SELECT count(*) FROM linux_process_watch_markers`).Scan(&markers) != nil || records != markers || records > linuxprocesswatch.MaxDevices {
		return nil, false, ErrLinuxProcessWatchUnavailable
	}
	var mismatch int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT id FROM linux_process_watches EXCEPT SELECT id FROM linux_process_watch_markers)`).Scan(&mismatch) != nil || mismatch != 0 {
		return nil, false, ErrLinuxProcessWatchUnavailable
	}
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT body FROM linux_process_watches WHERE id=?`, id).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return linuxprocesswatch.New(id), false, nil
	}
	if e != nil {
		return nil, false, e
	}
	state, e := linuxprocesswatch.Decode(raw)
	if e != nil || state.DeviceID != id {
		return nil, false, ErrLinuxProcessWatchUnavailable
	}
	return state, true, nil
}

// Reads validate the used marker and canonical ledger; they never create, prune,
// evaluate, acknowledge or enable monitoring.
func (s *Store) LinuxProcessWatchState(ctx context.Context, id string) (*linuxprocesswatch.State, error) {
	if !enrollmentcrypto.ValidID(id, "agent_") {
		return nil, linuxprocesswatch.ErrInvalid
	}
	if s.linuxProcessWatchBlocked.Load() {
		return nil, ErrLinuxProcessWatchUnavailable
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.linuxProcessWatchBlocked.Store(true)
		return nil, ErrLinuxProcessWatchUnavailable
	}
	defer tx.Rollback()
	if s.linuxProcessWatchBlocked.Load() {
		return nil, ErrLinuxProcessWatchUnavailable
	}
	state, _, e := s.loadLinuxProcessWatches(ctx, tx, id)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.linuxProcessWatchBlocked.Store(true)
		return nil, ErrLinuxProcessWatchUnavailable
	}
	if s.linuxProcessWatchBlocked.Load() {
		return nil, ErrLinuxProcessWatchUnavailable
	}
	return state, nil
}
func (s *Store) LinuxProcessWatchStates(ctx context.Context) (out map[string]*linuxprocesswatch.State, err error) {
	if s.linuxProcessWatchBlocked.Load() {
		return nil, ErrLinuxProcessWatchUnavailable
	}
	defer func() {
		if err != nil && ctx.Err() == nil {
			s.linuxProcessWatchBlocked.Store(true)
			err = ErrLinuxProcessWatchUnavailable
		}
	}()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Validate the whole marker set even when every used ledger has disappeared.
	// An empty list must not silently turn missing used state into default-off.
	var records, markers, mismatch int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM linux_process_watches`).Scan(&records) != nil || tx.QueryRowContext(ctx, `SELECT count(*) FROM linux_process_watch_markers`).Scan(&markers) != nil || records != markers || records > linuxprocesswatch.MaxDevices || tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT id FROM linux_process_watches EXCEPT SELECT id FROM linux_process_watch_markers)`).Scan(&mismatch) != nil || mismatch != 0 {
		return nil, ErrLinuxProcessWatchUnavailable
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM linux_process_watches ORDER BY id LIMIT 26`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !enrollmentcrypto.ValidID(id, "agent_") {
			return nil, ErrLinuxProcessWatchUnavailable
		}
		ids = append(ids, id)
	}
	if rows.Err() != nil || rows.Close() != nil || len(ids) > linuxprocesswatch.MaxDevices {
		return nil, ErrLinuxProcessWatchUnavailable
	}
	out = map[string]*linuxprocesswatch.State{}
	for _, id := range ids {
		state, exists, e := s.loadLinuxProcessWatches(ctx, tx, id)
		if e != nil || !exists {
			return nil, ErrLinuxProcessWatchUnavailable
		}
		out[id] = state
	}
	if s.linuxProcessWatchBlocked.Load() {
		return nil, ErrLinuxProcessWatchUnavailable
	}
	return out, nil
}

func (s *Store) UpdateLinuxProcessWatches(ctx context.Context, in linuxprocesswatch.Input, policy *linuxprocesswatch.ConfigureRequest, ack *linuxprocesswatch.AcknowledgeRequest, evaluate bool, clock func() time.Time, guard func(time.Time) error) (*linuxprocesswatch.State, time.Time, error) {
	return s.updateLinuxProcessWatches(ctx, in, policy, ack, evaluate, false, clock, guard)
}

// PruneLinuxProcessWatchHistory performs source-independent local retention on
// an existing ledger only. It cannot configure or evaluate a watch.
func (s *Store) PruneLinuxProcessWatchHistory(ctx context.Context, id string, clock func() time.Time) error {
	_, _, err := s.updateLinuxProcessWatches(ctx, linuxprocesswatch.Input{DeviceID: id}, nil, nil, false, true, clock, func(time.Time) error { return ctx.Err() })
	return err
}
func (s *Store) updateLinuxProcessWatches(ctx context.Context, in linuxprocesswatch.Input, policy *linuxprocesswatch.ConfigureRequest, ack *linuxprocesswatch.AcknowledgeRequest, evaluate, retentionOnly bool, clock func() time.Time, guard func(time.Time) error) (*linuxprocesswatch.State, time.Time, error) {
	if !enrollmentcrypto.ValidID(in.DeviceID, "agent_") || clock == nil || guard == nil || policy != nil && ack != nil || evaluate && (policy != nil || ack != nil) {
		return nil, time.Time{}, linuxprocesswatch.ErrInvalid
	}
	fail := func() (*linuxprocesswatch.State, time.Time, error) {
		s.linuxProcessWatchBlocked.Store(true)
		return nil, time.Time{}, ErrLinuxProcessWatchUnavailable
	}
	if s.linuxProcessWatchBlocked.Load() {
		return nil, time.Time{}, ErrLinuxProcessWatchUnavailable
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		if ctx.Err() != nil {
			return nil, time.Time{}, ctx.Err()
		}
		return fail()
	}
	defer tx.Rollback()
	if s.linuxProcessWatchBlocked.Load() {
		return nil, time.Time{}, ErrLinuxProcessWatchUnavailable
	}
	state, exists, e := s.loadLinuxProcessWatches(ctx, tx, in.DeviceID)
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
	if policy != nil {
		e = linuxprocesswatch.Configure(state, in, *policy, now)
	} else if ack != nil {
		e = linuxprocesswatch.Acknowledge(state, in, *ack, now)
	} else if evaluate {
		e = linuxprocesswatch.Evaluate(state, in, now)
	} else if retentionOnly {
		e = linuxprocesswatch.Maintain(state, now)
	}
	if e != nil {
		return nil, now, e
	}
	// A default-off read/evaluation never adopts or creates state.
	if policy == nil && ack == nil && (!evaluate && !retentionOnly || !exists) {
		return state, now, nil
	}
	raw, e := linuxprocesswatch.Encode(state)
	if e != nil {
		return fail()
	}
	if !exists {
		var n int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM linux_process_watches`).Scan(&n) != nil {
			return fail()
		}
		if n >= linuxprocesswatch.MaxDevices {
			return nil, now, linuxprocesswatch.ErrCapacity
		}
	}
	if s.linuxProcessWatchBlocked.Load() {
		return nil, now, ErrLinuxProcessWatchUnavailable
	}
	if e = guard(now); e != nil {
		return nil, now, e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO linux_process_watches(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`, in.DeviceID, raw); e != nil {
		return fail()
	}
	if !exists {
		if _, e = tx.ExecContext(ctx, `INSERT INTO linux_process_watch_markers(id) VALUES(?)`, in.DeviceID); e != nil {
			return fail()
		}
	}
	if s.linuxProcessWatchBlocked.Load() {
		return nil, now, ErrLinuxProcessWatchUnavailable
	}
	if e = guard(now); e != nil {
		return nil, now, e
	}
	if e = tx.Commit(); e != nil {
		return fail()
	}
	return state, now, nil
}
