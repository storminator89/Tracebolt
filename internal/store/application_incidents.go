package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/applicationcheck"
	"time"
)

const applicationIncidentSchema = `CREATE TABLE IF NOT EXISTS application_incidents(id INTEGER PRIMARY KEY CHECK(id=1),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=196608 AND json_valid(body)));CREATE TABLE IF NOT EXISTS application_incident_marker(id INTEGER PRIMARY KEY CHECK(id=1))`

var ErrApplicationIncidentSession = errors.New("application_incident_session_ended")

func decodeApplicationIncidents(raw []byte) (applicationcheck.IncidentState, error) {
	var state applicationcheck.IncidentState
	if len(raw) == 0 || len(raw) > applicationcheck.IncidentMaxBytes {
		return state, applicationcheck.ErrIncidentUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&state) != nil || state.Validate() != nil {
		return state, applicationcheck.ErrIncidentUnavailable
	}
	// Stored state has exactly one canonical producer, not a public import format.
	// Equality rejects duplicates, aliases, extra JSON, and alternate time encodings.
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(raw, canonical) {
		return state, applicationcheck.ErrIncidentUnavailable
	}
	return state, nil
}
func (s *Store) applicationIncidentTransaction(ctx context.Context, source applicationcheck.IncidentSource, command *applicationcheck.IncidentCommand, authorized func() bool, observation *applicationcheck.IncidentObservation) (applicationcheck.IncidentState, time.Time, error) {
	zero := applicationcheck.NewIncidentState()
	if s.applicationIncidentBlocked.Load() {
		return zero, time.Time{}, applicationcheck.ErrIncidentUnavailable
	}
	fail := func() (applicationcheck.IncidentState, time.Time, error) {
		s.applicationIncidentBlocked.Store(true)
		return zero, time.Time{}, applicationcheck.ErrIncidentUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		if ctx.Err() != nil {
			return zero, time.Time{}, ctx.Err()
		}
		return fail()
	}
	defer tx.Rollback()
	if s.applicationIncidentBlocked.Load() {
		return zero, time.Time{}, applicationcheck.ErrIncidentUnavailable
	}
	var raw []byte
	exists := true
	err = tx.QueryRowContext(ctx, `SELECT body FROM application_incidents WHERE id=1`).Scan(&raw)
	state := applicationcheck.NewIncidentState()
	if errors.Is(err, sql.ErrNoRows) {
		exists = false
	} else if err != nil {
		if ctx.Err() != nil {
			return zero, time.Time{}, ctx.Err()
		}
		return fail()
	} else {
		state, err = decodeApplicationIncidents(raw)
		if err != nil {
			return fail()
		}
	}
	var markers int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM application_incident_marker`).Scan(&markers); err != nil {
		if ctx.Err() != nil {
			return zero, time.Time{}, ctx.Err()
		}
		return fail()
	}
	if markers < 0 || markers > 1 || exists != (markers == 1) {
		return fail()
	}
	if source.Now == nil {
		return fail()
	}
	now := source.Now().UTC()
	if err = state.Synchronize(source, now); err != nil {
		return fail()
	}
	if command != nil {
		if authorized == nil || !authorized() {
			return zero, now, ErrApplicationIncidentSession
		}
		if err = state.Apply(*command, source, now); err != nil {
			return zero, now, err
		}
	} else if observation != nil {
		if err = state.Observe(source, *observation, now); err != nil {
			return fail()
		}
	}
	if !exists && command == nil {
		s.applicationIncidentActive.Store(false)
		s.applicationIncidentLoaded.Store(true)
		return state, now, nil
	}
	if state.Validate() != nil {
		return fail()
	}
	body, err := json.Marshal(state)
	if err != nil || len(body) > applicationcheck.IncidentMaxBytes {
		return fail()
	}
	if s.applicationIncidentBlocked.Load() {
		return zero, now, applicationcheck.ErrIncidentUnavailable
	}
	if command != nil && !authorized() {
		return zero, now, ErrApplicationIncidentSession
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO application_incidents(id,body) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`, body); err != nil {
		return fail()
	}
	if !exists {
		if _, err = tx.ExecContext(ctx, `INSERT INTO application_incident_marker(id) VALUES(1)`); err != nil {
			return fail()
		}
	}
	if command != nil && !authorized() {
		return zero, now, ErrApplicationIncidentSession
	}
	if s.applicationIncidentBlocked.Load() {
		return zero, now, applicationcheck.ErrIncidentUnavailable
	}
	if err = tx.Commit(); err != nil {
		return fail()
	}
	s.applicationIncidentActive.Store(state.Policy.Enabled)
	s.applicationIncidentLoaded.Store(true)
	return state, now, nil
}

// Construction/source transitions reconcile only previously approved local
// state. With no incident row, nothing is persisted and observation hooks are inert.
func (s *Store) ObserveApplicationSource(ctx context.Context, source applicationcheck.IncidentSource) error {
	_, _, err := s.applicationIncidentTransaction(ctx, source, nil, nil, nil)
	return err
}
func (s *Store) ObserveApplicationResult(ctx context.Context, source applicationcheck.IncidentSource, r applicationcheck.IncidentObservation) error {
	if s.applicationIncidentBlocked.Load() {
		return applicationcheck.ErrIncidentUnavailable
	}
	if s.applicationIncidentLoaded.Load() && !s.applicationIncidentActive.Load() {
		return nil
	}
	_, _, err := s.applicationIncidentTransaction(ctx, source, nil, nil, &r)
	return err
}
func (s *Store) ApplicationIncidents(ctx context.Context, source applicationcheck.IncidentSource, canManage bool) (applicationcheck.IncidentView, error) {
	state, now, err := s.applicationIncidentTransaction(ctx, source, nil, nil, nil)
	if err != nil {
		return applicationcheck.IncidentView{}, err
	}
	return state.View(source, now, canManage), nil
}
func (s *Store) ChangeApplicationIncidents(ctx context.Context, source applicationcheck.IncidentSource, c applicationcheck.IncidentCommand, authorized func() bool, canManage bool) (applicationcheck.IncidentView, error) {
	state, now, err := s.applicationIncidentTransaction(ctx, source, &c, authorized, nil)
	if err != nil {
		return applicationcheck.IncidentView{}, err
	}
	return state.View(source, now, canManage), nil
}
