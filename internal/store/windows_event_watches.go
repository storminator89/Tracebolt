package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowseventwatch"
	"time"
)

const windowsEventWatchSchema = `CREATE TABLE IF NOT EXISTS windows_event_watches(id TEXT PRIMARY KEY,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=196608));CREATE TABLE IF NOT EXISTS windows_event_watch_markers(id TEXT PRIMARY KEY)`
const windowsEventWatchEnvelopeBytes = 192 << 10

var ErrWindowsEventWatchUnavailable = errors.New("windows_event_watch_storage_unavailable")
var ErrWindowsEventWatchConflict = errors.New("windows_event_watch_changed")
var ErrWindowsEventWatchSession = errors.New("windows_event_watch_session_ended")

type WindowsEventWatchRequest struct {
	RequestID  string  `json:"requestId"`
	Operation  string  `json:"operation"`
	IncidentID *string `json:"incidentId"`
}
type WindowsEventWatchRecord struct {
	Version     int                       `json:"version"`
	DeviceID    string                    `json:"deviceId"`
	Revision    uint64                    `json:"revision"`
	LastRequest *WindowsEventWatchRequest `json:"lastRequest"`
	State       windowseventwatch.State   `json:"state"`
}
type WindowsEventWatchCommand struct {
	RequestID             string
	ExpectedRevision      uint64
	SourceToken           string
	Operation             string
	Enabled               bool
	Selectors             []windowseventwatch.Selector
	RetentionAcknowledged bool
	IncidentID            string
}

func newWindowsEventWatchRecord(id string) WindowsEventWatchRecord {
	return WindowsEventWatchRecord{Version: 1, DeviceID: id, State: windowseventwatch.New()}
}
func encodeWindowsEventWatchRecord(v WindowsEventWatchRecord) ([]byte, error) {
	if v.Version != 1 || !enrollmentcrypto.ValidID(v.DeviceID, "agent_") || v.Revision > windowseventwatch.MaxCounter || v.State.Policy.Revision > v.Revision || v.State.DeviceID != "" && v.State.DeviceID != v.DeviceID || v.State.Validate() != nil {
		return nil, ErrWindowsEventWatchUnavailable
	}
	if v.Revision == 0 {
		if v.LastRequest != nil || v.State.Policy.Enabled || v.State.Policy.Revision != 0 {
			return nil, ErrWindowsEventWatchUnavailable
		}
	} else if v.LastRequest == nil || !enrollmentcrypto.ValidID(v.LastRequest.RequestID, "eventrequest_") || v.LastRequest.Operation != "policy" && v.LastRequest.Operation != "review" || (v.LastRequest.Operation == "review") != (v.LastRequest.IncidentID != nil) {
		return nil, ErrWindowsEventWatchUnavailable
	}
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > windowsEventWatchEnvelopeBytes {
		return nil, ErrWindowsEventWatchUnavailable
	}
	return raw, nil
}
func (s *Store) loadWindowsEventWatch(ctx context.Context, tx *sql.Tx, id string) (WindowsEventWatchRecord, bool, error) {
	var records, markers, mismatch int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM windows_event_watches`).Scan(&records) != nil || tx.QueryRowContext(ctx, `SELECT count(*) FROM windows_event_watch_markers`).Scan(&markers) != nil || records != markers || records > 25 || tx.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT id FROM windows_event_watches EXCEPT SELECT id FROM windows_event_watch_markers)`).Scan(&mismatch) != nil || mismatch != 0 {
		return WindowsEventWatchRecord{}, false, ErrWindowsEventWatchUnavailable
	}
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT body FROM windows_event_watches WHERE id=?`, id).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return newWindowsEventWatchRecord(id), false, nil
	}
	if e != nil {
		return WindowsEventWatchRecord{}, false, e
	}
	var v WindowsEventWatchRecord
	if json.Unmarshal(raw, &v) != nil {
		return v, false, ErrWindowsEventWatchUnavailable
	}
	canonical, e := encodeWindowsEventWatchRecord(v)
	if e != nil || !bytes.Equal(canonical, raw) || v.DeviceID != id {
		return v, false, ErrWindowsEventWatchUnavailable
	}
	return v, true, nil
}

// Reads never initialize, repair, evaluate, enable or prune a ledger.
func (s *Store) WindowsEventWatchRecord(ctx context.Context, id string) (WindowsEventWatchRecord, error) {
	if !enrollmentcrypto.ValidID(id, "agent_") {
		return WindowsEventWatchRecord{}, windowseventwatch.ErrInvalid
	}
	if s.windowsEventWatchBlocked.Load() {
		return WindowsEventWatchRecord{}, ErrWindowsEventWatchUnavailable
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return WindowsEventWatchRecord{}, e
	}
	defer tx.Rollback()
	v, _, e := s.loadWindowsEventWatch(ctx, tx, id)
	if e != nil && ctx.Err() == nil {
		s.windowsEventWatchBlocked.Store(true)
	}
	return v, e
}
func (s *Store) WindowsEventWatchRecords(ctx context.Context) (out []WindowsEventWatchRecord, err error) {
	if s.windowsEventWatchBlocked.Load() {
		return nil, ErrWindowsEventWatchUnavailable
	}
	defer func() {
		if err != nil && ctx.Err() == nil {
			s.windowsEventWatchBlocked.Store(true)
		}
	}()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Validate both marker sets even if the record list is empty.
	if _, _, err = s.loadWindowsEventWatch(ctx, tx, "agent_00000000000000000000000000000001"); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM windows_event_watches ORDER BY id LIMIT 26`)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || !enrollmentcrypto.ValidID(id, "agent_") {
			rows.Close()
			return nil, ErrWindowsEventWatchUnavailable
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil || closeErr != nil || len(ids) > 25 {
		return nil, ErrWindowsEventWatchUnavailable
	}
	out = []WindowsEventWatchRecord{}
	for _, id := range ids {
		v, exists, e := s.loadWindowsEventWatch(ctx, tx, id)
		if e != nil || !exists {
			return nil, ErrWindowsEventWatchUnavailable
		}
		out = append(out, v)
	}
	return out, nil
}
func (s *Store) UpdateWindowsEventWatch(ctx context.Context, in windowseventwatch.Input, command *WindowsEventWatchCommand, evaluate bool, clock func() time.Time, guard func(time.Time) error) (WindowsEventWatchRecord, error) {
	return s.updateWindowsEventWatch(ctx, in.Source.DeviceID, in, command, evaluate, false, clock, guard)
}
func (s *Store) PruneWindowsEventWatch(ctx context.Context, id string, clock func() time.Time) error {
	_, e := s.updateWindowsEventWatch(ctx, id, windowseventwatch.Input{}, nil, false, true, clock, func(time.Time) error { return ctx.Err() })
	return e
}
func (s *Store) updateWindowsEventWatch(ctx context.Context, id string, in windowseventwatch.Input, command *WindowsEventWatchCommand, evaluate, retentionOnly bool, clock func() time.Time, guard func(time.Time) error) (WindowsEventWatchRecord, error) {
	if !enrollmentcrypto.ValidID(id, "agent_") || clock == nil || guard == nil || command != nil && (evaluate || retentionOnly) {
		return WindowsEventWatchRecord{}, windowseventwatch.ErrInvalid
	}
	if s.windowsEventWatchBlocked.Load() {
		return WindowsEventWatchRecord{}, ErrWindowsEventWatchUnavailable
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return WindowsEventWatchRecord{}, e
	}
	defer tx.Rollback()
	v, exists, e := s.loadWindowsEventWatch(ctx, tx, id)
	if e != nil {
		if ctx.Err() == nil {
			s.windowsEventWatchBlocked.Store(true)
		}
		return v, e
	}
	now := clock().UTC()
	if e = guard(now); e != nil {
		return v, e
	}
	if command != nil {
		c := command
		if !enrollmentcrypto.ValidID(c.RequestID, "eventrequest_") || c.ExpectedRevision != v.Revision || v.Revision == windowseventwatch.MaxCounter || c.SourceToken != windowseventwatch.SourceToken(in) || v.LastRequest != nil && v.LastRequest.RequestID == c.RequestID {
			return v, ErrWindowsEventWatchConflict
		}
		if v.State.DeviceID != "" && (v.State.DeviceID != in.Source.DeviceID || v.State.InvitationID != in.Source.InvitationID || v.State.CertificateHash != in.Source.CertificateHash) {
			return v, ErrWindowsEventWatchConflict
		}
		switch c.Operation {
		case "policy":
			if c.Selectors == nil || len(c.Selectors) > windowseventwatch.MaxSelectors || c.Enabled && (!c.RetentionAcknowledged || len(c.Selectors) == 0 || !windowseventwatch.Fresh(in, now)) || !c.Enabled && (len(c.Selectors) != 0 || c.RetentionAcknowledged) {
				return v, windowseventwatch.ErrInvalid
			}
			if c.Enabled {
				if v.State.GrantID != "" && !v.State.SourceMatches(in) {
					return v, ErrWindowsEventWatchConflict
				}
				for _, sel := range c.Selectors {
					found := false
					for _, ch := range in.Events.Channels {
						for _, row := range ch.Rows {
							if sel.Channel == ch.Channel && sel.Provider == row.Provider && sel.EventID == row.EventID && sel.Level == row.Level {
								found = true
							}
						}
					}
					if !found {
						return v, ErrWindowsEventWatchConflict
					}
				}
			}
			p := windowseventwatch.Policy{Enabled: c.Enabled, Revision: v.Revision + 1, Selectors: c.Selectors, RetentionAcknowledged: c.RetentionAcknowledged}
			if c.Enabled {
				p.EnabledAt = now
			}
			if e = v.State.SetPolicy(p, now); e != nil {
				return v, e
			}
			if c.Enabled {
				if e = v.State.Evaluate(in, now); e != nil {
					return v, e
				}
			}
		case "review":
			if !v.State.SourceMatches(in) {
				return v, ErrWindowsEventWatchConflict
			}
			if e = v.State.Review(c.IncidentID, now); e != nil {
				return v, e
			}
		default:
			return v, windowseventwatch.ErrInvalid
		}
		v.Revision++
		v.LastRequest = &WindowsEventWatchRequest{RequestID: c.RequestID, Operation: c.Operation}
		if c.Operation == "review" {
			id := c.IncidentID
			v.LastRequest.IncidentID = &id
		}
	} else if retentionOnly {
		if !exists {
			return v, nil
		}
		e = v.State.Cleanup(now)
	} else if evaluate {
		if !exists || !v.State.Policy.Enabled {
			return v, nil
		}
		e = v.State.Evaluate(in, now)
	} else {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	raw, e := encodeWindowsEventWatchRecord(v)
	if e != nil {
		return v, e
	}
	if e = guard(now); e != nil {
		return v, e
	}
	if !exists {
		var n int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM windows_event_watches`).Scan(&n) != nil || n >= 25 {
			return v, ErrWindowsEventWatchUnavailable
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO windows_event_watch_markers(id) VALUES(?)`, id); e != nil {
			return v, e
		}
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO windows_event_watches(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`, id, raw); e != nil {
		return v, e
	}
	final := clock().UTC()
	if final.Before(now) {
		return v, ErrWindowsEventWatchConflict
	}
	if e = guard(final); e != nil {
		return v, e
	}
	if s.windowsEventWatchBlocked.Load() {
		return v, ErrWindowsEventWatchUnavailable
	}
	if e = tx.Commit(); e != nil {
		if ctx.Err() == nil {
			s.windowsEventWatchBlocked.Store(true)
		}
		return v, ErrWindowsEventWatchUnavailable
	}
	return v, nil
}
