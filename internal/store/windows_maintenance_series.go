package store

// Finite series have their own canonical ledger. They are never represented as
// persisted v1 schedules: v1's serial history invariant cannot express siblings.
import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"localrmm/internal/alarmdelivery"
)

const windowsMaintenanceSeriesSchema = `CREATE TABLE IF NOT EXISTS windows_maintenance_series(target TEXT PRIMARY KEY,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=16384 AND json_valid(body))); CREATE TABLE IF NOT EXISTS windows_maintenance_series_used(target TEXT PRIMARY KEY); CREATE TABLE IF NOT EXISTS windows_maintenance_series_receipts(operation TEXT PRIMARY KEY,target TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=4096 AND json_valid(body)))`
const WindowsMaintenanceSeriesReviewAge = 120 * time.Second
const WindowsMaintenanceSeriesReceiptAge = 24 * time.Hour
const maxWindowsMaintenanceSeriesReceipts = 9600

type WindowsMaintenanceSeriesDates struct {
	StartsAt time.Time `json:"startsAt"`
	EndsAt   time.Time `json:"endsAt"`
}
type WindowsMaintenanceSeriesOccurrence struct {
	ID          uint64     `json:"id"`
	SeriesID    uint64     `json:"seriesId"`
	CreatedAt   time.Time  `json:"createdAt"`
	StartsAt    time.Time  `json:"startsAt"`
	EndsAt      time.Time  `json:"endsAt"`
	CancelledAt *time.Time `json:"cancelledAt"`
	EndedAt     *time.Time `json:"endedAt"`
	Intent      string     `json:"intent"`
}

func (w WindowsMaintenanceSeriesOccurrence) window() WindowsMaintenanceScheduleWindow {
	return WindowsMaintenanceScheduleWindow{ID: w.ID, CreatedAt: w.CreatedAt, StartsAt: w.StartsAt, EndsAt: w.EndsAt, CancelledAt: w.CancelledAt, EndedAt: w.EndedAt, Intent: w.Intent}
}
func (w WindowsMaintenanceSeriesOccurrence) Pending(at time.Time) bool { return w.window().Pending(at) }
func (w WindowsMaintenanceSeriesOccurrence) Active(at time.Time) bool  { return w.window().Active(at) }
func (w WindowsMaintenanceSeriesOccurrence) Suppresses(transition, at time.Time) bool {
	return w.window().Suppresses(transition, at)
}

// Definitions retain the immutable original sibling set even when its oldest
// terminal members have safely crossed the retired prefix floor.
type WindowsMaintenanceSeriesDefinition struct {
	ID                uint64    `json:"id"`
	FirstOccurrenceID uint64    `json:"firstOccurrenceId"`
	Count             int       `json:"count"`
	CreatedAt         time.Time `json:"createdAt"`
	StartsAt          time.Time `json:"startsAt"`
	EndsAt            time.Time `json:"endsAt"`
	Intent            string    `json:"intent"`
}
type WindowsMaintenanceSeriesState struct {
	Version            int                                  `json:"version"`
	Target             WindowsMaintenanceTarget             `json:"target"`
	Revision           uint64                               `json:"revision"`
	ChangedAt          time.Time                            `json:"changedAt"`
	ObservedAt         time.Time                            `json:"observedAt"`
	LastOccurrenceID   uint64                               `json:"lastOccurrenceId"`
	RetiredOccurrences uint64                               `json:"retiredOccurrences"`
	RetiredThroughAt   *time.Time                           `json:"retiredThroughAt"`
	Occurrences        []WindowsMaintenanceSeriesOccurrence `json:"occurrences"`
	Series             []WindowsMaintenanceSeriesDefinition `json:"series"`
	ActionRevisions    []uint64                             `json:"actionRevisions"`
}

func (s WindowsMaintenanceSeriesState) valid() bool {
	if s.Version != 1 || !s.Target.Valid() || s.Revision < 1 || s.Revision > MaxWindowsMaintenanceRevision || s.LastOccurrenceID < 2 || s.LastOccurrenceID > MaxWindowsMaintenanceRevision || !validMaintenanceTime(s.ChangedAt) || !validMaintenanceTime(s.ObservedAt) || s.ObservedAt.Before(s.ChangedAt) || len(s.Occurrences) < 1 || len(s.Occurrences) > 16 || s.RetiredOccurrences+uint64(len(s.Occurrences)) != s.LastOccurrenceID || len(s.Series) < 1 || len(s.Series) > 16 || len(s.ActionRevisions) != len(s.Occurrences) {
		return false
	}
	if s.RetiredOccurrences == 0 {
		if s.RetiredThroughAt != nil {
			return false
		}
	} else {
		if len(s.Occurrences) < 4 || s.RetiredThroughAt == nil || !validMaintenanceTime(*s.RetiredThroughAt) || s.ObservedAt.Before(s.RetiredThroughAt.Add(alarmdelivery.MaxQueueAge)) {
			return false
		}
	}
	definitions := map[uint64]WindowsMaintenanceSeriesDefinition{}
	for i, d := range s.Series {
		if d.ID < 1 || d.ID > s.Revision || d.Count < 2 || d.Count > 4 || d.FirstOccurrenceID < 1 || d.FirstOccurrenceID > MaxWindowsMaintenanceRevision-uint64(d.Count-1) || !validMaintenanceTime(d.CreatedAt) || !validMaintenanceTime(d.StartsAt) || !validMaintenanceTime(d.EndsAt) || d.StartsAt.Sub(d.CreatedAt) < time.Minute || d.StartsAt.Sub(d.CreatedAt) > 7*24*time.Hour || d.EndsAt.Sub(d.StartsAt) < time.Minute || d.EndsAt.Sub(d.StartsAt) > 24*time.Hour || d.EndsAt.Add(time.Duration(d.Count-1)*7*24*time.Hour).Sub(d.CreatedAt) > 29*24*time.Hour || !ValidWindowsMaintenanceIntent(d.Intent) || d.CreatedAt.After(s.ChangedAt) {
			return false
		}
		if i == 0 {
			if d.FirstOccurrenceID > s.RetiredOccurrences+1 || d.FirstOccurrenceID+uint64(d.Count) <= s.RetiredOccurrences+1 {
				return false
			}
		} else {
			prev := s.Series[i-1]
			if d.ID <= prev.ID || d.FirstOccurrenceID != prev.FirstOccurrenceID+uint64(prev.Count) || d.CreatedAt.Before(prev.CreatedAt) {
				return false
			}
		}
		definitions[d.ID] = d
	}
	if s.RetiredOccurrences > 0 && s.Series[0].FirstOccurrenceID <= s.RetiredOccurrences {
		d := s.Series[0]
		lastRetiredEnd := d.EndsAt.Add(time.Duration(s.RetiredOccurrences-d.FirstOccurrenceID) * 7 * 24 * time.Hour)
		if s.RetiredThroughAt.Before(lastRetiredEnd) {
			return false
		}
	}
	last := s.Series[len(s.Series)-1]
	if last.FirstOccurrenceID+uint64(last.Count)-1 != s.LastOccurrenceID {
		return false
	}
	for i, w := range s.Occurrences {
		revision := s.ActionRevisions[i]
		if w.CancelledAt != nil || w.EndedAt != nil {
			if revision <= w.SeriesID || revision > s.Revision {
				return false
			}
		} else if revision != 0 {
			return false
		}
		d, ok := definitions[w.SeriesID]
		if !ok || w.ID != s.RetiredOccurrences+uint64(i)+1 || w.ID < d.FirstOccurrenceID || w.ID >= d.FirstOccurrenceID+uint64(d.Count) {
			return false
		}
		offset := time.Duration(w.ID-d.FirstOccurrenceID) * 7 * 24 * time.Hour
		if !w.CreatedAt.Equal(d.CreatedAt) || !w.StartsAt.Equal(d.StartsAt.Add(offset)) || !w.EndsAt.Equal(d.EndsAt.Add(offset)) || w.Intent != d.Intent || !validMaintenanceTime(w.CreatedAt) || !validMaintenanceTime(w.StartsAt) || !validMaintenanceTime(w.EndsAt) {
			return false
		}
		if w.CancelledAt != nil && (w.EndedAt != nil || !validMaintenanceTime(*w.CancelledAt) || w.CancelledAt.Before(w.CreatedAt) || !w.CancelledAt.Before(w.StartsAt) || w.CancelledAt.After(s.ChangedAt)) {
			return false
		}
		if w.EndedAt != nil && (!validMaintenanceTime(*w.EndedAt) || w.EndedAt.Before(w.StartsAt) || !w.EndedAt.Before(w.EndsAt) || w.EndedAt.After(s.ChangedAt)) {
			return false
		}
	}
	return true
}

type WindowsMaintenanceSeriesReceipt struct {
	Version       int                      `json:"version"`
	OperationID   string                   `json:"operationId"`
	Target        WindowsMaintenanceTarget `json:"target"`
	Action        string                   `json:"action"`
	Revision      uint64                   `json:"revision"`
	OccurrenceIDs []uint64                 `json:"occurrenceIds"`
	CommittedAt   time.Time                `json:"committedAt"`
	ExpiresAt     time.Time                `json:"expiresAt"`
}

func maintenanceSeriesOperationTime(id string) (time.Time, bool) {
	p := strings.Split(id, "_")
	if len(p) != 3 || p[0] != "wms" || len(p[2]) != 32 {
		return time.Time{}, false
	}
	raw, e := hex.DecodeString(p[2])
	if e != nil || hex.EncodeToString(raw) != p[2] {
		return time.Time{}, false
	}
	ms, e := strconv.ParseInt(p[1], 10, 64)
	if e != nil || strconv.FormatInt(ms, 10) != p[1] {
		return time.Time{}, false
	}
	at := time.UnixMilli(ms).UTC()
	return at, validMaintenanceTime(at)
}
func (r WindowsMaintenanceSeriesReceipt) valid() bool {
	issued, ok := maintenanceSeriesOperationTime(r.OperationID)
	if !ok || r.Version != 1 || !r.Target.Valid() || r.Revision < 1 || r.Revision > MaxWindowsMaintenanceRevision || !validMaintenanceTime(r.CommittedAt) || r.CommittedAt.Before(issued) || !r.CommittedAt.Before(issued.Add(WindowsMaintenanceSeriesReviewAge)) || !r.ExpiresAt.Equal(r.CommittedAt.Add(WindowsMaintenanceSeriesReceiptAge)) {
		return false
	}
	if r.Action == "create" {
		if len(r.OccurrenceIDs) < 2 || len(r.OccurrenceIDs) > 4 {
			return false
		}
	} else if (r.Action != "cancel" && r.Action != "end") || len(r.OccurrenceIDs) != 1 {
		return false
	}
	var last uint64
	for _, id := range r.OccurrenceIDs {
		if id <= last || id > MaxWindowsMaintenanceRevision {
			return false
		}
		last = id
	}
	return true
}
func maintenanceSeriesTablesPresent(ctx context.Context, tx *sql.Tx) (bool, error) {
	var n int
	e := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('windows_maintenance_series','windows_maintenance_series_used','windows_maintenance_series_receipts')`).Scan(&n)
	if e != nil {
		return false, e
	}
	if n != 0 && n != 3 {
		return false, ErrWindowsMaintenance
	}
	return n == 3, nil
}
func readWindowsMaintenanceSeries(ctx context.Context, tx *sql.Tx) ([]WindowsMaintenanceSeriesState, error) {
	out := []WindowsMaintenanceSeriesState{}
	present, e := maintenanceSeriesTablesPresent(ctx, tx)
	if e != nil {
		return nil, e
	}
	var version int
	if e = tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); e != nil {
		return nil, e
	}
	if !present {
		if version >= 3 {
			return nil, ErrWindowsMaintenance
		}
		return out, nil
	}
	var mismatch int
	if e = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM windows_maintenance_series s LEFT JOIN windows_maintenance_series_used u USING(target) WHERE u.target IS NULL)+(SELECT count(*) FROM windows_maintenance_series_used u LEFT JOIN windows_maintenance_series s USING(target) WHERE s.target IS NULL)`).Scan(&mismatch); e != nil || mismatch != 0 {
		return nil, ErrWindowsMaintenance
	}
	rows, e := tx.QueryContext(ctx, `SELECT target,body FROM windows_maintenance_series ORDER BY target LIMIT 151`)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var key string
		var raw []byte
		var s WindowsMaintenanceSeriesState
		if e = rows.Scan(&key, &raw); e != nil {
			rows.Close()
			return nil, e
		}
		if len(raw) > 16384 || json.Unmarshal(raw, &s) != nil || !s.valid() || s.Target.Key() != key {
			rows.Close()
			return nil, ErrWindowsMaintenance
		}
		canonical, _ := json.Marshal(s)
		if !bytes.Equal(canonical, raw) {
			rows.Close()
			return nil, ErrWindowsMaintenance
		}
		out = append(out, s)
		if len(out) > 150 {
			rows.Close()
			return nil, ErrWindowsMaintenance
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if (version < 3 && len(out) > 0) || (version >= 3 && len(out) == 0) {
		return nil, ErrWindowsMaintenance
	}
	return out, nil
}
func receiptMatchesSeries(r WindowsMaintenanceSeriesReceipt, s WindowsMaintenanceSeriesState) bool {
	if r.Target != s.Target || r.Revision > s.Revision || r.CommittedAt.After(s.ChangedAt) || r.Revision == s.Revision && !r.CommittedAt.Equal(s.ChangedAt) {
		return false
	}
	allRetired := true
	for _, id := range r.OccurrenceIDs {
		if id > s.LastOccurrenceID {
			return false
		}
		if id > s.RetiredOccurrences {
			allRetired = false
		}
	}
	if allRetired {
		return !s.ObservedAt.Before(r.ExpiresAt)
	}
	if r.Action == "create" {
		for _, d := range s.Series {
			if d.ID != r.Revision {
				continue
			}
			if len(r.OccurrenceIDs) != d.Count || !r.CommittedAt.Equal(d.CreatedAt) {
				return false
			}
			for i, id := range r.OccurrenceIDs {
				if id != d.FirstOccurrenceID+uint64(i) {
					return false
				}
			}
			return true
		}
		return false
	}
	for i, w := range s.Occurrences {
		if w.ID == r.OccurrenceIDs[0] {
			if s.ActionRevisions[i] != r.Revision {
				return false
			}
			if r.Action == "cancel" {
				return w.CancelledAt != nil && w.CancelledAt.Equal(r.CommittedAt)
			}
			return w.EndedAt != nil && w.EndedAt.Equal(r.CommittedAt)
		}
	}
	return false
}
func readMaintenanceSeriesReceipts(ctx context.Context, tx *sql.Tx) ([]WindowsMaintenanceSeriesReceipt, error) {
	out := []WindowsMaintenanceSeriesReceipt{}
	present, e := maintenanceSeriesTablesPresent(ctx, tx)
	if e != nil || !present {
		return out, e
	}
	rows, e := tx.QueryContext(ctx, `SELECT operation,target,body FROM windows_maintenance_series_receipts ORDER BY operation LIMIT ?`, maxWindowsMaintenanceSeriesReceipts+1)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var id, key string
		var raw []byte
		var r WindowsMaintenanceSeriesReceipt
		if e = rows.Scan(&id, &key, &raw); e != nil {
			return nil, e
		}
		if len(raw) > 4096 || json.Unmarshal(raw, &r) != nil || !r.valid() || r.OperationID != id || r.Target.Key() != key {
			return nil, ErrWindowsMaintenance
		}
		canonical, _ := json.Marshal(r)
		if !bytes.Equal(raw, canonical) {
			return nil, ErrWindowsMaintenance
		}
		out = append(out, r)
		if len(out) > maxWindowsMaintenanceSeriesReceipts {
			return nil, ErrWindowsMaintenance
		}
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if e = rows.Close(); e != nil {
		return nil, e
	}
	states, e := readWindowsMaintenanceSeries(ctx, tx)
	if e != nil {
		return nil, e
	}
	for _, r := range out {
		found := false
		for _, state := range states {
			if receiptMatchesSeries(r, state) {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrWindowsMaintenance
		}
	}
	return out, nil
}
func saveWindowsMaintenanceSeries(ctx context.Context, tx *sql.Tx, s WindowsMaintenanceSeriesState) error {
	if !s.valid() {
		return ErrWindowsMaintenance
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > 16384 {
		return ErrWindowsMaintenance
	}
	if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO windows_maintenance_series_used(target) VALUES(?)`, s.Target.Key()); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO windows_maintenance_series(target,body) VALUES(?,?) ON CONFLICT(target) DO UPDATE SET body=excluded.body`, s.Target.Key(), raw)
	return e
}

// An in-memory suppression adapter only; never pass these rows to the v1 writer.
func seriesScheduleAdapter(states []WindowsMaintenanceSeriesState) []WindowsMaintenanceScheduleState {
	out := []WindowsMaintenanceScheduleState{}
	for _, s := range states {
		v := WindowsMaintenanceScheduleState{Target: s.Target, ObservedAt: s.ObservedAt, Windows: []WindowsMaintenanceScheduleWindow{}}
		for _, w := range s.Occurrences {
			v.Windows = append(v.Windows, w.window())
		}
		out = append(out, v)
	}
	return out
}
func observeWindowsMaintenanceSeries(ctx context.Context, tx *sql.Tx, states []WindowsMaintenanceSeriesState, now time.Time, strict bool) error {
	for i := range states {
		s := &states[i]
		if now.Before(s.ObservedAt) {
			if strict {
				return ErrWindowsMaintenanceConflict
			}
			continue
		}
		if now.After(s.ObservedAt) {
			s.ObservedAt = now
			if e := saveWindowsMaintenanceSeries(ctx, tx, *s); e != nil {
				return e
			}
		}
	}
	return nil
}
func maintenanceSeriesCapacity(legacy []WindowsMaintenanceScheduleState, series []WindowsMaintenanceSeriesState, target WindowsMaintenanceTarget, additional int) error {
	keys := map[string]int{}
	for _, s := range legacy {
		keys[s.Target.Key()] += len(s.Windows)
	}
	for _, s := range series {
		keys[s.Target.Key()] += len(s.Occurrences)
	}
	if target.Valid() {
		keys[target.Key()] += additional
	}
	if len(keys) > MaxWindowsMaintenanceTargets {
		return ErrLimit
	}
	for _, n := range keys {
		if n > MaxWindowsMaintenanceSchedules {
			return ErrLimit
		}
	}
	return nil
}
func pruneWindowsMaintenanceSeries(s *WindowsMaintenanceSeriesState, now time.Time) {
	// Retire only a contiguous prefix. A future sibling always fences retirement,
	// even if later siblings were cancelled early; gaps are never interpreted as use.
	for len(s.Occurrences) > 4 {
		w := s.Occurrences[0]
		end := w.EndsAt // Conservative immutable nominal horizon, even after cancellation.
		if w.Pending(now) || w.Active(now) || now.Before(end.Add(alarmdelivery.MaxQueueAge)) {
			break
		}
		if s.RetiredThroughAt == nil || end.After(*s.RetiredThroughAt) {
			stamp := end
			s.RetiredThroughAt = &stamp
		}
		s.RetiredOccurrences++
		s.Occurrences = s.Occurrences[1:]
		s.ActionRevisions = s.ActionRevisions[1:]
	}
	for len(s.Series) > 1 && s.Series[0].FirstOccurrenceID+uint64(s.Series[0].Count)-1 <= s.RetiredOccurrences {
		s.Series = s.Series[1:]
	}
}

func (s *Store) WindowsMaintenanceSeries(ctx context.Context, clock func() time.Time) ([]WindowsMaintenanceSeriesState, error) {
	_, series, _, err := s.ReadWindowsMaintenancePlanning(ctx, clock)
	return series, err
}

// ReadWindowsMaintenancePlanning returns the complete manager-owned planning
// snapshot under one transaction. Old wire shapes stay untouched; a modern
// caller can derive exact cross-ledger reservations without a split-read race.
func (s *Store) ReadWindowsMaintenancePlanning(ctx context.Context, clock func() time.Time) ([]WindowsMaintenanceScheduleState, []WindowsMaintenanceSeriesState, []WindowsMaintenanceState, error) {
	if clock == nil {
		return nil, nil, nil, ErrWindowsMaintenance
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, nil, nil, e
	}
	defer tx.Rollback()
	series, e := readWindowsMaintenanceSeries(ctx, tx)
	if e != nil {
		return nil, nil, nil, e
	}
	legacy, e := readWindowsMaintenanceSchedules(ctx, tx)
	if e != nil {
		return nil, nil, nil, e
	}
	immediate, e := readWindowsMaintenance(ctx, tx)
	if e != nil {
		return nil, nil, nil, e
	}
	now := clock().UTC()
	if !validMaintenanceTime(now) {
		return nil, nil, nil, ErrWindowsMaintenanceConflict
	}
	if e = observeWindowsMaintenanceSeries(ctx, tx, series, now, true); e != nil {
		return nil, nil, nil, e
	}
	for _, v := range legacy {
		if now.Before(v.ObservedAt) {
			return nil, nil, nil, ErrWindowsMaintenanceConflict
		}
	}
	if e = consumeScheduledWindowsNotifications(ctx, tx, legacy, now); e != nil {
		return nil, nil, nil, e
	}
	for i := range legacy {
		pruneWindowsMaintenanceSchedules(&legacy[i], now)
		if e = saveWindowsMaintenanceSchedule(ctx, tx, legacy[i]); e != nil {
			return nil, nil, nil, e
		}
	}
	for i := range series {
		pruneWindowsMaintenanceSeries(&series[i], now)
		if e = saveWindowsMaintenanceSeries(ctx, tx, series[i]); e != nil {
			return nil, nil, nil, e
		}
	}
	if e = maintenanceSeriesCapacity(legacy, series, WindowsMaintenanceTarget{}, 0); e != nil {
		return nil, nil, nil, e
	}
	final := clock().UTC()
	if !validMaintenanceTime(final) || final.Before(now) {
		return nil, nil, nil, ErrWindowsMaintenanceConflict
	}
	if e = tx.Commit(); e != nil {
		return nil, nil, nil, e
	}
	return legacy, series, immediate, nil
}
func (s *Store) WindowsMaintenanceSeriesReceipt(ctx context.Context, id string) (WindowsMaintenanceSeriesReceipt, bool, error) {
	zero := WindowsMaintenanceSeriesReceipt{}
	if _, ok := maintenanceSeriesOperationTime(id); !ok {
		return zero, false, ErrWindowsMaintenance
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return zero, false, e
	}
	defer tx.Rollback()
	states, e := readWindowsMaintenanceSeries(ctx, tx)
	if e != nil {
		return zero, false, e
	}
	receipts, e := readMaintenanceSeriesReceipts(ctx, tx)
	if e != nil {
		return zero, false, e
	}
	for _, r := range receipts {
		if r.OperationID == id {
			for _, v := range states {
				if v.Target == r.Target && r.Revision <= v.Revision {
					return r, true, nil
				}
			}
			return zero, false, ErrWindowsMaintenance
		}
	}
	return zero, false, nil // Absence is unresolved, never a certificate of non-execution.
}
func validateSeriesChange(target WindowsMaintenanceTarget, expected uint64, action string, id uint64, dates []WindowsMaintenanceSeriesDates, intent string, now time.Time, legacy []WindowsMaintenanceScheduleState, series []WindowsMaintenanceSeriesState, immediate []WindowsMaintenanceState) (WindowsMaintenanceSeriesState, time.Time, error) {
	zero := WindowsMaintenanceSeriesState{}
	if !target.Valid() || expected >= MaxWindowsMaintenanceRevision || !validMaintenanceTime(now) {
		return zero, time.Time{}, ErrWindowsMaintenance
	}
	next := WindowsMaintenanceSeriesState{Version: 1, Target: target, Occurrences: []WindowsMaintenanceSeriesOccurrence{}}
	for _, v := range series {
		if v.Target == target {
			next = v
		}
		if v.Target.sameIdentity(target) && now.Before(v.ObservedAt) {
			return zero, time.Time{}, ErrWindowsMaintenanceConflict
		}
	}
	if next.Revision != expected {
		return zero, time.Time{}, ErrWindowsMaintenanceConflict
	}
	for _, v := range legacy {
		if v.Target.sameIdentity(target) && now.Before(v.ObservedAt) {
			return zero, time.Time{}, ErrWindowsMaintenanceConflict
		}
	}
	for _, v := range immediate {
		if v.Target.sameIdentity(target) && now.Before(v.ChangedAt) {
			return zero, time.Time{}, ErrWindowsMaintenanceConflict
		}
	}
	deadline := time.Time{}
	if action == "create" {
		if id != 0 || len(dates) < 2 || len(dates) > 4 || !ValidWindowsMaintenanceIntent(intent) {
			return zero, deadline, ErrWindowsMaintenance
		}
		for i, d := range dates {
			if !validMaintenanceTime(d.StartsAt) || !validMaintenanceTime(d.EndsAt) || d.EndsAt.Sub(d.StartsAt) < time.Minute || d.EndsAt.Sub(d.StartsAt) > 24*time.Hour {
				return zero, deadline, ErrWindowsMaintenance
			}
			if i == 0 {
				if d.StartsAt.Sub(now) < time.Minute || d.StartsAt.Sub(now) > 7*24*time.Hour {
					return zero, deadline, ErrWindowsMaintenanceConflict
				}
			} else if d.StartsAt.Sub(dates[i-1].StartsAt) != 7*24*time.Hour || d.EndsAt.Sub(dates[i-1].EndsAt) != 7*24*time.Hour {
				return zero, deadline, ErrWindowsMaintenance
			}
		}
		if dates[len(dates)-1].EndsAt.Sub(now) > 29*24*time.Hour {
			return zero, deadline, ErrWindowsMaintenanceConflict
		}
		combined := append(append([]WindowsMaintenanceScheduleState{}, legacy...), seriesScheduleAdapter(series)...)
		if e := schedulesOverlapImmediate(combined, target, now, dates[len(dates)-1].EndsAt); e != nil {
			return zero, deadline, e
		}
		for _, v := range immediate {
			if maintenanceDomainsOverlap(v.Target, target) && v.Windows[0].Active(now) {
				return zero, deadline, ErrWindowsMaintenanceConflict
			}
		}
		if e := maintenanceSeriesCapacity(legacy, series, target, len(dates)); e != nil {
			return zero, deadline, e
		}
		if next.LastOccurrenceID > MaxWindowsMaintenanceRevision-uint64(len(dates)) {
			return zero, deadline, ErrLimit
		}
		deadline = dates[0].StartsAt
		next.ActionRevisions = append([]uint64{}, next.ActionRevisions...)
		next.Series = append(append([]WindowsMaintenanceSeriesDefinition{}, next.Series...), WindowsMaintenanceSeriesDefinition{ID: expected + 1, FirstOccurrenceID: next.LastOccurrenceID + 1, Count: len(dates), CreatedAt: now, StartsAt: dates[0].StartsAt, EndsAt: dates[0].EndsAt, Intent: intent})
		next.Occurrences = append([]WindowsMaintenanceSeriesOccurrence{}, next.Occurrences...)
		for _, d := range dates {
			next.LastOccurrenceID++
			next.ActionRevisions = append(next.ActionRevisions, 0)
			next.Occurrences = append(next.Occurrences, WindowsMaintenanceSeriesOccurrence{ID: next.LastOccurrenceID, SeriesID: expected + 1, CreatedAt: now, StartsAt: d.StartsAt, EndsAt: d.EndsAt, Intent: intent})
		}
	} else {
		if (action != "cancel" && action != "end") || id == 0 || len(dates) != 0 || intent != "" {
			return zero, deadline, ErrWindowsMaintenance
		}
		found := false
		next.ActionRevisions = append([]uint64{}, next.ActionRevisions...)
		next.Occurrences = append([]WindowsMaintenanceSeriesOccurrence{}, next.Occurrences...)
		for i := range next.Occurrences {
			w := &next.Occurrences[i]
			if w.ID != id {
				continue
			}
			found = true
			next.ActionRevisions[i] = expected + 1
			if action == "cancel" {
				if !w.Pending(now) {
					return zero, deadline, ErrWindowsMaintenanceConflict
				}
				w.CancelledAt = &now
				deadline = w.StartsAt
			} else {
				if !w.Active(now) {
					return zero, deadline, ErrWindowsMaintenanceConflict
				}
				w.EndedAt = &now
				deadline = w.EndsAt
			}
		}
		if !found {
			return zero, deadline, ErrWindowsMaintenanceConflict
		}
	}
	next.Revision = expected + 1
	next.ChangedAt = now
	next.ObservedAt = now
	if !next.valid() {
		return zero, deadline, ErrWindowsMaintenance
	}
	return next, deadline, nil
}
func (s *Store) PreviewWindowsMaintenanceSeries(ctx context.Context, target WindowsMaintenanceTarget, expected uint64, action string, id uint64, dates []WindowsMaintenanceSeriesDates, intent string, clock func() time.Time) error {
	if clock == nil {
		return ErrWindowsMaintenance
	}
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	series, e := readWindowsMaintenanceSeries(ctx, tx)
	if e != nil {
		return e
	}
	legacy, e := readWindowsMaintenanceSchedules(ctx, tx)
	if e != nil {
		return e
	}
	immediate, e := readWindowsMaintenance(ctx, tx)
	if e != nil {
		return e
	}
	_, _, e = validateSeriesChange(target, expected, action, id, dates, intent, clock().UTC(), legacy, series, immediate)
	return e
}
func (s *Store) ChangeWindowsMaintenanceSeries(ctx context.Context, target WindowsMaintenanceTarget, expected uint64, action string, id uint64, dates []WindowsMaintenanceSeriesDates, intent, operationID string, issuedAt, expiresAt time.Time, clock func() time.Time, guard func(time.Time, time.Time) error) (WindowsMaintenanceSeriesReceipt, error) {
	zero := WindowsMaintenanceSeriesReceipt{}
	issued, ok := maintenanceSeriesOperationTime(operationID)
	if !ok || !issued.Equal(issuedAt) || !validMaintenanceTime(expiresAt) || !expiresAt.After(issuedAt) || expiresAt.After(issuedAt.Add(WindowsMaintenanceSeriesReviewAge)) || clock == nil || guard == nil {
		return zero, ErrWindowsMaintenance
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return zero, e
	}
	defer tx.Rollback()
	now := clock().UTC()
	if !validMaintenanceTime(now) || now.Before(issuedAt) || !now.Before(expiresAt) {
		return zero, ErrWindowsMaintenanceConflict
	}
	if e = guard(now, expiresAt); e != nil {
		return zero, e
	}
	series, e := readWindowsMaintenanceSeries(ctx, tx)
	if e != nil {
		return zero, e
	}
	legacy, e := readWindowsMaintenanceSchedules(ctx, tx)
	if e != nil {
		return zero, e
	}
	immediate, e := readWindowsMaintenance(ctx, tx)
	if e != nil {
		return zero, e
	}
	receipts, e := readMaintenanceSeriesReceipts(ctx, tx)
	if e != nil {
		return zero, e
	}
	for _, r := range receipts {
		if r.OperationID == operationID {
			return zero, ErrWindowsMaintenanceConflict
		}
	}
	if e = observeWindowsMaintenanceSeries(ctx, tx, series, now, true); e != nil {
		return zero, e
	}
	if e = consumeScheduledWindowsNotifications(ctx, tx, legacy, now); e != nil {
		return zero, e
	}
	for i := range series {
		pruneWindowsMaintenanceSeries(&series[i], now)
	}
	for i := range legacy {
		if now.Before(legacy[i].ObservedAt) {
			return zero, ErrWindowsMaintenanceConflict
		}
		pruneWindowsMaintenanceSchedules(&legacy[i], now)
		if e = saveWindowsMaintenanceSchedule(ctx, tx, legacy[i]); e != nil {
			return zero, e
		}
	}
	next, deadline, e := validateSeriesChange(target, expected, action, id, dates, intent, now, legacy, series, immediate)
	if e != nil {
		return zero, e
	}
	// First explicit use creates the entire separate schema and durable compatibility
	// marker in the same transaction as the exact plan and immutable receipt.
	if _, e = tx.ExecContext(ctx, windowsMaintenanceSeriesSchema); e != nil {
		return zero, e
	}
	if _, e = tx.ExecContext(ctx, `PRAGMA user_version=3`); e != nil {
		return zero, e
	}
	found := false
	for i := range series {
		if series[i].Target == target {
			series[i] = next
			found = true
		}
	}
	if !found {
		series = append(series, next)
	}
	for _, v := range series {
		if e = saveWindowsMaintenanceSeries(ctx, tx, v); e != nil {
			return zero, e
		}
	}
	retained := 0
	for _, r := range receipts {
		if !now.Before(r.ExpiresAt) {
			if _, e = tx.ExecContext(ctx, `DELETE FROM windows_maintenance_series_receipts WHERE operation=?`, r.OperationID); e != nil {
				return zero, e
			}
		} else {
			retained++
		}
	}
	if retained >= maxWindowsMaintenanceSeriesReceipts {
		return zero, ErrLimit
	}
	receipt := WindowsMaintenanceSeriesReceipt{Version: 1, OperationID: operationID, Target: target, Action: action, Revision: next.Revision, OccurrenceIDs: []uint64{}, CommittedAt: now, ExpiresAt: now.Add(WindowsMaintenanceSeriesReceiptAge)}
	if action == "create" {
		for _, w := range next.Occurrences {
			if w.SeriesID == next.Revision {
				receipt.OccurrenceIDs = append(receipt.OccurrenceIDs, w.ID)
			}
		}
	} else {
		receipt.OccurrenceIDs = append(receipt.OccurrenceIDs, id)
	}
	if !receipt.valid() {
		return zero, ErrWindowsMaintenance
	}
	raw, _ := json.Marshal(receipt)
	if _, e = tx.ExecContext(ctx, `INSERT INTO windows_maintenance_series_receipts(operation,target,body) VALUES(?,?,?)`, operationID, target.Key(), raw); e != nil {
		return zero, e
	}
	if e = consumeScheduledWindowsNotifications(ctx, tx, legacy, now); e != nil {
		return zero, e
	}
	check := func(at, previous time.Time) error {
		if !validMaintenanceTime(at) || at.Before(previous) || !at.Before(expiresAt) || !at.Before(deadline) || action == "create" && dates[0].StartsAt.Sub(at) < time.Minute {
			return ErrWindowsMaintenanceConflict
		}
		return nil
	}
	final := clock().UTC()
	if e = check(final, now); e != nil {
		return zero, e
	}
	if expiresAt.Before(deadline) {
		deadline = expiresAt
	}
	if e = guard(final, deadline); e != nil {
		return zero, e
	}
	if e = check(clock().UTC(), final); e != nil {
		return zero, e
	}
	if e = tx.Commit(); e != nil {
		return zero, e
	}
	return receipt, nil
}
