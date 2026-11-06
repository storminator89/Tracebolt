package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"localrmm/internal/alarmdelivery"
)

const windowsMaintenanceScheduleSchema = `CREATE TABLE IF NOT EXISTS windows_maintenance_schedules(id TEXT NOT NULL,domain TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=8192 AND json_valid(body)),PRIMARY KEY(id,domain)); CREATE TABLE IF NOT EXISTS windows_maintenance_schedule_used(id TEXT NOT NULL,domain TEXT NOT NULL,PRIMARY KEY(id,domain))`
const MaxWindowsMaintenanceSchedules = 16

type WindowsMaintenanceScheduleWindow struct {
	ID          uint64     `json:"id"`
	CreatedAt   time.Time  `json:"createdAt"`
	StartsAt    time.Time  `json:"startsAt"`
	EndsAt      time.Time  `json:"endsAt"`
	CancelledAt *time.Time `json:"cancelledAt"`
	EndedAt     *time.Time `json:"endedAt"`
	Intent      string     `json:"intent"`
}

func (w WindowsMaintenanceScheduleWindow) effectiveEnd() time.Time {
	if w.EndedAt != nil {
		return *w.EndedAt
	}
	return w.EndsAt
}
func (w WindowsMaintenanceScheduleWindow) Pending(now time.Time) bool {
	return w.CancelledAt == nil && w.EndedAt == nil && now.Before(w.StartsAt)
}
func (w WindowsMaintenanceScheduleWindow) Active(now time.Time) bool {
	return w.CancelledAt == nil && w.EndedAt == nil && !now.Before(w.StartsAt) && now.Before(w.EndsAt)
}

// A definitively unsent transition crossing a used window is consumed even if
// the worker missed the whole window. Cancelled plans suppress nothing.
func (w WindowsMaintenanceScheduleWindow) Suppresses(transition, now time.Time) bool {
	return w.CancelledAt == nil && !now.Before(w.StartsAt) && transition.Before(w.effectiveEnd())
}

type WindowsMaintenanceScheduleState struct {
	Version                int                                `json:"version"`
	Target                 WindowsMaintenanceTarget           `json:"target"`
	RetiredWindows         uint64                             `json:"retiredWindows"`
	RetiredThroughRevision uint64                             `json:"retiredThroughRevision"`
	Revision               uint64                             `json:"revision"`
	ChangedAt              time.Time                          `json:"changedAt"`
	ObservedAt             time.Time                          `json:"observedAt"`
	Windows                []WindowsMaintenanceScheduleWindow `json:"windows"`
}

func (s WindowsMaintenanceScheduleState) valid() bool {
	if s.RetiredWindows > s.RetiredThroughRevision || s.RetiredThroughRevision > 2*s.RetiredWindows || s.RetiredThroughRevision >= s.Revision || s.Version != 1 || !s.Target.Valid() || s.Revision < 1 || s.Revision > MaxWindowsMaintenanceRevision || !validMaintenanceTime(s.ChangedAt) || !validMaintenanceTime(s.ObservedAt) || s.ObservedAt.Before(s.ChangedAt) || len(s.Windows) < 1 || len(s.Windows) > MaxWindowsMaintenanceSchedules {
		return false
	}
	for i, w := range s.Windows {
		if w.ID < 1 || w.ID > s.Revision || !validMaintenanceTime(w.CreatedAt) || !validMaintenanceTime(w.StartsAt) || !validMaintenanceTime(w.EndsAt) || w.StartsAt.Sub(w.CreatedAt) < time.Minute || w.StartsAt.Sub(w.CreatedAt) > 7*24*time.Hour || w.EndsAt.Sub(w.StartsAt) < time.Minute || w.EndsAt.Sub(w.StartsAt) > 24*time.Hour || !ValidWindowsMaintenanceIntent(w.Intent) {
			return false
		}
		changed, rev := w.CreatedAt, w.ID
		if w.CancelledAt != nil {
			if w.EndedAt != nil || !validMaintenanceTime(*w.CancelledAt) || w.CancelledAt.Before(w.CreatedAt) || !w.CancelledAt.Before(w.StartsAt) {
				return false
			}
			changed = *w.CancelledAt
			rev++
		}
		if w.EndedAt != nil {
			if !validMaintenanceTime(*w.EndedAt) || w.EndedAt.Before(w.StartsAt) || !w.EndedAt.Before(w.EndsAt) {
				return false
			}
			changed = *w.EndedAt
			rev++
		}
		if i == 0 {
			if rev != s.Revision || !changed.Equal(s.ChangedAt) {
				return false
			}
		} else {
			newer := s.Windows[i-1]
			if rev+1 != newer.ID || changed.After(newer.CreatedAt) || w.CancelledAt == nil && w.effectiveEnd().After(newer.CreatedAt) {
				return false
			}
		}
	}
	return s.Windows[len(s.Windows)-1].ID == s.RetiredThroughRevision+1
}
func readWindowsMaintenanceSchedules(ctx context.Context, tx *sql.Tx) ([]WindowsMaintenanceScheduleState, error) {
	var mismatch int
	if e := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM windows_maintenance_schedules s LEFT JOIN windows_maintenance_schedule_used u USING(id,domain) WHERE u.id IS NULL)+(SELECT count(*) FROM windows_maintenance_schedule_used u LEFT JOIN windows_maintenance_schedules s USING(id,domain) WHERE s.id IS NULL)`).Scan(&mismatch); e != nil {
		return nil, e
	} else if mismatch != 0 {
		return nil, ErrWindowsMaintenance
	}
	rows, e := tx.QueryContext(ctx, `SELECT id,domain,body FROM windows_maintenance_schedules ORDER BY id,domain LIMIT 151`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []WindowsMaintenanceScheduleState{}
	for rows.Next() {
		var id, domain string
		var raw []byte
		var v WindowsMaintenanceScheduleState
		if e = rows.Scan(&id, &domain, &raw); e != nil {
			return nil, e
		}
		if len(raw) > 8192 || json.Unmarshal(raw, &v) != nil || !v.valid() || v.Target.DeviceID != id || v.Target.Domain != domain {
			return nil, ErrWindowsMaintenance
		}
		canonical, _ := json.Marshal(v)
		if !bytes.Equal(raw, canonical) {
			return nil, ErrWindowsMaintenance
		}
		out = append(out, v)
		if len(out) > MaxWindowsMaintenanceTargets {
			return nil, ErrWindowsMaintenance
		}
	}
	return out, rows.Err()
}
func saveWindowsMaintenanceSchedule(ctx context.Context, tx *sql.Tx, v WindowsMaintenanceScheduleState) error {
	if !v.valid() {
		return ErrWindowsMaintenance
	}
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 8192 {
		return ErrWindowsMaintenance
	}
	if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO windows_maintenance_schedule_used(id,domain) VALUES(?,?)`, v.Target.DeviceID, v.Target.Domain); e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO windows_maintenance_schedules(id,domain,body) VALUES(?,?,?) ON CONFLICT(id,domain) DO UPDATE SET body=excluded.body`, v.Target.DeviceID, v.Target.Domain, raw)
	return e
}
func maintenanceDomainsOverlap(a, b WindowsMaintenanceTarget) bool {
	return a.sameIdentity(b) && (a.Domain == "all" || b.Domain == "all" || a.Domain == b.Domain)
}
func schedulesOverlapImmediate(states []WindowsMaintenanceScheduleState, target WindowsMaintenanceTarget, start, end time.Time) error {
	for _, s := range states {
		if !maintenanceDomainsOverlap(s.Target, target) {
			continue
		}
		if start.Before(s.ObservedAt) {
			return ErrWindowsMaintenanceConflict
		}
		for _, w := range s.Windows {
			if w.Pending(start) || w.Active(start) {
				return ErrWindowsMaintenanceConflict
			}
		}
	}
	return nil
}

// Explicit reads observe a durable clock floor only for already-created plans.
// No read creates a plan, evaluates health or grants a notification recipient.
func (s *Store) WindowsMaintenanceSchedules(ctx context.Context, clock func() time.Time) ([]WindowsMaintenanceScheduleState, error) {
	if clock == nil {
		return nil, ErrWindowsMaintenance
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	states, e := readWindowsMaintenanceSchedules(ctx, tx)
	if e != nil {
		return nil, e
	}
	now := clock().UTC()
	if !validMaintenanceTime(now) {
		return nil, ErrWindowsMaintenanceConflict
	}
	for i := range states {
		if now.Before(states[i].ObservedAt) {
			return nil, ErrWindowsMaintenanceConflict
		}
		states[i].ObservedAt = now
	}
	if e = consumeScheduledWindowsNotifications(ctx, tx, states, now); e != nil {
		return nil, e
	}
	for i := range states {
		pruneWindowsMaintenanceSchedules(&states[i], now)
		if e = saveWindowsMaintenanceSchedule(ctx, tx, states[i]); e != nil {
			return nil, e
		}
	}
	final := clock().UTC()
	if !validMaintenanceTime(final) || final.Before(now) {
		return nil, ErrWindowsMaintenanceConflict
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return states, nil
}

// The caller retains the existing original-identity enrollment lease and active
// shared-administrator session throughout this operator-store transaction.
func (s *Store) ChangeWindowsMaintenanceSchedule(ctx context.Context, target WindowsMaintenanceTarget, expected uint64, action string, windowID uint64, starts, ends time.Time, intent string, clock func() time.Time, guard func(time.Time, time.Time) error) (WindowsMaintenanceScheduleState, error) {
	zero := WindowsMaintenanceScheduleState{}
	if !target.Valid() || expected >= MaxWindowsMaintenanceRevision || clock == nil || guard == nil || action != "schedule" && action != "cancel" && action != "end" {
		return zero, ErrWindowsMaintenance
	}
	plan := action == "schedule"
	if plan && (windowID != 0 || !validMaintenanceTime(starts) || !validMaintenanceTime(ends) || !ValidWindowsMaintenanceIntent(intent)) || !plan && (windowID == 0 || !starts.IsZero() || !ends.IsZero() || intent != "") {
		return zero, ErrWindowsMaintenance
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return zero, e
	}
	defer tx.Rollback()
	now := clock().UTC()
	if !validMaintenanceTime(now) {
		return zero, ErrWindowsMaintenanceConflict
	}
	if e = guard(now, time.Time{}); e != nil {
		return zero, e
	}
	states, e := readWindowsMaintenanceSchedules(ctx, tx)
	if e != nil {
		return zero, e
	}
	immediate, e := readWindowsMaintenance(ctx, tx)
	if e != nil {
		return zero, e
	}
	next := WindowsMaintenanceScheduleState{Version: 1, Target: target, Windows: []WindowsMaintenanceScheduleWindow{}}
	replaces := false
	for _, s := range states {
		if s.Target.DeviceID == target.DeviceID && s.Target.Domain == target.Domain {
			replaces = true
			if s.Target == target {
				next = s
			}
		}
		if s.Target.sameIdentity(target) && now.Before(s.ObservedAt) {
			return zero, ErrWindowsMaintenanceConflict
		}
		if plan && maintenanceDomainsOverlap(s.Target, target) {
			for _, w := range s.Windows {
				if w.Pending(now) || w.Active(now) {
					return zero, ErrWindowsMaintenanceConflict
				}
			}
		}
	}
	series, e := readWindowsMaintenanceSeries(ctx, tx)
	if e != nil {
		return zero, e
	}
	if plan {
		if e = schedulesOverlapImmediate(seriesScheduleAdapter(series), target, now, ends); e != nil {
			return zero, e
		}
	}
	if expected != next.Revision {
		return zero, ErrWindowsMaintenanceConflict
	}
	if !replaces && len(states) >= MaxWindowsMaintenanceTargets {
		return zero, ErrLimit
	}
	for _, st := range immediate {
		if !st.Target.sameIdentity(target) {
			continue
		}
		if now.Before(st.ChangedAt) {
			return zero, ErrWindowsMaintenanceConflict
		}
		if plan && maintenanceDomainsOverlap(st.Target, target) && st.Windows[0].Active(now) {
			return zero, ErrWindowsMaintenanceConflict
		}
	}
	// Retire only after existing queued work is consumed and in-flight retries
	// are fenced. The retained floor makes the resulting shortened ledger exact.
	if e = consumeScheduledWindowsNotifications(ctx, tx, states, now); e != nil {
		return zero, e
	}
	pruneWindowsMaintenanceSchedules(&next, now)
	// Capacity counts exact identities across both independent ledgers, not table rows.
	capacityStates := append([]WindowsMaintenanceScheduleState{}, states...)
	for i := range capacityStates {
		if capacityStates[i].Target.DeviceID == target.DeviceID && capacityStates[i].Target.Domain == target.Domain {
			capacityStates = append(capacityStates[:i], capacityStates[i+1:]...)
			break
		}
	}
	if next.Revision > 0 {
		capacityStates = append(capacityStates, next)
	}
	additional := 0
	if plan {
		additional = 1
	}
	if e = maintenanceSeriesCapacity(capacityStates, series, target, additional); e != nil {
		return zero, e
	}
	deadline := time.Time{}
	if plan {
		if starts.Sub(now) < time.Minute || starts.Sub(now) > 7*24*time.Hour || ends.Sub(starts) < time.Minute || ends.Sub(starts) > 24*time.Hour {
			return zero, ErrWindowsMaintenanceConflict
		}
		if len(next.Windows) >= MaxWindowsMaintenanceSchedules {
			return zero, ErrLimit
		}
		deadline = starts
		next.Windows = append([]WindowsMaintenanceScheduleWindow{{ID: expected + 1, CreatedAt: now, StartsAt: starts, EndsAt: ends, Intent: intent}}, next.Windows...)
	} else {
		if len(next.Windows) == 0 || next.Windows[0].ID != windowID {
			return zero, ErrWindowsMaintenanceConflict
		}
		next.Windows = append([]WindowsMaintenanceScheduleWindow{}, next.Windows...)
		w := &next.Windows[0]
		if action == "cancel" {
			if !w.Pending(now) {
				return zero, ErrWindowsMaintenanceConflict
			}
			w.CancelledAt = &now
			deadline = w.StartsAt
		} else {
			if !w.Active(now) {
				return zero, ErrWindowsMaintenanceConflict
			}
			w.EndedAt = &now
			deadline = w.EndsAt
		}
	}
	next.Revision = expected + 1
	next.ChangedAt = now
	next.ObservedAt = now
	if e = saveWindowsMaintenanceSchedule(ctx, tx, next); e != nil {
		return zero, e
	}
	// An older manager must reject a database containing future suppression rather
	// than silently ignore it. Untouched stores retain their original version.
	var compatibility int
	if e = tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&compatibility); e != nil {
		return zero, e
	}
	if compatibility < 2 {
		if _, e = tx.ExecContext(ctx, `PRAGMA user_version=2`); e != nil {
			return zero, e
		}
	}
	found := false
	for i := range states {
		if states[i].Target.DeviceID == target.DeviceID && states[i].Target.Domain == target.Domain {
			states[i] = next
			found = true
			break
		}
	}
	if !found {
		states = append(states, next)
	}
	if e = consumeScheduledWindowsNotifications(ctx, tx, states, now); e != nil {
		return zero, e
	}
	final := clock().UTC()
	if !validMaintenanceTime(final) || final.Before(now) || plan && starts.Sub(final) < time.Minute || (!deadline.IsZero() && !final.Before(deadline)) {
		return zero, ErrWindowsMaintenanceConflict
	}
	if e = guard(final, deadline); e != nil {
		return zero, e
	}
	afterGuard := clock().UTC()
	if !validMaintenanceTime(afterGuard) || afterGuard.Before(final) || plan && starts.Sub(afterGuard) < time.Minute || (!deadline.IsZero() && !afterGuard.Before(deadline)) {
		return zero, ErrWindowsMaintenanceConflict
	}
	if e = tx.Commit(); e != nil {
		return zero, e
	}
	return next, nil
}

// Source transitions can be queued behind a later read. Their original time is
// still evaluated against retained windows without treating that event as a
// new wall-clock observation or moving its timestamps.
func scheduledWindowsNotificationMuted(ctx context.Context, tx *sql.Tx, target WindowsMaintenanceTarget, transition, now time.Time, observe bool) (bool, error) {
	states, e := readWindowsMaintenanceSchedules(ctx, tx)
	if e != nil {
		return false, e
	}
	series, e := readWindowsMaintenanceSeries(ctx, tx)
	if e != nil {
		return false, e
	}
	for i := range series {
		if !maintenanceDomainsOverlap(series[i].Target, target) {
			continue
		}
		if e = observeWindowsMaintenanceSeries(ctx, tx, series[i:i+1], now, observe); e != nil {
			return false, e
		}
	}
	seriesMuted := false
	for _, state := range series {
		if maintenanceDomainsOverlap(state.Target, target) {
			at := now
			if at.Before(state.ObservedAt) {
				at = state.ObservedAt
			}
			for _, occurrence := range state.Occurrences {
				seriesMuted = seriesMuted || occurrence.Suppresses(transition, at)
			}
		}
	}
	muted := false
	for _, s := range states {
		if !maintenanceDomainsOverlap(s.Target, target) {
			continue
		}
		at := now
		if observe {
			if at.Before(s.ObservedAt) {
				return false, ErrWindowsMaintenanceConflict
			}
			s.ObservedAt = at
			if e = saveWindowsMaintenanceSchedule(ctx, tx, s); e != nil {
				return false, e
			}
		} else {
			// A newly admitted source transition is itself an observed manager
			// time. Retain its floor even without a subsequent UI/worker read;
			// delayed older transitions cannot lower it or fail solely for age.
			if at.Before(s.ObservedAt) {
				at = s.ObservedAt
			} else if at.After(s.ObservedAt) {
				s.ObservedAt = at
				if e = saveWindowsMaintenanceSchedule(ctx, tx, s); e != nil {
					return false, e
				}
			}
		}
		for _, w := range s.Windows {
			muted = muted || w.Suppresses(transition, at)
		}
	}
	return muted || seriesMuted, nil
}

// All queued and in-flight rows are bounded by the existing shared outbox cap.
// Original payload nanoseconds, not the millisecond index, decide early-end edges.
func consumeScheduledWindowsNotifications(ctx context.Context, tx *sql.Tx, states []WindowsMaintenanceScheduleState, now time.Time) error {
	// A unified read/consumption commits both ledgers' observed clock floors.
	// Consuming old work must not permit a later rollback cancellation of the
	// legacy window that already suppressed it through the new-series view.
	for i := range states {
		if now.Before(states[i].ObservedAt) {
			return ErrWindowsMaintenanceConflict
		}
		states[i].ObservedAt = now
		if e := saveWindowsMaintenanceSchedule(ctx, tx, states[i]); e != nil {
			return e
		}
	}
	series, e := readWindowsMaintenanceSeries(ctx, tx)
	if e != nil {
		return e
	}
	if e = observeWindowsMaintenanceSeries(ctx, tx, series, now, true); e != nil {
		return e
	}
	states = append(append([]WindowsMaintenanceScheduleState{}, states...), seriesScheduleAdapter(series)...)
	if len(states) == 0 {
		return nil
	}
	rows, e := tx.QueryContext(ctx, `SELECT id,device,domain,target,body FROM windows_notification_outbox WHERE state IN ('queued','in_flight') LIMIT ?`, alarmdelivery.MaxRecords+1)
	if e != nil {
		return e
	}
	ids := []string{}
	count := 0
	for rows.Next() {
		var id, device, domain string
		var raw, body []byte
		var payload alarmdelivery.Payload
		if e = rows.Scan(&id, &device, &domain, &raw, &body); e != nil {
			rows.Close()
			return e
		}
		count++
		if count > alarmdelivery.MaxRecords || len(body) > alarmdelivery.MaxPayloadBytes || json.Unmarshal(body, &payload) != nil || !validMaintenanceTime(payload.TransitionAt) {
			rows.Close()
			return ErrWindowsNotification
		}
		var target WindowsMaintenanceTarget
		if domain == "service-complete" {
			v, err := decodeWindowsCompleteNotificationEnvelope(raw)
			if err != nil {
				rows.Close()
				return err
			}
			target = completeNotificationMaintenanceTarget(completeNotificationPolicyTarget(v))
		} else {
			var v WindowsIncidentTarget
			if json.Unmarshal(raw, &v) != nil || !v.valid() {
				rows.Close()
				return ErrWindowsNotification
			}
			target = notificationPolicyTarget(v)
		}
		if target.DeviceID != device || payload.EventID != id || payload.DeviceID != device {
			rows.Close()
			return ErrWindowsNotification
		}
		muted := false
		for _, s := range states {
			if maintenanceDomainsOverlap(s.Target, target) {
				for _, w := range s.Windows {
					muted = muted || w.Suppresses(payload.TransitionAt, now)
				}
			}
		}
		if muted {
			ids = append(ids, id)
		}
	}
	e = rows.Err()
	ce := rows.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	for _, id := range ids {
		if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state=CASE WHEN state='queued' THEN 'suppressed' ELSE state END,stop_retry=1,code='maintenance',finished=CASE WHEN state='queued' THEN ? ELSE finished END WHERE id=? AND state IN ('queued','in_flight')`, now.UnixMilli(), id); e != nil {
			return e
		}
	}
	return nil
}

// The notification queue has an immutable 24-hour original-event lifetime.
// Older windows can no longer admit a deliverable transition; queued/in-flight
// effects must be consumed before this function is called. Keep four recent
// records and a durable retired revision/count floor, never reset sequence IDs.
func pruneWindowsMaintenanceSchedules(s *WindowsMaintenanceScheduleState, now time.Time) {
	for len(s.Windows) > 4 {
		last := s.Windows[len(s.Windows)-1]
		end := last.effectiveEnd()
		if last.CancelledAt != nil {
			end = *last.CancelledAt
		}
		if now.Before(end.Add(alarmdelivery.MaxQueueAge)) {
			break
		}
		s.RetiredWindows++
		s.RetiredThroughRevision = last.ID
		if last.CancelledAt != nil || last.EndedAt != nil {
			s.RetiredThroughRevision++
		}
		s.Windows = s.Windows[:len(s.Windows)-1]
	}
}
