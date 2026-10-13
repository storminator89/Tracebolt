package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/alarmdelivery"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsresource"
	"localrmm/internal/windowsservicehealth"
)

type WindowsNotificationCandidate struct {
	ID             string
	Target         WindowsIncidentTarget
	CompleteTarget *WindowsCompleteIncidentTarget
	Subject        string
}

func (s *Store) NextWindowsNotification(ctx context.Context, b alarmdelivery.Binding, now time.Time) (*WindowsNotificationCandidate, error) {
	if !b.Valid() || !validMaintenanceTime(now) {
		return nil, ErrWindowsNotification
	}
	var v WindowsNotificationCandidate
	var raw, body []byte
	var domain string
	e := s.db.QueryRowContext(ctx, `SELECT id,target,domain,body FROM windows_notification_outbox WHERE binding=? AND state='queued' AND due<=? ORDER BY due,created,id LIMIT 1`, b.Key(), now.UnixMilli()).Scan(&v.ID, &raw, &domain, &body)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if domain == "service-complete" {
		envelope, err := decodeWindowsCompleteNotificationEnvelope(raw)
		if err != nil {
			return nil, err
		}
		payload, err := decodeWindowsCompleteNotificationPayload(body, b.Key(), v.ID, envelope)
		if err != nil {
			return nil, err
		}
		v.CompleteTarget = &envelope.Target
		v.Target = envelope.Target.WindowsIncidentTarget
		v.Subject = payload.Target
		return &v, nil
	}
	if json.Unmarshal(raw, &v.Target) != nil || !v.Target.valid() || v.Target.Domain != domain {
		return nil, ErrWindowsNotification
	}
	canonical, _ := json.Marshal(v.Target)
	if !bytes.Equal(raw, canonical) {
		return nil, ErrWindowsNotification
	}
	return &v, nil
}

// Losing identity authority consumes pending work; it never edits source state.
func (s *Store) SuppressWindowsNotification(ctx context.Context, id string, now time.Time) error {
	_, e := s.db.ExecContext(ctx, `UPDATE windows_notification_outbox SET state='suppressed',code='authority_unavailable',finished=? WHERE id=? AND state='queued'`, now.UnixMilli(), id)
	return e
}

func notificationCurrent(ctx context.Context, tx *sql.Tx, t WindowsIncidentTarget, in windowscapacity.Input, now, since time.Time) (*windowsNotificationEpisode, bool, error) {
	var raw []byte
	var episodes []windowsNotificationEpisode
	var evaluated *time.Time
	current := false
	switch t.Domain {
	case "contact":
		e := tx.QueryRowContext(ctx, `SELECT body FROM windows_contact_devices WHERE id=?`, t.DeviceID).Scan(&raw)
		if errors.Is(e, sql.ErrNoRows) {
			return nil, false, nil
		}
		if e != nil {
			return nil, false, e
		}
		s, e := decodeWindowsContact(t.DeviceID, raw)
		if e != nil {
			return nil, false, e
		}
		episodes = contactNotificationEpisodes(s)
		evaluated = s.EvaluatedAt
		current = s.View(in.Input, now, s.Epoch).Status == "overdue"
	case "disk":
		e := tx.QueryRowContext(ctx, `SELECT body FROM windows_capacity_devices WHERE id=?`, t.DeviceID).Scan(&raw)
		if errors.Is(e, sql.ErrNoRows) {
			return nil, false, nil
		}
		if e != nil {
			return nil, false, e
		}
		s, e := decodeWindowsCapacity(t.DeviceID, raw)
		if e != nil {
			return nil, false, e
		}
		episodes = capacityNotificationEpisodes(s, "disk")
		evaluated = s.EvaluatedAt
		current = s.View(in, now, s.Epoch).Status == "pressure"
	case "cpu", "memory":
		e := tx.QueryRowContext(ctx, `SELECT body FROM windows_resource_devices WHERE id=? AND metric=?`, t.DeviceID, t.Domain).Scan(&raw)
		if errors.Is(e, sql.ErrNoRows) {
			return nil, false, nil
		}
		if e != nil {
			return nil, false, e
		}
		s, e := decodeWindowsResource(t.DeviceID, windowsresource.Kind(t.Domain), raw)
		if e != nil {
			return nil, false, e
		}
		episodes = capacityNotificationEpisodes(s.Assessment, t.Domain)
		evaluated = s.Assessment.EvaluatedAt
		v, e := windowsresource.MakeView(s.Assessment, in, s.Metric, now, s.Assessment.Epoch)
		if e != nil {
			return nil, false, e
		}
		current = v.Status == "pressure"
	case "service":
		e := tx.QueryRowContext(ctx, `SELECT body FROM windows_service_devices WHERE id=?`, t.DeviceID).Scan(&raw)
		if errors.Is(e, sql.ErrNoRows) {
			return nil, false, nil
		}
		if e != nil {
			return nil, false, e
		}
		s, e := decodeWindowsService(t.DeviceID, raw)
		if e != nil {
			return nil, false, e
		}
		episodes = serviceNotificationEpisodes(s)
		evaluated = s.EvaluatedAt
		v := s.View(windowsservicehealth.Input{Input: in.Input, Sample: in.Services}, now, s.Epoch)
		for _, episode := range episodes {
			if episode.Target == t {
				for _, check := range v.Checks {
					if check.Name == episode.Subject && check.Status == "attention" {
						current = true
					}
				}
			}
		}
	default:
		return nil, false, ErrWindowsNotification
	}
	if evaluated == nil || evaluated.Before(since) {
		current = false
	}
	for _, v := range episodes {
		if v.Target == t {
			return &v, current, nil
		}
	}
	return nil, false, nil
}

// Enrollment authority is locked by the caller before this operator transaction.
// The final claim is the dispatch boundary: no storage lock spans HTTP I/O.
func (s *Store) ClaimWindowsNotification(ctx context.Context, b alarmdelivery.Binding, c WindowsNotificationCandidate, in windowscapacity.Input, since time.Time, clock func() time.Time, guard func(time.Time) error) (*alarmdelivery.Attempt, error) {
	if !b.Valid() || c.CompleteTarget != nil || !c.Target.valid() || clock == nil || guard == nil || !in.Authorized || c.Target.DeviceID != in.DeviceID || c.Target.InvitationID != in.InvitationID || c.Target.CertificateHash != in.CertificateHash {
		return nil, ErrWindowsNotification
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	now := clock().UTC()
	if !validMaintenanceTime(now) || now.Before(since) {
		return nil, ErrWindowsNotificationConflict
	}
	if e = guard(now); e != nil {
		return nil, e
	}
	var body, raw []byte
	var revision uint64
	var attempts int
	var created, due, last int64
	var active string
	var enabled int
	if e = tx.QueryRowContext(ctx, `SELECT binding,enabled,last_send FROM alarm_settings WHERE id=1`).Scan(&active, &enabled, &last); e != nil {
		return nil, e
	}
	if enabled != 1 || active != b.Key() || last > 0 && now.UnixMilli() < last+alarmdelivery.SendInterval.Milliseconds() {
		return nil, nil
	}
	e = tx.QueryRowContext(ctx, `SELECT target,body,revision,attempts,created,due FROM windows_notification_outbox WHERE id=? AND binding=? AND state='queued'`, c.ID, b.Key()).Scan(&raw, &body, &revision, &attempts, &created, &due)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if due > now.UnixMilli() {
		return nil, nil
	}
	canonical, _ := json.Marshal(c.Target)
	if !bytes.Equal(raw, canonical) {
		return nil, ErrWindowsNotification
	}
	var payload alarmdelivery.Payload
	if json.Unmarshal(body, &payload) != nil || len(body) > alarmdelivery.MaxPayloadBytes {
		return nil, ErrWindowsNotification
	}
	canonical, _ = json.Marshal(payload)
	sum := sha256.Sum256([]byte(b.Key() + "\x00" + c.Target.Key() + "\x00" + payload.Transition))
	if !bytes.Equal(body, canonical) || payload.SchemaVersion != WindowsNotificationSchema || payload.EventID != c.ID || c.ID != hex.EncodeToString(sum[:]) || payload.DeviceID != c.Target.DeviceID || payload.IncidentID != c.Target.IncidentID || payload.Rule != "windows-"+c.Target.Domain || payload.Severity != "warning" || (payload.Transition != "opened" && payload.Transition != "recovered") || !validMaintenanceTime(payload.ObservedAt) || payload.ObservedAt.After(payload.TransitionAt) || payload.TransitionAt.UnixMilli() != created {
		return nil, ErrWindowsNotification
	}
	suppress := ""
	if !now.Before(payload.TransitionAt.Add(alarmdelivery.MaxQueueAge)) {
		suppress = "queue_expired"
	}
	policies, e := readWindowsNotificationPolicies(ctx, tx)
	if e != nil {
		return nil, e
	}
	policyCurrent := false
	target := notificationPolicyTarget(c.Target)
	for _, p := range policies {
		if p.Target == target && p.Enabled && p.Revision == revision && p.Binding == b.Key() && !now.Before(p.ChangedAt) {
			policyCurrent = true
		}
	}
	if !policyCurrent {
		suppress = "source_policy_changed"
	}
	maintenance, e := readWindowsMaintenance(ctx, tx)
	if e != nil {
		return nil, e
	}
	muted, e := notificationMaintenance(maintenance, target, now)
	if e != nil {
		return nil, e
	}
	if muted {
		suppress = "maintenance"
	}
	episode, current, e := notificationCurrent(ctx, tx, c.Target, in, now, since)
	if e != nil {
		return nil, e
	}
	if episode == nil {
		suppress = "episode_unavailable"
	} else {
		if payload.Target != episode.Subject {
			return nil, ErrWindowsNotification
		}
		if payload.Transition == "opened" {
			if payload.State != "open" || payload.Reason != "confirmed_unhealthy" || !payload.TransitionAt.Equal(c.Target.OpenedAt) {
				return nil, ErrWindowsNotification
			}
			if episode.ResolvedAt != nil {
				suppress = "episode_closed"
			}
		}
		if payload.Transition == "recovered" {
			if episode.ResolvedAt == nil || !notificationRecovery(*episode) || payload.State != "recovered" || payload.Reason != episode.Reason || !payload.TransitionAt.Equal(*episode.ResolvedAt) {
				return nil, ErrWindowsNotification
			}
			var opening string
			e = tx.QueryRowContext(ctx, `SELECT state FROM windows_notification_outbox WHERE target_key=? AND binding=? AND revision=? AND transition='opened'`, c.Target.Key(), b.Key(), revision).Scan(&opening)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return nil, e
			}
			if opening == "in_flight" && suppress == "" {
				return nil, nil
			}
			if opening != "provider_accepted" {
				suppress = "opening_not_accepted"
			}
		}
	}
	if suppress != "" {
		if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state='suppressed',code=?,finished=? WHERE id=?`, suppress, now.UnixMilli(), c.ID); e != nil {
			return nil, e
		}
		return nil, tx.Commit()
	}
	if payload.Transition == "opened" {
		// Unknown evidence waits briefly for an actual evaluation, never becomes a
		// recovery. Delaying this one candidate prevents starvation of other devices.
		next := now.Add(30 * time.Second).UnixMilli()
		if current {
			var previous sql.NullInt64
			if e = tx.QueryRowContext(ctx, `SELECT max(last_attempt) FROM windows_notification_outbox WHERE binding=? AND policy_key=? AND transition='opened' AND id<>?`, b.Key(), target.Key(), c.ID).Scan(&previous); e != nil {
				return nil, e
			}
			if previous.Valid && previous.Int64 > 0 && now.UnixMilli() < previous.Int64+alarmdelivery.OpeningCooldown.Milliseconds() {
				next = previous.Int64 + alarmdelivery.OpeningCooldown.Milliseconds()
				current = false
			}
		}
		if !current {
			if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET due=? WHERE id=?`, next, c.ID); e != nil {
				return nil, e
			}
			return nil, tx.Commit()
		}
	}
	final := clock().UTC()
	if !validMaintenanceTime(final) || final.Before(now) || !final.Before(in.AuthorityUntil) || !final.Before(payload.TransitionAt.Add(alarmdelivery.MaxQueueAge)) {
		return nil, ErrWindowsNotificationConflict
	}
	if e = guard(final); e != nil {
		return nil, e
	}
	// Re-evaluate freshness and bounded windows at the final sampled clock.
	muted, e = notificationMaintenance(maintenance, target, final)
	if e != nil || muted {
		if e != nil {
			return nil, e
		}
		return nil, ErrWindowsNotificationConflict
	}
	if payload.Transition == "opened" {
		_, fresh, e := notificationCurrent(ctx, tx, c.Target, in, final, since)
		if e != nil {
			return nil, e
		}
		if !fresh {
			return nil, ErrWindowsNotificationConflict
		}
	}
	if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state='in_flight',attempts=attempts+1,last_attempt=? WHERE id=?`, final.UnixMilli(), c.ID); e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alarm_settings SET last_send=? WHERE id=1`, final.UnixMilli()); e != nil {
		return nil, e
	}
	// SQL writes can consume the remaining source/queue lifetime. The last
	// sampled pre-commit clock must qualify evidence too, not only identity.
	commitAt := clock().UTC()
	if !validMaintenanceTime(commitAt) || commitAt.Before(final) || !commitAt.Before(in.AuthorityUntil) || !commitAt.Before(payload.TransitionAt.Add(alarmdelivery.MaxQueueAge)) {
		return nil, ErrWindowsNotificationConflict
	}
	if e = guard(commitAt); e != nil {
		return nil, e
	}
	if payload.Transition == "opened" {
		_, fresh, err := notificationCurrent(ctx, tx, c.Target, in, commitAt, since)
		if err != nil {
			return nil, err
		}
		if !fresh {
			return nil, ErrWindowsNotificationConflict
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return &alarmdelivery.Attempt{Payload: payload, Number: attempts + 1}, nil
}
func (s *Store) CompleteWindowsNotification(ctx context.Context, b alarmdelivery.Binding, a alarmdelivery.Attempt, result alarmdelivery.Result, now time.Time) error {
	if !b.Valid() || !validMaintenanceTime(now) || (a.Payload.SchemaVersion != WindowsNotificationSchema && a.Payload.SchemaVersion != WindowsCompleteNotificationSchema) || a.Number < 1 || a.Number > alarmdelivery.MaxAttempts {
		return ErrWindowsNotification
	}
	state, code := string(result.Outcome), sanitizeAlarmCode(result.Code)
	due, finished := now.UnixMilli(), now.UnixMilli()
	switch result.Outcome {
	case alarmdelivery.Accepted, alarmdelivery.Failed, alarmdelivery.Uncertain:
	case alarmdelivery.Retryable:
		if a.Number >= alarmdelivery.MaxAttempts || !now.Before(a.Payload.TransitionAt.Add(alarmdelivery.MaxQueueAge)) {
			state, code = "failed", "retry_exhausted"
		} else {
			state = "queued"
			finished = 0
			delays := []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 15 * time.Minute}
			due = now.Add(delays[a.Number-1]).UnixMilli()
		}
	default:
		state, code = "uncertain", "invalid_transport_result"
	}
	// A maintenance/policy change during HTTP preserves accepted/uncertain truth,
	// but permanently consumes a definite retry, even if its window already ended.
	body, e := json.Marshal(a.Payload)
	if e != nil || len(body) > alarmdelivery.MaxPayloadBytes {
		return ErrWindowsNotification
	}
	_, e = s.db.ExecContext(ctx, `UPDATE windows_notification_outbox SET state=CASE WHEN stop_retry=1 AND ?='queued' THEN 'suppressed' ELSE ? END,code=CASE WHEN stop_retry=1 AND ?='queued' THEN code ELSE ? END,due=?,finished=CASE WHEN stop_retry=1 AND ?='queued' THEN ? ELSE ? END WHERE id=? AND binding=? AND state='in_flight' AND attempts=? AND body=?`, state, state, state, code, due, state, now.UnixMilli(), finished, a.Payload.EventID, b.Key(), a.Number, body)
	return e
}

// Unavailable complete evidence is not authority loss or recovery. Delay only
// this queued candidate, preserving its original queue deadline and attempt count.
func (s *Store) DeferWindowsNotification(ctx context.Context, id string, now time.Time) error {
	if !validMaintenanceTime(now) || len(id) != 64 {
		return ErrWindowsNotification
	}
	_, e := s.db.ExecContext(ctx, `UPDATE windows_notification_outbox SET state=CASE WHEN created<=? THEN 'suppressed' ELSE state END,code=CASE WHEN created<=? THEN 'queue_expired' ELSE code END,finished=CASE WHEN created<=? THEN ? ELSE finished END,due=? WHERE id=? AND state='queued' AND created<=?`, now.Add(-alarmdelivery.MaxQueueAge).UnixMilli(), now.Add(-alarmdelivery.MaxQueueAge).UnixMilli(), now.Add(-alarmdelivery.MaxQueueAge).UnixMilli(), now.UnixMilli(), now.Add(30*time.Second).UnixMilli(), id, now.UnixMilli())
	return e
}
