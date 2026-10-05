package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/alarmdelivery"
	"localrmm/internal/health"
	"time"
)

const alarmSchema = `CREATE TABLE IF NOT EXISTS alarm_settings(id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), last_send INTEGER NOT NULL DEFAULT 0, dropped INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO alarm_settings(id,binding,enabled) VALUES(1,'',0);
CREATE TABLE IF NOT EXISTS alarm_outbox(id TEXT PRIMARY KEY, binding TEXT NOT NULL, device TEXT NOT NULL, incident TEXT NOT NULL, rule TEXT NOT NULL, transition TEXT NOT NULL CHECK(transition IN ('opened','recovered')), body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=2048 AND json_valid(body)), state TEXT NOT NULL CHECK(state IN ('queued','in_flight','provider_accepted','failed','uncertain','suppressed')), attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0 AND attempts<=5), created INTEGER NOT NULL, due INTEGER NOT NULL, last_attempt INTEGER NOT NULL DEFAULT 0, finished INTEGER NOT NULL DEFAULT 0, code TEXT NOT NULL DEFAULT '', UNIQUE(binding,device,incident,transition));
CREATE INDEX IF NOT EXISTS alarm_due ON alarm_outbox(state,due);`

// ConfigureAlarms is called once before starting health/worker goroutines. It
// never scans history. No configuration means disabled, including after restart.
// Destination changes suppress old pending records rather than redirecting them.
func (s *Store) ConfigureAlarms(ctx context.Context, b *alarmdelivery.Binding, now time.Time) error {
	if now.IsZero() || b != nil && !b.Valid() {
		return alarmdelivery.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	key := ""
	enabled := 0
	if b != nil {
		key = b.Key()
		enabled = 1
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alarm_outbox SET state='uncertain',code='restart_in_flight',finished=? WHERE state='in_flight'`, now.UnixMilli()); e != nil {
		return e
	}
	code := "destination_changed"
	if b == nil {
		code = "delivery_disabled"
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alarm_outbox SET state='suppressed',code=?,finished=? WHERE state='queued' AND (binding<>? OR ?=0)`, code, now.UnixMilli(), key, enabled); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alarm_settings SET binding=?,enabled=? WHERE id=1`, key, enabled); e != nil {
		return e
	}
	return tx.Commit()
}

func enqueueHealthAlarms(ctx context.Context, tx *sql.Tx, device string, before []health.Incident, state health.State, transitions []health.Incident) error {
	var binding string
	var enabled int
	if e := tx.QueryRowContext(ctx, `SELECT binding,enabled FROM alarm_settings WHERE id=1`).Scan(&binding, &enabled); e != nil {
		return e
	}
	if enabled == 0 {
		return nil
	}
	previous := map[string]health.Incident{}
	for _, x := range before {
		previous[x.ID] = x
	}
	incidents := append([]health.Incident{}, state.Incidents...)
	seen := map[string]bool{}
	for _, x := range incidents {
		seen[x.ID] = true
	}
	for _, x := range transitions {
		if !seen[x.ID] {
			incidents = append(incidents, x)
			seen[x.ID] = true
		}
	}
	protectedIDs := []string{}
	for _, x := range incidents {
		protectedIDs = append(protectedIDs, x.ID)
	}
	protectedJSON, _ := json.Marshal(protectedIDs)
	for _, x := range incidents {
		old, exists := previous[x.ID]
		transition := ""
		at := x.OpenedAt
		if !exists && x.ResolvedAt == nil {
			transition = "opened"
		}
		if exists && old.ResolvedAt == nil && x.ResolvedAt != nil {
			// Close any definitively unsent opening without inventing recovery receipt.
			if _, e := tx.ExecContext(ctx, `UPDATE alarm_outbox SET state='suppressed',code=?,finished=? WHERE binding=? AND device=? AND incident=? AND transition='opened' AND state='queued'`, x.ClosedReason, x.ResolvedAt.UnixMilli(), binding, device, x.ID); e != nil {
				return e
			}
			if x.ClosedReason == "recovered" {
				var opening string
				e := tx.QueryRowContext(ctx, `SELECT state FROM alarm_outbox WHERE binding=? AND device=? AND incident=? AND transition='opened'`, binding, device, x.ID).Scan(&opening)
				if e != nil && !errors.Is(e, sql.ErrNoRows) {
					return e
				}
				if opening == "provider_accepted" || opening == "in_flight" {
					transition = "recovered"
					at = *x.ResolvedAt
				}
			}
		}
		if transition == "" {
			continue
		}
		sum := sha256.Sum256([]byte(binding + "\x00" + device + "\x00" + x.ID + "\x00" + transition))
		id := hex.EncodeToString(sum[:])
		reason, known := "confirmed_unhealthy", "open"
		if transition == "recovered" {
			reason = "confirmed_recovery"
			known = "recovered"
		}
		payload := alarmdelivery.Payload{SchemaVersion: "tracebolt.alarm-event.v1", EventID: id, DeviceID: device, IncidentID: x.ID, Rule: x.Key, Target: x.Target, Severity: "warning", Transition: transition, State: known, Reason: reason, ObservedAt: x.LastObservedAt, TransitionAt: at}
		body, e := json.Marshal(payload)
		if e != nil || len(body) > alarmdelivery.MaxPayloadBytes {
			return alarmdelivery.ErrInvalid
		}
		// Retain accepted openings for the full lifetime of their health history,
		// including a long-lived incident’s newly created recovery intent.
		// Health transitions cannot be replayed by re-reading, even after pruning.
		if _, e = tx.ExecContext(ctx, `DELETE FROM alarm_outbox WHERE state NOT IN ('queued','in_flight') AND created<? AND NOT (transition='opened' AND state='provider_accepted' AND ((device=? AND incident IN (SELECT value FROM json_each(?))) OR EXISTS (SELECT 1 FROM alarm_outbox r WHERE r.binding=alarm_outbox.binding AND r.device=alarm_outbox.device AND r.incident=alarm_outbox.incident AND r.transition='recovered' AND r.state IN ('queued','in_flight')) OR EXISTS (SELECT 1 FROM health_devices h,json_each(h.body,'$.incidents') j WHERE h.id=alarm_outbox.device AND json_extract(j.value,'$.id')=alarm_outbox.incident)))`, at.Add(-health.Retention).UnixMilli(), device, string(protectedJSON)); e != nil {
			return e
		}
		var total, pending int
		if e = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(state IN ('queued','in_flight')),0) FROM alarm_outbox`).Scan(&total, &pending); e != nil {
			return e
		}
		if total >= alarmdelivery.MaxRecords || pending >= alarmdelivery.MaxPending {
			// Queue overload must not freeze health evaluation. Persist a visible gap
			// counter in the same transaction; this is not a successful delivery intent.
			if _, e = tx.ExecContext(ctx, `UPDATE alarm_settings SET dropped=dropped+1 WHERE id=1`); e != nil {
				return e
			}
			continue
		}
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO alarm_outbox(id,binding,device,incident,rule,transition,body,state,created,due) VALUES(?,?,?,?,?,?,?,'queued',?,?)`, id, binding, device, x.ID, x.Key, transition, body, at.UnixMilli(), at.UnixMilli()); e != nil {
			return e
		}
	}
	return nil
}

type alarmRow struct {
	id, binding, device, incident, rule, transition, state string
	body                                                   []byte
	attempts                                               int
	created, due, last                                     int64
}

func (s *Store) ClaimAlarm(ctx context.Context, b alarmdelivery.Binding, now time.Time) (*alarmdelivery.Attempt, error) {
	if !b.Valid() || now.IsZero() {
		return nil, alarmdelivery.ErrInvalid
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	key := b.Key()
	var active string
	var enabled int
	var last int64
	if e = tx.QueryRowContext(ctx, `SELECT binding,enabled,last_send FROM alarm_settings WHERE id=1`).Scan(&active, &enabled, &last); e != nil {
		return nil, e
	}
	if enabled == 0 || active != key {
		return nil, nil
	}
	ms := now.UnixMilli()
	if _, e = tx.ExecContext(ctx, `UPDATE alarm_outbox SET state='failed',code='queue_expired',finished=? WHERE state='queued' AND created<=?`, ms, now.Add(-alarmdelivery.MaxQueueAge).UnixMilli()); e != nil {
		return nil, e
	}
	if last != 0 && ms < last+alarmdelivery.SendInterval.Milliseconds() {
		return nil, tx.Commit()
	}
	rows, e := tx.QueryContext(ctx, `SELECT id,binding,device,incident,rule,transition,body,state,attempts,created,due,last_attempt FROM alarm_outbox WHERE binding=? AND state='queued' AND due<=? ORDER BY due,created,id LIMIT 500`, key, ms)
	if e != nil {
		return nil, e
	}
	candidates := []alarmRow{}
	for rows.Next() {
		var r alarmRow
		if e = rows.Scan(&r.id, &r.binding, &r.device, &r.incident, &r.rule, &r.transition, &r.body, &r.state, &r.attempts, &r.created, &r.due, &r.last); e != nil {
			rows.Close()
			return nil, e
		}
		candidates = append(candidates, r)
	}
	e = rows.Err()
	closeErr := rows.Close()
	if e != nil {
		return nil, e
	}
	if closeErr != nil {
		return nil, closeErr
	}
	for _, r := range candidates {
		var raw []byte
		if e = tx.QueryRowContext(ctx, `SELECT body FROM health_devices WHERE id=?`, r.device).Scan(&raw); e != nil {
			return nil, e
		}
		hs, e := decodeHealth(raw)
		if e != nil {
			return nil, e
		}
		var incident *health.Incident
		for i := range hs.Incidents {
			if hs.Incidents[i].ID == r.incident {
				incident = &hs.Incidents[i]
				break
			}
		}
		suppress := ""
		if r.transition == "opened" {
			if incident == nil || incident.ResolvedAt != nil {
				suppress = "no_longer_open"
			} else if hs.MaintenanceUntil != nil && now.Before(*hs.MaintenanceUntil) {
				suppress = "maintenance"
			}
			if suppress == "" {
				// Stale/unauthorized inputs become unknown, never a healthy recovery.
				current := false
				for _, c := range hs.View(r.device, now).Checks {
					if c.Key == incident.Key && c.State == "open" {
						current = true
					}
				}
				if !current {
					continue
				}
				var previous sql.NullInt64
				if e = tx.QueryRowContext(ctx, `SELECT max(last_attempt) FROM alarm_outbox WHERE binding=? AND device=? AND rule=? AND transition='opened' AND id<>? AND last_attempt>0`, key, r.device, r.rule, r.id).Scan(&previous); e != nil {
					return nil, e
				}
				if previous.Valid && ms < previous.Int64+alarmdelivery.OpeningCooldown.Milliseconds() {
					if _, e = tx.ExecContext(ctx, `UPDATE alarm_outbox SET due=? WHERE id=?`, previous.Int64+alarmdelivery.OpeningCooldown.Milliseconds(), r.id); e != nil {
						return nil, e
					}
					continue
				}
			}
		} else {
			var opening string
			e = tx.QueryRowContext(ctx, `SELECT state FROM alarm_outbox WHERE binding=? AND device=? AND incident=? AND transition='opened'`, key, r.device, r.incident).Scan(&opening)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return nil, e
			}
			if opening == "in_flight" {
				continue
			}
			if opening != "provider_accepted" {
				suppress = "opening_not_accepted"
			}
		}
		if suppress != "" {
			if _, e = tx.ExecContext(ctx, `UPDATE alarm_outbox SET state='suppressed',code=?,finished=? WHERE id=?`, suppress, ms, r.id); e != nil {
				return nil, e
			}
			continue
		}
		var p alarmdelivery.Payload
		if json.Unmarshal(r.body, &p) != nil || p.EventID != r.id || len(r.body) > alarmdelivery.MaxPayloadBytes {
			return nil, alarmdelivery.ErrInvalid
		}
		if _, e = tx.ExecContext(ctx, `UPDATE alarm_outbox SET state='in_flight',attempts=attempts+1,last_attempt=? WHERE id=?`, ms, r.id); e != nil {
			return nil, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE alarm_settings SET last_send=? WHERE id=1`, ms); e != nil {
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
		return &alarmdelivery.Attempt{Payload: p, Number: r.attempts + 1}, nil
	}
	return nil, tx.Commit()
}

// CompleteAlarm uses both immutable event identity and attempt number. A stale
// completion cannot overwrite an uncertain restart or a later attempt.
func (s *Store) CompleteAlarm(ctx context.Context, b alarmdelivery.Binding, a alarmdelivery.Attempt, result alarmdelivery.Result, now time.Time) error {
	if !b.Valid() || now.IsZero() || a.Number < 1 || a.Number > alarmdelivery.MaxAttempts {
		return alarmdelivery.ErrInvalid
	}
	outcome := result.Outcome
	code := sanitizeAlarmCode(result.Code)
	switch outcome {
	case alarmdelivery.Accepted, alarmdelivery.Retryable, alarmdelivery.Failed, alarmdelivery.Uncertain:
	default:
		outcome = alarmdelivery.Uncertain
		code = "invalid_transport_result"
	}
	state := string(outcome)
	due := now.UnixMilli()
	finished := now.UnixMilli()
	if outcome == alarmdelivery.Retryable {
		if a.Number >= alarmdelivery.MaxAttempts || !now.Before(a.Payload.TransitionAt.Add(alarmdelivery.MaxQueueAge)) {
			state = "failed"
			code = "retry_exhausted"
		} else {
			state = "queued"
			finished = 0
			delays := []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 15 * time.Minute}
			due = now.Add(delays[a.Number-1]).UnixMilli()
		}
	}
	_, e := s.db.ExecContext(ctx, `UPDATE alarm_outbox SET state=?,code=?,due=?,finished=? WHERE id=? AND binding=? AND state='in_flight' AND attempts=?`, state, code, due, finished, a.Payload.EventID, b.Key(), a.Number)
	return e
}
func sanitizeAlarmCode(code string) string {
	// Never persist provider bodies, endpoint strings, wrapped errors or secrets.
	switch code {
	case "disabled", "request_cancelled", "invalid_payload", "invalid_destination", "dns_failed", "destination_blocked", "connection_failed", "request_uncertain", "provider_accepted", "provider_rate_limited", "provider_uncertain", "redirect_blocked", "provider_rejected":
		return code
	default:
		return "transport_result"
	}
}

type AlarmStatus struct {
	SchemaVersion    string `json:"schemaVersion"`
	Enabled          bool   `json:"enabled"`
	Queued           int    `json:"queued"`
	InFlight         int    `json:"inFlight"`
	ProviderAccepted int    `json:"providerAccepted"`
	Failed           int    `json:"failed"`
	Uncertain        int    `json:"uncertain"`
	Suppressed       int    `json:"suppressed"`
	Dropped          int64  `json:"dropped"`
}

func (s *Store) AlarmStatus(ctx context.Context) (AlarmStatus, error) {
	out := AlarmStatus{SchemaVersion: "tracebolt.alarm-status.v1"}
	var enabled int
	e := s.db.QueryRowContext(ctx, `SELECT enabled,dropped,(SELECT count(*) FROM alarm_outbox WHERE state='queued'),(SELECT count(*) FROM alarm_outbox WHERE state='in_flight'),(SELECT count(*) FROM alarm_outbox WHERE state='provider_accepted'),(SELECT count(*) FROM alarm_outbox WHERE state='failed'),(SELECT count(*) FROM alarm_outbox WHERE state='uncertain'),(SELECT count(*) FROM alarm_outbox WHERE state='suppressed') FROM alarm_settings WHERE id=1`).Scan(&enabled, &out.Dropped, &out.Queued, &out.InFlight, &out.ProviderAccepted, &out.Failed, &out.Uncertain, &out.Suppressed)
	out.Enabled = enabled == 1
	return out, e
}
