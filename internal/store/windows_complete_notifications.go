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
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
)

const WindowsCompleteNotificationSchema = "tracebolt.windows-alarm-event.v2"
const MaxWindowsCompleteNotificationPolicies = 25
const windowsCompleteNotificationSchema = `CREATE TABLE IF NOT EXISTS windows_complete_notification_policies(id TEXT PRIMARY KEY,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=1024 AND json_valid(body)))`

// The target pins the explicitly approved health policy and original local grant.
// IdentityKey deliberately omits these mutable approvals: replacing them uses the
// retained notification revision, never another retained identity slot.
type WindowsCompleteNotificationTarget struct {
	WindowsMaintenanceTarget
	Source               windowsservicehealth.SourceBinding `json:"source"`
	HealthPolicyRevision uint64                             `json:"healthPolicyRevision"`
}

func (v WindowsCompleteNotificationTarget) Valid() bool {
	identity := v.WindowsMaintenanceTarget
	identity.Domain = "service"
	return v.Domain == "service-complete" && identity.Valid() && v.Source.Kind == windowsservicehealth.CompleteSourceKind && windowsfullservices.ValidHex(v.Source.GrantID, 32) && windowsfullservices.ValidSequence(v.Source.GrantRevision) && v.HealthPolicyRevision > 0 && v.HealthPolicyRevision <= windowsservicehealth.MaxCounter
}
func (v WindowsCompleteNotificationTarget) Key() string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(append([]byte("tracebolt.windows-notification-target.v2\x00"), raw...))
	return hex.EncodeToString(sum[:])
}
func (v WindowsCompleteNotificationTarget) IdentityKey() string {
	raw, _ := json.Marshal(v.WindowsMaintenanceTarget)
	sum := sha256.Sum256(append([]byte("tracebolt.windows-notification-identity.v2\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

type WindowsCompleteNotificationPolicy struct {
	Version   int                               `json:"version"`
	Target    WindowsCompleteNotificationTarget `json:"target"`
	Revision  uint64                            `json:"revision"`
	Enabled   bool                              `json:"enabled"`
	Binding   string                            `json:"binding"`
	ChangedAt time.Time                         `json:"changedAt"`
}

func (v WindowsCompleteNotificationPolicy) valid() bool {
	return v.Version == 2 && v.Target.Valid() && v.Revision > 0 && v.Revision <= MaxWindowsMaintenanceRevision && enrollmentcrypto.ValidHash(v.Binding) && validMaintenanceTime(v.ChangedAt)
}
func readWindowsCompleteNotificationPolicies(ctx context.Context, tx *sql.Tx) ([]WindowsCompleteNotificationPolicy, error) {
	rows, e := tx.QueryContext(ctx, `SELECT id,body FROM windows_complete_notification_policies ORDER BY id LIMIT 26`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []WindowsCompleteNotificationPolicy{}
	for rows.Next() {
		var id string
		var raw []byte
		var p WindowsCompleteNotificationPolicy
		if e = rows.Scan(&id, &raw); e != nil {
			return nil, e
		}
		if len(raw) == 0 || len(raw) > 1024 || json.Unmarshal(raw, &p) != nil || !p.valid() || p.Target.IdentityKey() != id {
			return nil, ErrWindowsNotification
		}
		canonical, _ := json.Marshal(p)
		if !bytes.Equal(raw, canonical) {
			return nil, ErrWindowsNotification
		}
		out = append(out, p)
		if len(out) > MaxWindowsCompleteNotificationPolicies {
			return nil, ErrWindowsNotification
		}
	}
	return out, rows.Err()
}

func completeNotificationHealth(ctx context.Context, tx *sql.Tx, target WindowsCompleteNotificationTarget) (windowsservicehealth.State, error) {
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT body FROM windows_service_devices WHERE id=?`, target.DeviceID).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return windowsservicehealth.State{}, ErrWindowsNotificationConflict
	}
	if e != nil {
		return windowsservicehealth.State{}, e
	}
	state, e := decodeWindowsService(target.DeviceID, raw)
	if e != nil {
		return state, e
	}
	if state.SchemaVersion != windowsservicehealth.CompleteStateSchema || state.DeviceID != target.DeviceID || state.InvitationID != target.InvitationID || state.CertificateHash != target.CertificateHash || !state.Policy.Enabled || state.Policy.Revision != target.HealthPolicyRevision || state.Policy.Source == nil || *state.Policy.Source != target.Source {
		return state, ErrWindowsNotificationConflict
	}
	return state, nil
}
func completeNotificationInput(target WindowsCompleteNotificationTarget, in windowsservicehealth.Input, at time.Time) bool {
	if !in.Complete || !in.Authorized || in.DeviceID != target.DeviceID || in.InvitationID != target.InvitationID || in.CertificateHash != target.CertificateHash || !validMaintenanceTime(at) || !at.Before(in.AuthorityUntil) {
		return false
	}
	inv := in.Inventory(at)
	return inv != nil && inv.Source != nil && inv.Source.Binding() == target.Source && in.Selection != nil && *in.Selection == *inv.Source
}

// The caller holds the exact enrollment/current-leaf/complete-source lease.
// Approval writes never evaluate or backfill an episode. Disable needs only the
// exact retained approval and live identity, not a currently available generation.
func (s *Store) ChangeWindowsCompleteNotificationPolicy(ctx context.Context, target WindowsCompleteNotificationTarget, revision uint64, enabled bool, binding string, in windowsservicehealth.Input, clock func() time.Time, guard func(time.Time) error) (WindowsCompleteNotificationPolicy, error) {
	var next WindowsCompleteNotificationPolicy
	if !target.Valid() || revision >= MaxWindowsMaintenanceRevision || clock == nil || guard == nil || enabled && !enrollmentcrypto.ValidHash(binding) {
		return next, ErrWindowsNotification
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return next, e
	}
	defer tx.Rollback()
	now := clock().UTC()
	if !validMaintenanceTime(now) {
		return next, ErrWindowsNotificationConflict
	}
	if e = guard(now); e != nil {
		return next, e
	}
	policies, e := readWindowsCompleteNotificationPolicies(ctx, tx)
	if e != nil {
		return next, e
	}
	for _, p := range policies {
		if p.Target.IdentityKey() == target.IdentityKey() {
			next = p
		}
	}
	if next.Revision != revision || next.Revision > 0 && now.Before(next.ChangedAt) {
		return next, ErrWindowsNotificationConflict
	}
	if next.Revision == 0 && len(policies) >= MaxWindowsCompleteNotificationPolicies {
		return next, ErrLimit
	}
	if enabled {
		if !completeNotificationInput(target, in, now) {
			return next, ErrWindowsNotificationConflict
		}
		if _, e = completeNotificationHealth(ctx, tx, target); e != nil {
			return next, e
		}
		var active string
		var on int
		if e = tx.QueryRowContext(ctx, `SELECT binding,enabled FROM alarm_settings WHERE id=1`).Scan(&active, &on); e != nil {
			return next, e
		}
		if on != 1 || active != binding {
			return next, ErrWindowsNotificationConflict
		}
	} else {
		if next.Revision == 0 || !next.Enabled || next.Target != target || binding != "" {
			return next, ErrWindowsNotificationConflict
		}
		binding = next.Binding
	}
	next = WindowsCompleteNotificationPolicy{Version: 2, Target: target, Revision: revision + 1, Enabled: enabled, Binding: binding, ChangedAt: now}
	raw, _ := json.Marshal(next)
	if len(raw) > 1024 {
		return next, ErrWindowsNotification
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO windows_complete_notification_policies(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body`, target.IdentityKey(), raw); e != nil {
		return next, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state=CASE WHEN state='queued' THEN 'suppressed' ELSE state END,stop_retry=1,code='source_policy_changed',finished=CASE WHEN state='queued' THEN ? ELSE finished END WHERE device=? AND domain='service-complete' AND json_extract(target,'$.target.invitationId')=? AND json_extract(target,'$.target.certificateHash')=? AND state IN ('queued','in_flight')`, now.UnixMilli(), target.DeviceID, target.InvitationID, target.CertificateHash); e != nil {
		return next, e
	}
	final := clock().UTC()
	if !validMaintenanceTime(final) || final.Before(now) {
		return next, ErrWindowsNotificationConflict
	}
	if e = guard(final); e != nil {
		return next, e
	}
	commitAt := clock().UTC()
	if !validMaintenanceTime(commitAt) || commitAt.Before(final) || enabled && !completeNotificationInput(target, in, commitAt) {
		return next, ErrWindowsNotificationConflict
	}
	if enabled {
		if _, e = completeNotificationHealth(ctx, tx, target); e != nil {
			return next, e
		}
	}
	return next, tx.Commit()
}

// The v2 envelope is tagged separately from the exact legacy target bytes. Its
// opening health revision is durable even after health configuration changes.
type windowsCompleteNotificationEnvelope struct {
	Version              int                           `json:"version"`
	Target               WindowsCompleteIncidentTarget `json:"target"`
	HealthPolicyRevision uint64                        `json:"healthPolicyRevision"`
}

func decodeWindowsCompleteNotificationEnvelope(raw []byte) (windowsCompleteNotificationEnvelope, error) {
	var v windowsCompleteNotificationEnvelope
	if len(raw) == 0 || len(raw) > 1024 || json.Unmarshal(raw, &v) != nil || v.Version != 2 || !v.Target.valid() || v.HealthPolicyRevision == 0 || v.HealthPolicyRevision > windowsservicehealth.MaxCounter {
		return v, ErrWindowsNotification
	}
	canonical, _ := json.Marshal(v)
	if !bytes.Equal(raw, canonical) {
		return v, ErrWindowsNotification
	}
	return v, nil
}
func completeNotificationPolicyTarget(v windowsCompleteNotificationEnvelope) WindowsCompleteNotificationTarget {
	return WindowsCompleteNotificationTarget{WindowsMaintenanceTarget: WindowsMaintenanceTarget{DeviceID: v.Target.DeviceID, InvitationID: v.Target.InvitationID, CertificateHash: v.Target.CertificateHash, Domain: "service-complete"}, Source: v.Target.Source, HealthPolicyRevision: v.HealthPolicyRevision}
}
func completeNotificationMaintenanceTarget(v WindowsCompleteNotificationTarget) WindowsMaintenanceTarget {
	target := v.WindowsMaintenanceTarget
	target.Domain = "service"
	return target
}

type windowsCompleteNotificationEpisode struct {
	Envelope windowsCompleteNotificationEnvelope
	Incident windowsservicehealth.Incident
}

func completeServiceNotificationEpisodes(state windowsservicehealth.State) []windowsCompleteNotificationEpisode {
	out := []windowsCompleteNotificationEpisode{}
	if state.SchemaVersion != windowsservicehealth.CompleteStateSchema {
		return out
	}
	for _, i := range state.Incidents {
		if i.OpeningObservation.Source == nil {
			continue
		}
		target := WindowsCompleteIncidentTarget{WindowsIncidentTarget: WindowsIncidentTarget{DeviceID: state.DeviceID, InvitationID: state.InvitationID, CertificateHash: state.CertificateHash, Domain: "service-complete", IncidentID: i.ID, OpenedAt: i.OpenedAt}, Source: i.OpeningObservation.Source.Binding()}
		out = append(out, windowsCompleteNotificationEpisode{windowsCompleteNotificationEnvelope{2, target, i.PolicyRevision}, i})
	}
	return out
}
func enqueueWindowsCompleteNotifications(ctx context.Context, tx *sql.Tx, before, after []windowsCompleteNotificationEpisode) error {
	if len(after) == 0 {
		return nil
	}
	policies, e := readWindowsCompleteNotificationPolicies(ctx, tx)
	if e != nil {
		return e
	}
	var binding string
	var enabled int
	if e = tx.QueryRowContext(ctx, `SELECT binding,enabled FROM alarm_settings WHERE id=1`).Scan(&binding, &enabled); e != nil {
		return e
	}
	previous := map[string]windowsCompleteNotificationEpisode{}
	for _, v := range before {
		previous[v.Envelope.Target.Key()] = v
	}
	// Consume closed openings even if their notification approval or health policy
	// has become unavailable. This can never create an unpaired recovery.
	for _, v := range after {
		old, exists := previous[v.Envelope.Target.Key()]
		if exists && old.Incident.ResolvedAt == nil && v.Incident.ResolvedAt != nil {
			if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state=CASE WHEN state='queued' THEN 'suppressed' ELSE state END,stop_retry=1,finished=CASE WHEN state='queued' THEN ? ELSE finished END,code='episode_closed' WHERE target_key=? AND transition='opened' AND state IN ('queued','in_flight')`, v.Incident.ResolvedAt.UnixMilli(), v.Envelope.Target.Key()); e != nil {
				return e
			}
		}
	}
	if enabled != 1 {
		return nil
	}
	byKey := map[string]WindowsCompleteNotificationPolicy{}
	for _, p := range policies {
		if p.Enabled && p.Binding == binding {
			byKey[p.Target.Key()] = p
		}
	}
	if len(byKey) == 0 {
		return nil
	}
	maintenance, e := readWindowsMaintenance(ctx, tx)
	if e != nil {
		return e
	}
	for _, v := range after {
		target := completeNotificationPolicyTarget(v.Envelope)
		p, ok := byKey[target.Key()]
		if !ok || p.Target != target {
			continue
		}
		old, exists := previous[v.Envelope.Target.Key()]
		transition := ""
		at := v.Incident.OpenedAt
		observed := v.Incident.OpeningObservation.CollectedAt
		if !exists && v.Incident.ResolvedAt == nil && !at.Before(p.ChangedAt) {
			transition = "opened"
		}
		if exists && old.Incident.ResolvedAt == nil && v.Incident.ResolvedAt != nil && v.Incident.ClosedReason == "running" && v.Incident.RecoveryObservation != nil && v.Incident.RecoveryObservation.Source != nil && v.Incident.RecoveryObservation.Source.Binding() == target.Source {
			var state string
			e = tx.QueryRowContext(ctx, `SELECT state FROM windows_notification_outbox WHERE target_key=? AND binding=? AND policy_key=? AND revision=? AND transition='opened'`, v.Envelope.Target.Key(), binding, target.Key(), p.Revision).Scan(&state)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if state == "provider_accepted" || state == "in_flight" {
				transition = "recovered"
				at = *v.Incident.ResolvedAt
				observed = v.Incident.RecoveryObservation.CollectedAt
			}
		}
		if transition == "" {
			continue
		}
		suppressed, e := notificationMaintenance(maintenance, completeNotificationMaintenanceTarget(target), at)
		if e != nil {
			return e
		}
		sum := sha256.Sum256([]byte(binding + "\x00" + v.Envelope.Target.Key() + "\x00" + transition))
		id := hex.EncodeToString(sum[:])
		reason, state := "confirmed_unhealthy", "open"
		if transition == "recovered" {
			reason, state = "running", "recovered"
		}
		payload := alarmdelivery.Payload{SchemaVersion: WindowsCompleteNotificationSchema, EventID: id, DeviceID: target.DeviceID, IncidentID: v.Envelope.Target.IncidentID, Rule: "windows-service-complete", Target: v.Incident.Name, Severity: "warning", Transition: transition, State: state, Reason: reason, ObservedAt: observed, TransitionAt: at}
		body, _ := json.Marshal(payload)
		raw, _ := json.Marshal(v.Envelope)
		if len(raw) > 1024 || !v.Envelope.Target.valid() {
			return ErrWindowsNotification
		}
		if len(body) > alarmdelivery.MaxPayloadBytes {
			if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_counters SET dropped=dropped+1 WHERE id=1`); e != nil {
				return e
			}
			continue
		}
		if e = pruneWindowsNotifications(ctx, tx, at); e != nil {
			return e
		}
		var count, pending int
		if e = tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(state IN ('queued','in_flight')),0) FROM windows_notification_outbox`).Scan(&count, &pending); e != nil {
			return e
		}
		if count >= alarmdelivery.MaxRecords || !suppressed && pending >= alarmdelivery.MaxPending {
			if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_counters SET dropped=dropped+1 WHERE id=1`); e != nil {
				return e
			}
			continue
		}
		queueState, code, finished := "queued", "", int64(0)
		if suppressed {
			queueState, code, finished = "suppressed", "maintenance", at.UnixMilli()
		}
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO windows_notification_outbox(id,binding,target_key,policy_key,revision,device,domain,target,body,transition,state,created,due,code,finished) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, binding, v.Envelope.Target.Key(), target.Key(), p.Revision, target.DeviceID, "service-complete", raw, body, transition, queueState, at.UnixMilli(), at.UnixMilli(), code, finished); e != nil {
			return e
		}
	}
	return nil
}

func decodeWindowsCompleteNotificationPayload(body []byte, binding, id string, envelope windowsCompleteNotificationEnvelope) (alarmdelivery.Payload, error) {
	var p alarmdelivery.Payload
	if len(body) == 0 || len(body) > alarmdelivery.MaxPayloadBytes || json.Unmarshal(body, &p) != nil {
		return p, ErrWindowsNotification
	}
	canonical, _ := json.Marshal(p)
	sum := sha256.Sum256([]byte(binding + "\x00" + envelope.Target.Key() + "\x00" + p.Transition))
	_, nameError := windowsservicehealth.CompleteServices([]string{p.Target})
	if !bytes.Equal(body, canonical) || p.SchemaVersion != WindowsCompleteNotificationSchema || p.EventID != id || id != hex.EncodeToString(sum[:]) || p.DeviceID != envelope.Target.DeviceID || p.IncidentID != envelope.Target.IncidentID || p.Rule != "windows-service-complete" || p.Severity != "warning" || nameError != nil || !validMaintenanceTime(p.ObservedAt) || !validMaintenanceTime(p.TransitionAt) || p.ObservedAt.After(p.TransitionAt) {
		return p, ErrWindowsNotification
	}
	if p.Transition == "opened" {
		if p.State != "open" || p.Reason != "confirmed_unhealthy" || !p.TransitionAt.Equal(envelope.Target.OpenedAt) {
			return p, ErrWindowsNotification
		}
	} else if p.Transition == "recovered" {
		if p.State != "recovered" || p.Reason != "running" || p.TransitionAt.Before(envelope.Target.OpenedAt) {
			return p, ErrWindowsNotification
		}
	} else {
		return p, ErrWindowsNotification
	}
	return p, nil
}
func completeNotificationCurrent(ctx context.Context, tx *sql.Tx, envelope windowsCompleteNotificationEnvelope, in windowsservicehealth.Input, at, since time.Time) (*windowsCompleteNotificationEpisode, bool, error) {
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT body FROM windows_service_devices WHERE id=?`, envelope.Target.DeviceID).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, false, nil
	}
	if e != nil {
		return nil, false, e
	}
	state, e := decodeWindowsService(envelope.Target.DeviceID, raw)
	if e != nil {
		return nil, false, e
	}
	var episode *windowsCompleteNotificationEpisode
	for _, v := range completeServiceNotificationEpisodes(state) {
		if v.Envelope == envelope {
			copy := v
			episode = &copy
			break
		}
	}
	if episode == nil {
		return nil, false, nil
	}
	target := completeNotificationPolicyTarget(envelope)
	if state.Policy.Revision != target.HealthPolicyRevision || !state.Policy.Enabled || state.Policy.Source == nil || *state.Policy.Source != target.Source || !completeNotificationInput(target, in, at) || state.EvaluatedAt == nil || state.EvaluatedAt.Before(since) {
		return episode, false, nil
	}
	view := state.View(in, at, state.Epoch)
	status := "attention"
	if episode.Incident.ResolvedAt != nil {
		status = "running"
	}
	for _, check := range view.Checks {
		if check.Name == episode.Incident.Name && check.Status == status && check.Observation != nil {
			return episode, true, nil
		}
	}
	return episode, false, nil
}

// Claim is the only complete-source dispatch admission. Its caller freezes the
// exact active enrollment leaf and selected complete generation before SQLite.
// Source, policy, opening and final clock are rechecked after SQL writes; no lock
// survives commit or spans transport. Unknown current evidence cannot recover.
func (s *Store) ClaimWindowsCompleteNotification(ctx context.Context, b alarmdelivery.Binding, c WindowsNotificationCandidate, in windowsservicehealth.Input, since time.Time, clock func() time.Time, guard func(time.Time) error) (*alarmdelivery.Attempt, error) {
	if !b.Valid() || c.CompleteTarget == nil || !c.CompleteTarget.valid() || c.Target != c.CompleteTarget.WindowsIncidentTarget || clock == nil || guard == nil || !in.Complete || !in.Authorized || in.DeviceID != c.Target.DeviceID || in.InvitationID != c.Target.InvitationID || in.CertificateHash != c.Target.CertificateHash {
		return nil, ErrWindowsNotification
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	now := clock().UTC()
	if !validMaintenanceTime(now) || !validMaintenanceTime(since) || now.Before(since) {
		return nil, ErrWindowsNotificationConflict
	}
	if e = guard(now); e != nil {
		return nil, e
	}
	var raw, body []byte
	var revision uint64
	var attempts int
	var created, due, last int64
	var active, targetKey, policyKey, device, domain, transition string
	var enabled int
	if e = tx.QueryRowContext(ctx, `SELECT binding,enabled,last_send FROM alarm_settings WHERE id=1`).Scan(&active, &enabled, &last); e != nil {
		return nil, e
	}
	if enabled != 1 || active != b.Key() || last > 0 && now.UnixMilli() < last+alarmdelivery.SendInterval.Milliseconds() {
		return nil, nil
	}
	e = tx.QueryRowContext(ctx, `SELECT target,body,revision,attempts,created,due,target_key,policy_key,device,domain,transition FROM windows_notification_outbox WHERE id=? AND binding=? AND state='queued'`, c.ID, b.Key()).Scan(&raw, &body, &revision, &attempts, &created, &due, &targetKey, &policyKey, &device, &domain, &transition)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if due > now.UnixMilli() {
		return nil, nil
	}
	envelope, e := decodeWindowsCompleteNotificationEnvelope(raw)
	if e != nil {
		return nil, e
	}
	target := completeNotificationPolicyTarget(envelope)
	if envelope.Target != *c.CompleteTarget || targetKey != envelope.Target.Key() || policyKey != target.Key() || device != target.DeviceID || domain != "service-complete" || revision == 0 || revision > MaxWindowsMaintenanceRevision || attempts < 0 || attempts >= alarmdelivery.MaxAttempts {
		return nil, ErrWindowsNotification
	}
	payload, e := decodeWindowsCompleteNotificationPayload(body, b.Key(), c.ID, envelope)
	if e != nil {
		return nil, e
	}
	if payload.Target != c.Subject || payload.TransitionAt.UnixMilli() != created || transition != payload.Transition {
		return nil, ErrWindowsNotification
	}
	suppress := ""
	if !now.Before(payload.TransitionAt.Add(alarmdelivery.MaxQueueAge)) {
		suppress = "queue_expired"
	}
	policies, e := readWindowsCompleteNotificationPolicies(ctx, tx)
	if e != nil {
		return nil, e
	}
	policyCurrent := false
	for _, p := range policies {
		if p.Target == target && p.Enabled && p.Revision == revision && p.Binding == b.Key() && !now.Before(p.ChangedAt) {
			policyCurrent = true
		}
	}
	if !policyCurrent {
		suppress = "source_policy_changed"
	}
	if _, err := completeNotificationHealth(ctx, tx, target); err != nil {
		if !errors.Is(err, ErrWindowsNotificationConflict) {
			return nil, err
		}
		suppress = "health_policy_changed"
	}
	maintenance, e := readWindowsMaintenance(ctx, tx)
	if e != nil {
		return nil, e
	}
	maintenanceTarget := completeNotificationMaintenanceTarget(target)
	muted, e := notificationMaintenance(maintenance, maintenanceTarget, now)
	if e != nil {
		return nil, e
	}
	if muted {
		suppress = "maintenance"
	}
	episode, current, e := completeNotificationCurrent(ctx, tx, envelope, in, now, since)
	if e != nil {
		return nil, e
	}
	if episode == nil {
		suppress = "episode_unavailable"
	} else {
		i := episode.Incident
		if payload.Target != i.Name {
			return nil, ErrWindowsNotification
		}
		if payload.Transition == "opened" {
			if !payload.ObservedAt.Equal(i.OpeningObservation.CollectedAt) {
				return nil, ErrWindowsNotification
			}
			if i.ResolvedAt != nil {
				suppress = "episode_closed"
			}
		} else {
			if i.ResolvedAt == nil || i.ClosedReason != "running" || i.RecoveryObservation == nil || i.RecoveryObservation.Source == nil || i.RecoveryObservation.Source.Binding() != target.Source || !payload.TransitionAt.Equal(*i.ResolvedAt) || !payload.ObservedAt.Equal(i.RecoveryObservation.CollectedAt) {
				return nil, ErrWindowsNotification
			}
			var opening string
			e = tx.QueryRowContext(ctx, `SELECT state FROM windows_notification_outbox WHERE target_key=? AND binding=? AND policy_key=? AND revision=? AND transition='opened'`, envelope.Target.Key(), b.Key(), target.Key(), revision).Scan(&opening)
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
		if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state='suppressed',code=?,finished=? WHERE id=? AND state='queued'`, suppress, now.UnixMilli(), c.ID); e != nil {
			return nil, e
		}
		return nil, tx.Commit()
	}
	// Loss of source freshness cannot authorize a retained recovery. It waits for
	// a live generation just as an opening waits for a qualifying evaluation.
	ready := completeNotificationInput(target, in, now) && current
	next := now.Add(30 * time.Second).UnixMilli()
	if ready && payload.Transition == "opened" {
		var previous sql.NullInt64
		if e = tx.QueryRowContext(ctx, `SELECT max(last_attempt) FROM windows_notification_outbox WHERE binding=? AND device=? AND domain='service-complete' AND json_extract(target,'$.target.invitationId')=? AND json_extract(target,'$.target.certificateHash')=? AND transition='opened' AND id<>?`, b.Key(), target.DeviceID, target.InvitationID, target.CertificateHash, c.ID).Scan(&previous); e != nil {
			return nil, e
		}
		if previous.Valid && previous.Int64 > 0 && now.UnixMilli() < previous.Int64+alarmdelivery.OpeningCooldown.Milliseconds() {
			next = previous.Int64 + alarmdelivery.OpeningCooldown.Milliseconds()
			ready = false
		}
	}
	if !ready {
		if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET due=? WHERE id=? AND state='queued'`, next, c.ID); e != nil {
			return nil, e
		}
		return nil, tx.Commit()
	}
	finalCheck := func(at, previous time.Time) error {
		if !validMaintenanceTime(at) || at.Before(previous) || !at.Before(payload.TransitionAt.Add(alarmdelivery.MaxQueueAge)) || !completeNotificationInput(target, in, at) {
			return ErrWindowsNotificationConflict
		}
		if err := guard(at); err != nil {
			return err
		}
		if _, err := completeNotificationHealth(ctx, tx, target); err != nil {
			return err
		}
		muted, err := notificationMaintenance(maintenance, maintenanceTarget, at)
		if err != nil {
			return err
		}
		if muted {
			return ErrWindowsNotificationConflict
		}
		retained, fresh, err := completeNotificationCurrent(ctx, tx, envelope, in, at, since)
		if err != nil {
			return err
		}
		if retained == nil || retained.Incident.Name != payload.Target || !fresh || payload.Transition == "opened" && retained.Incident.ResolvedAt != nil {
			return ErrWindowsNotificationConflict
		}
		return ctx.Err()
	}
	final := clock().UTC()
	if e = finalCheck(final, now); e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state='in_flight',attempts=attempts+1,last_attempt=? WHERE id=? AND state='queued'`, final.UnixMilli(), c.ID); e != nil {
		return nil, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE alarm_settings SET last_send=? WHERE id=1`, final.UnixMilli()); e != nil {
		return nil, e
	}
	commitAt := clock().UTC()
	if e = finalCheck(commitAt, final); e != nil {
		return nil, e
	}
	// A guard can itself consume the last source lifetime; qualify its return too.
	afterGuard := clock().UTC()
	if !validMaintenanceTime(afterGuard) || afterGuard.Before(commitAt) || !completeNotificationInput(target, in, afterGuard) || !afterGuard.Before(payload.TransitionAt.Add(alarmdelivery.MaxQueueAge)) {
		return nil, ErrWindowsNotificationConflict
	}
	_, fresh, err := completeNotificationCurrent(ctx, tx, envelope, in, afterGuard, since)
	if err != nil {
		return nil, err
	}
	if !fresh {
		return nil, ErrWindowsNotificationConflict
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	return &alarmdelivery.Attempt{Payload: payload, Number: attempts + 1}, nil
}
