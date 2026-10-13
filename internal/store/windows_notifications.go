package store

// Windows notification source admission is independent of recipient setup and
// Linux Health. Old v1 ledgers remain byte-for-byte unchanged.
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
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsservicehealth"
)

const WindowsNotificationSchema = "tracebolt.windows-alarm-event.v1"
const windowsNotificationSchema = `CREATE TABLE IF NOT EXISTS windows_notification_policies(id TEXT NOT NULL,domain TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=1024 AND json_valid(body)),PRIMARY KEY(id,domain));
CREATE TABLE IF NOT EXISTS windows_notification_outbox(id TEXT PRIMARY KEY,binding TEXT NOT NULL,target_key TEXT NOT NULL,policy_key TEXT NOT NULL,revision INTEGER NOT NULL,device TEXT NOT NULL,domain TEXT NOT NULL,target BLOB NOT NULL CHECK(length(target)<=1024 AND json_valid(target)),body BLOB NOT NULL CHECK(length(body)<=2048 AND json_valid(body)),transition TEXT NOT NULL CHECK(transition IN ('opened','recovered')),state TEXT NOT NULL CHECK(state IN ('queued','in_flight','provider_accepted','failed','uncertain','suppressed')),attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),created INTEGER NOT NULL,due INTEGER NOT NULL,last_attempt INTEGER NOT NULL DEFAULT 0,finished INTEGER NOT NULL DEFAULT 0,code TEXT NOT NULL DEFAULT '',stop_retry INTEGER NOT NULL DEFAULT 0 CHECK(stop_retry IN (0,1)),UNIQUE(binding,target_key,revision,transition));
CREATE INDEX IF NOT EXISTS windows_notification_due ON windows_notification_outbox(state,due);
CREATE TABLE IF NOT EXISTS windows_notification_counters(id INTEGER PRIMARY KEY CHECK(id=1),dropped INTEGER NOT NULL DEFAULT 0);
INSERT OR IGNORE INTO windows_notification_counters(id) VALUES(1);`

var ErrWindowsNotification = errors.New("windows_notification_invalid")
var ErrWindowsNotificationConflict = errors.New("windows_notification_conflict")

type WindowsNotificationPolicy struct {
	Version   int                      `json:"version"`
	Target    WindowsMaintenanceTarget `json:"target"`
	Revision  uint64                   `json:"revision"`
	Enabled   bool                     `json:"enabled"`
	Binding   string                   `json:"binding"`
	ChangedAt time.Time                `json:"changedAt"`
}

func (v WindowsNotificationPolicy) valid() bool {
	return v.Version == 1 && v.Target.Valid() && v.Target.Domain != "all" && v.Revision > 0 && v.Revision <= MaxWindowsMaintenanceRevision && enrollmentcrypto.ValidHash(v.Binding) && validMaintenanceTime(v.ChangedAt)
}
func readWindowsNotificationPolicies(ctx context.Context, tx *sql.Tx) ([]WindowsNotificationPolicy, error) {
	rows, e := tx.QueryContext(ctx, `SELECT id,domain,body FROM windows_notification_policies ORDER BY id,domain LIMIT 126`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []WindowsNotificationPolicy{}
	for rows.Next() {
		var id, domain string
		var raw []byte
		var p WindowsNotificationPolicy
		if e = rows.Scan(&id, &domain, &raw); e != nil {
			return nil, e
		}
		if len(raw) > 1024 || json.Unmarshal(raw, &p) != nil || !p.valid() || p.Target.DeviceID != id || p.Target.Domain != domain {
			return nil, ErrWindowsNotification
		}
		canonical, _ := json.Marshal(p)
		if !bytes.Equal(raw, canonical) {
			return nil, ErrWindowsNotification
		}
		out = append(out, p)
		if len(out) > 125 {
			return nil, ErrWindowsNotification
		}
	}
	return out, rows.Err()
}

type WindowsNotificationSnapshot struct {
	Policies        []WindowsNotificationPolicy
	Binding         string
	DeliveryEnabled bool
	Counts          AlarmStatus
}

func (s *Store) WindowsNotifications(ctx context.Context) (WindowsNotificationSnapshot, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return WindowsNotificationSnapshot{}, e
	}
	defer tx.Rollback()
	var v WindowsNotificationSnapshot
	v.Policies, e = readWindowsNotificationPolicies(ctx, tx)
	if e != nil {
		return v, e
	}
	var enabled int
	if e = tx.QueryRowContext(ctx, `SELECT binding,enabled FROM alarm_settings WHERE id=1`).Scan(&v.Binding, &enabled); e != nil {
		return v, e
	}
	v.DeliveryEnabled = enabled == 1
	e = tx.QueryRowContext(ctx, `SELECT dropped,(SELECT count(*) FROM windows_notification_outbox WHERE state='queued'),(SELECT count(*) FROM windows_notification_outbox WHERE state='in_flight'),(SELECT count(*) FROM windows_notification_outbox WHERE state='provider_accepted'),(SELECT count(*) FROM windows_notification_outbox WHERE state='failed'),(SELECT count(*) FROM windows_notification_outbox WHERE state='uncertain'),(SELECT count(*) FROM windows_notification_outbox WHERE state='suppressed') FROM windows_notification_counters WHERE id=1`).Scan(&v.Counts.Dropped, &v.Counts.Queued, &v.Counts.InFlight, &v.Counts.ProviderAccepted, &v.Counts.Failed, &v.Counts.Uncertain, &v.Counts.Suppressed)
	if e != nil {
		return v, e
	}
	return v, tx.Commit()
}

// Called under the enrollment lease. Source opt-in never creates a destination,
// evaluates history or backfills an already open episode.
func (s *Store) ChangeWindowsNotificationPolicy(ctx context.Context, target WindowsMaintenanceTarget, revision uint64, enabled bool, binding string, clock func() time.Time, guard func(time.Time) error) (WindowsNotificationPolicy, error) {
	var next WindowsNotificationPolicy
	if !target.Valid() || target.Domain == "all" || revision >= MaxWindowsMaintenanceRevision || clock == nil || guard == nil || enabled && !enrollmentcrypto.ValidHash(binding) {
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
	policies, e := readWindowsNotificationPolicies(ctx, tx)
	if e != nil {
		return next, e
	}
	found := false
	for _, p := range policies {
		if p.Target.DeviceID == target.DeviceID && p.Target.Domain == target.Domain {
			found = true
			if p.Target == target {
				next = p
			}
		}
	}
	if next.Revision != revision || !next.ChangedAt.IsZero() && now.Before(next.ChangedAt) {
		return next, ErrWindowsNotificationConflict
	}
	if !found && len(policies) >= 125 {
		return next, ErrLimit
	}
	if enabled {
		var current string
		var active int
		if e = tx.QueryRowContext(ctx, `SELECT binding,enabled FROM alarm_settings WHERE id=1`).Scan(&current, &active); e != nil {
			return next, e
		}
		if active != 1 || current != binding {
			return next, ErrWindowsNotificationConflict
		}
	} else {
		if next.Revision == 0 || !next.Enabled || binding != "" {
			return next, ErrWindowsNotificationConflict
		}
		binding = next.Binding
	}
	next = WindowsNotificationPolicy{1, target, revision + 1, enabled, binding, now}
	raw, _ := json.Marshal(next)
	if _, e = tx.ExecContext(ctx, `INSERT INTO windows_notification_policies(id,domain,body) VALUES(?,?,?) ON CONFLICT(id,domain) DO UPDATE SET body=excluded.body`, target.DeviceID, target.Domain, raw); e != nil {
		return next, e
	}
	// In-flight requests cannot be recalled; a definitive failure cannot retry
	// after the policy changes, including a disable/re-enable between attempts.
	if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state=CASE WHEN state='queued' THEN 'suppressed' ELSE state END,stop_retry=1,code='source_policy_changed',finished=CASE WHEN state='queued' THEN ? ELSE finished END WHERE device=? AND domain=? AND state IN ('queued','in_flight')`, now.UnixMilli(), target.DeviceID, target.Domain); e != nil {
		return next, e
	}
	final := clock().UTC()
	if final.Before(now) || !validMaintenanceTime(final) {
		return next, ErrWindowsNotificationConflict
	}
	if e = guard(final); e != nil {
		return next, e
	}
	return next, tx.Commit()
}

type windowsNotificationEpisode struct {
	Target     WindowsIncidentTarget
	ResolvedAt *time.Time
	Reason     string
	ObservedAt time.Time
	Subject    string
}

func notificationTarget(id, invite, cert, domain, incident string, opened time.Time) WindowsIncidentTarget {
	return WindowsIncidentTarget{id, invite, cert, domain, incident, opened}
}
func contactNotificationEpisodes(s windowscontact.State) []windowsNotificationEpisode {
	out := []windowsNotificationEpisode{}
	for _, i := range s.Incidents {
		at := i.LastAcceptedAt
		if i.RecoveryAcceptedAt != nil {
			at = *i.RecoveryAcceptedAt
		}
		out = append(out, windowsNotificationEpisode{notificationTarget(s.DeviceID, s.InvitationID, s.CertificateHash, "contact", i.ID, i.OpenedAt), i.ResolvedAt, i.ClosedReason, at, "authenticated-reports"})
	}
	return out
}
func capacityNotificationEpisodes(s windowscapacity.State, domain string) []windowsNotificationEpisode {
	out := []windowsNotificationEpisode{}
	for _, i := range s.Incidents {
		at := i.LastHighObservation.CollectedAt
		if i.RecoveryObservation != nil {
			at = i.RecoveryObservation.CollectedAt
		}
		out = append(out, windowsNotificationEpisode{notificationTarget(s.DeviceID, s.InvitationID, s.CertificateHash, domain, i.ID, i.OpenedAt), i.ResolvedAt, i.ClosedReason, at, domain})
	}
	return out
}
func serviceNotificationEpisodes(s windowsservicehealth.State) []windowsNotificationEpisode {
	// Existing recipient consent and delivery envelopes cover preview-v1 only.
	if s.SchemaVersion == windowsservicehealth.CompleteStateSchema {
		return []windowsNotificationEpisode{}
	}
	out := []windowsNotificationEpisode{}
	for _, i := range s.Incidents {
		at := i.LastBadObservation.CollectedAt
		if i.RecoveryObservation != nil {
			at = i.RecoveryObservation.CollectedAt
		}
		out = append(out, windowsNotificationEpisode{notificationTarget(s.DeviceID, s.InvitationID, s.CertificateHash, "service", i.ID, i.OpenedAt), i.ResolvedAt, i.ClosedReason, at, i.Name})
	}
	return out
}
func notificationRecovery(e windowsNotificationEpisode) bool {
	return e.Target.Domain == "contact" && e.Reason == "reports-resumed" || (e.Target.Domain == "disk" || e.Target.Domain == "cpu" || e.Target.Domain == "memory") && e.Reason == "within-policy" || e.Target.Domain == "service" && e.Reason == "running"
}
func notificationPolicyTarget(t WindowsIncidentTarget) WindowsMaintenanceTarget {
	return WindowsMaintenanceTarget{t.DeviceID, t.InvitationID, t.CertificateHash, t.Domain}
}
func notificationMaintenance(states []WindowsMaintenanceState, target WindowsMaintenanceTarget, now time.Time) (bool, error) {
	for _, s := range states {
		if s.Target.sameIdentity(target) && (s.Target.Domain == "all" || s.Target.Domain == target.Domain) {
			if now.Before(s.ChangedAt) {
				return false, ErrWindowsNotificationConflict
			}
			if s.Windows[0].Active(now) {
				return true, nil
			}
		}
	}
	return false, nil
}

// Invoked inside each source transaction, after encoding the original ledger.
// Comparing exact original identities and domains avoids colliding local IDs.
func enqueueWindowsNotifications(ctx context.Context, tx *sql.Tx, before, after []windowsNotificationEpisode) error {
	if len(after) == 0 {
		return nil
	}
	policies, e := readWindowsNotificationPolicies(ctx, tx)
	if e != nil {
		return e
	}
	var binding string
	var enabled int
	if e = tx.QueryRowContext(ctx, `SELECT binding,enabled FROM alarm_settings WHERE id=1`).Scan(&binding, &enabled); e != nil {
		return e
	}
	if enabled == 0 {
		return nil
	}
	byKey := map[string]WindowsNotificationPolicy{}
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
	previous := map[string]windowsNotificationEpisode{}
	for _, v := range before {
		previous[v.Target.Key()] = v
	}
	for _, v := range after {
		target := notificationPolicyTarget(v.Target)
		p, ok := byKey[target.Key()]
		if !ok || p.Target != target {
			continue
		}
		old, exists := previous[v.Target.Key()]
		transition := ""
		at := v.Target.OpenedAt
		if !exists && v.ResolvedAt == nil && !at.Before(p.ChangedAt) {
			transition = "opened"
		}
		if exists && old.ResolvedAt == nil && v.ResolvedAt != nil {
			if _, e = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state='suppressed',finished=?,code='episode_closed' WHERE target_key=? AND state='queued' AND transition='opened'`, v.ResolvedAt.UnixMilli(), v.Target.Key()); e != nil {
				return e
			}
			if notificationRecovery(v) {
				var state string
				e = tx.QueryRowContext(ctx, `SELECT state FROM windows_notification_outbox WHERE target_key=? AND binding=? AND revision=? AND transition='opened'`, v.Target.Key(), binding, p.Revision).Scan(&state)
				if e != nil && !errors.Is(e, sql.ErrNoRows) {
					return e
				}
				if state == "provider_accepted" || state == "in_flight" {
					transition = "recovered"
					at = *v.ResolvedAt
				}
			}
		}
		if transition == "" {
			continue
		}
		suppressed, e := notificationMaintenance(maintenance, target, at)
		if e != nil {
			return e
		}
		sum := sha256.Sum256([]byte(binding + "\x00" + v.Target.Key() + "\x00" + transition))
		id := hex.EncodeToString(sum[:])
		reason := "confirmed_unhealthy"
		state := "open"
		if transition == "recovered" {
			reason = v.Reason
			state = "recovered"
		}
		payload := alarmdelivery.Payload{SchemaVersion: WindowsNotificationSchema, EventID: id, DeviceID: v.Target.DeviceID, IncidentID: v.Target.IncidentID, Rule: "windows-" + v.Target.Domain, Target: v.Subject, Severity: "warning", Transition: transition, State: state, Reason: reason, ObservedAt: v.ObservedAt, TransitionAt: at}
		body, _ := json.Marshal(payload)
		raw, _ := json.Marshal(v.Target)
		if len(body) > alarmdelivery.MaxPayloadBytes || !v.Target.valid() {
			return ErrWindowsNotification
		}
		// Prune only during a source transition. Accepted opening dependencies are
		// kept while their exact episode remains retained, or a recovery is pending.
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
		if _, e = tx.ExecContext(ctx, `INSERT OR IGNORE INTO windows_notification_outbox(id,binding,target_key,policy_key,revision,device,domain,target,body,transition,state,created,due,code,finished) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, binding, v.Target.Key(), target.Key(), p.Revision, v.Target.DeviceID, v.Target.Domain, raw, body, transition, queueState, at.UnixMilli(), at.UnixMilli(), code, finished); e != nil {
			return e
		}
	}
	return nil
}
func pruneWindowsNotifications(ctx context.Context, tx *sql.Tx, at time.Time) error {
	snapshot, e := readWindowsIncidentSnapshot(ctx, tx)
	if e != nil {
		return e
	}
	keys := []string{}
	for key := range snapshot.Targets() {
		keys = append(keys, key)
	}
	raw, _ := json.Marshal(keys)
	_, e = tx.ExecContext(ctx, `DELETE FROM windows_notification_outbox WHERE state NOT IN ('queued','in_flight') AND created<? AND NOT(transition='opened' AND state='provider_accepted' AND (target_key IN (SELECT value FROM json_each(?)) OR EXISTS(SELECT 1 FROM windows_notification_outbox r WHERE r.target_key=windows_notification_outbox.target_key AND r.binding=windows_notification_outbox.binding AND r.revision=windows_notification_outbox.revision AND r.transition='recovered' AND r.state IN ('queued','in_flight'))))`, at.Add(-30*24*time.Hour).UnixMilli(), string(raw))
	return e
}
