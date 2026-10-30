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

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowscontact"
)

// Planning metadata never changes source evaluation, incident history,
// acknowledgement, Linux alarms or endpoint authority. Windows notification
// dispatch alone consumes matching windows.
const windowsMaintenanceSchema = `CREATE TABLE IF NOT EXISTS windows_maintenance(id TEXT NOT NULL, domain TEXT NOT NULL, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=4096 AND json_valid(body)), PRIMARY KEY(id,domain))`
const MaxWindowsMaintenanceTargets = 150
const MaxWindowsMaintenanceHistory = 4
const MaxWindowsMaintenanceRevision = uint64(1<<53 - 1)

var ErrWindowsMaintenance = errors.New("windows_maintenance_invalid")
var ErrWindowsMaintenanceConflict = errors.New("windows_maintenance_conflict")

type WindowsMaintenanceTarget struct {
	DeviceID        string `json:"deviceId"`
	InvitationID    string `json:"invitationId"`
	CertificateHash string `json:"certificateHash"`
	Domain          string `json:"domain"`
}

func WindowsMaintenanceDomains() []string {
	return []string{"all", "contact", "cpu", "disk", "memory", "service"}
}
func (v WindowsMaintenanceTarget) Valid() bool {
	validDomain := false
	for _, domain := range WindowsMaintenanceDomains() {
		validDomain = validDomain || v.Domain == domain
	}
	return validDomain && windowscontact.ValidDeviceID(v.DeviceID) && enrollmentcrypto.ValidID(v.InvitationID, "invite_") && enrollmentcrypto.ValidHash(v.CertificateHash)
}
func (v WindowsMaintenanceTarget) Key() string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(append([]byte("tracebolt.windows-maintenance-target.v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}
func (v WindowsMaintenanceTarget) sameIdentity(other WindowsMaintenanceTarget) bool {
	return v.DeviceID == other.DeviceID && v.InvitationID == other.InvitationID && v.CertificateHash == other.CertificateHash
}
func ValidWindowsMaintenanceIntent(v string) bool {
	return v == "planned-work" || v == "investigation" || v == "other"
}
func validMaintenanceTime(at time.Time) bool {
	return !at.IsZero() && at.Year() >= 1970 && at.Year() <= 9999 && at.Location() == time.UTC
}

type WindowsMaintenanceWindow struct {
	ID        uint64     `json:"id"`
	StartedAt time.Time  `json:"startedAt"`
	EndsAt    time.Time  `json:"endsAt"`
	EndedAt   *time.Time `json:"endedAt"`
	Intent    string     `json:"intent"`
}

// Active uses the trusted manager clock. Explicitly ended windows never reopen;
// a time before the durable change floor is rejected by the caller. No arbitrary
// wall-clock rollback detection across manager restarts is claimed.
func (v WindowsMaintenanceWindow) Active(now time.Time) bool {
	return v.EndedAt == nil && !now.Before(v.StartedAt) && now.Before(v.EndsAt)
}

type WindowsMaintenanceState struct {
	Version   int                        `json:"version"`
	Target    WindowsMaintenanceTarget   `json:"target"`
	Revision  uint64                     `json:"revision"`
	ChangedAt time.Time                  `json:"changedAt"`
	Windows   []WindowsMaintenanceWindow `json:"windows"`
}

func (v WindowsMaintenanceState) valid() bool {
	if v.Version != 1 || !v.Target.Valid() || v.Revision < 1 || v.Revision > MaxWindowsMaintenanceRevision || !validMaintenanceTime(v.ChangedAt) || len(v.Windows) < 1 || len(v.Windows) > MaxWindowsMaintenanceHistory {
		return false
	}
	for i, w := range v.Windows {
		if w.ID < 1 || w.ID > v.Revision || !validMaintenanceTime(w.StartedAt) || !validMaintenanceTime(w.EndsAt) || w.EndsAt.Sub(w.StartedAt) < time.Minute || w.EndsAt.Sub(w.StartedAt) > 24*time.Hour || !ValidWindowsMaintenanceIntent(w.Intent) {
			return false
		}
		end := w.EndsAt
		if w.EndedAt != nil {
			if !validMaintenanceTime(*w.EndedAt) || w.EndedAt.Before(w.StartedAt) || !w.EndedAt.Before(w.EndsAt) {
				return false
			}
			end = *w.EndedAt
		}
		if i == 0 {
			changed := w.StartedAt
			revision := w.ID
			if w.EndedAt != nil {
				changed = *w.EndedAt
				revision++
			}
			if !v.ChangedAt.Equal(changed) || v.Revision != revision {
				return false
			}
		} else {
			step := uint64(1)
			if w.EndedAt != nil {
				step = 2
			}
			if w.ID+step != v.Windows[i-1].ID || end.After(v.Windows[i-1].StartedAt) {
				return false
			}
		}
	}
	return true
}
func decodeWindowsMaintenance(id, domain string, raw []byte) (WindowsMaintenanceState, error) {
	var v WindowsMaintenanceState
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal(raw, &v) != nil || !v.valid() || v.Target.DeviceID != id || v.Target.Domain != domain {
		return v, ErrWindowsMaintenance
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(canonical, raw) {
		return WindowsMaintenanceState{}, ErrWindowsMaintenance
	}
	return v, nil
}
func readWindowsMaintenance(ctx context.Context, tx *sql.Tx) ([]WindowsMaintenanceState, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id,domain,body FROM windows_maintenance ORDER BY id,domain LIMIT 151")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WindowsMaintenanceState{}
	for rows.Next() {
		var id, domain string
		var raw []byte
		if err = rows.Scan(&id, &domain, &raw); err != nil {
			return nil, err
		}
		v, e := decodeWindowsMaintenance(id, domain, raw)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
		if len(out) > MaxWindowsMaintenanceTargets {
			return nil, ErrWindowsMaintenance
		}
	}
	return out, rows.Err()
}

// A read never expires, repairs, prunes or otherwise writes retained metadata.
func (s *Store) WindowsMaintenance(ctx context.Context) ([]WindowsMaintenanceState, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out, err := readWindowsMaintenance(ctx, tx)
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

// Start and early-end both require an exact revision. An uncertain request is
// reconciled by read only; replay cannot extend its original end or create a new
// window. The enrollment authority lease must surround this operator transaction.
// A confirmed replacement may replace only that device/scope's old identity
// metadata. Unavailable other identities are never pruned on unrelated writes.
func (s *Store) ChangeWindowsMaintenance(ctx context.Context, target WindowsMaintenanceTarget, expected uint64, endsAt time.Time, intent string, endID uint64, clock func() time.Time, guard func(time.Time, time.Time) error) (WindowsMaintenanceState, error) {
	return s.changeWindowsMaintenance(ctx, target, expected, endsAt, intent, endID, clock, guard, nil)
}

func (s *Store) changeWindowsMaintenance(ctx context.Context, target WindowsMaintenanceTarget, expected uint64, endsAt time.Time, intent string, endID uint64, clock func() time.Time, guard func(time.Time, time.Time) error, group *FleetGroupMaintenanceSelection) (WindowsMaintenanceState, error) {
	start := endID == 0
	if !target.Valid() || expected >= MaxWindowsMaintenanceRevision || clock == nil || guard == nil || start && (!validMaintenanceTime(endsAt) || !ValidWindowsMaintenanceIntent(intent)) || !start && (!endsAt.IsZero() || intent != "") {
		return WindowsMaintenanceState{}, ErrWindowsMaintenance
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WindowsMaintenanceState{}, err
	}
	defer tx.Rollback()
	admitted := clock().UTC()
	if !validMaintenanceTime(admitted) {
		return WindowsMaintenanceState{}, ErrWindowsMaintenanceConflict
	}
	if err = runPolicyGuards(ctx, []func() error{func() error { return guard(admitted, endsAt) }}); err != nil {
		return WindowsMaintenanceState{}, err
	}
	if err = checkFleetGroupMaintenance(ctx, tx, group, target); err != nil {
		return WindowsMaintenanceState{}, err
	}
	states, err := readWindowsMaintenance(ctx, tx)
	if err != nil {
		return WindowsMaintenanceState{}, err
	}
	now := clock().UTC()
	if !validMaintenanceTime(now) || now.Before(admitted) {
		return WindowsMaintenanceState{}, ErrWindowsMaintenanceConflict
	}
	next := WindowsMaintenanceState{Version: 1, Target: target, Windows: []WindowsMaintenanceWindow{}}
	replaces := false
	for _, old := range states {
		if old.Target.DeviceID == target.DeviceID && old.Target.Domain == target.Domain {
			replaces = true
			if old.Target == target {
				next = old
			}
		}
		if old.Target.sameIdentity(target) {
			if now.Before(old.ChangedAt) {
				return next, ErrWindowsMaintenanceConflict
			}
			if start && (target.Domain == "all" || old.Target.Domain == "all" || old.Target.Domain == target.Domain) && old.Windows[0].Active(now) {
				return next, ErrWindowsMaintenanceConflict
			}
		}
	}
	if next.Revision != expected {
		return next, ErrWindowsMaintenanceConflict
	}
	if !replaces && len(states) >= MaxWindowsMaintenanceTargets {
		return next, ErrLimit
	}
	if start {
		if endsAt.Sub(now) < time.Minute || endsAt.Sub(now) > 24*time.Hour {
			return next, ErrWindowsMaintenanceConflict
		}
		next.Windows = append([]WindowsMaintenanceWindow{{ID: expected + 1, StartedAt: now, EndsAt: endsAt, Intent: intent}}, next.Windows...)
		if len(next.Windows) > MaxWindowsMaintenanceHistory {
			next.Windows = next.Windows[:MaxWindowsMaintenanceHistory]
		}
	} else {
		if len(next.Windows) == 0 || next.Windows[0].ID != endID || !next.Windows[0].Active(now) {
			return next, ErrWindowsMaintenanceConflict
		}
		next.Windows = append([]WindowsMaintenanceWindow{}, next.Windows...)
		next.Windows[0].EndedAt = &now
	}
	next.Revision = expected + 1
	next.ChangedAt = now
	if !next.valid() {
		return next, ErrWindowsMaintenance
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return next, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO windows_maintenance(id,domain,body) VALUES(?,?,?) ON CONFLICT(id,domain) DO UPDATE SET body=excluded.body", target.DeviceID, target.Domain, raw); err != nil {
		return next, err
	}
	if start {
		// Consume queued work now, so an early end before the worker wakes cannot
		// release stale backlog. In-flight completion remains truthful, but no retry.
		if _, err = tx.ExecContext(ctx, `UPDATE windows_notification_outbox SET state=CASE WHEN state='queued' THEN 'suppressed' ELSE state END,stop_retry=1,code='maintenance',finished=CASE WHEN state='queued' THEN ? ELSE finished END WHERE device=? AND CASE WHEN domain='service-complete' THEN json_extract(target,'$.target.invitationId') ELSE json_extract(target,'$.invitationId') END=? AND CASE WHEN domain='service-complete' THEN json_extract(target,'$.target.certificateHash') ELSE json_extract(target,'$.certificateHash') END=? AND (?='all' OR domain=? OR (?='service' AND domain='service-complete')) AND state IN ('queued','in_flight')`, now.UnixMilli(), target.DeviceID, target.InvitationID, target.CertificateHash, target.Domain, target.Domain, target.Domain); err != nil {
			return next, err
		}
	}
	final := clock().UTC()
	if !validMaintenanceTime(final) || final.Before(now) || !final.Before(next.Windows[0].EndsAt) {
		return WindowsMaintenanceState{}, ErrWindowsMaintenanceConflict
	}
	if err = checkFleetGroupMaintenance(ctx, tx, group, target); err != nil {
		return WindowsMaintenanceState{}, err
	}
	if err = runPolicyGuards(ctx, []func() error{func() error { return guard(final, next.Windows[0].EndsAt) }}); err != nil {
		return WindowsMaintenanceState{}, err
	}
	if err = tx.Commit(); err != nil {
		return WindowsMaintenanceState{}, err
	}
	return next, nil
}
