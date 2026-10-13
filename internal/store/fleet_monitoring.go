package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowsresource"
)

// Separate manager-only opt-in metadata. Existing group and percentage v1 bytes
// are unchanged; creating these tables never creates an assignment or policy.
const fleetMonitoringSchema = `CREATE TABLE IF NOT EXISTS fleet_monitoring_definitions(id TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=4096 AND json_valid(body)))`
const fleetMonitoringAssignmentsSchema = `CREATE TABLE IF NOT EXISTS fleet_monitoring_assignments(id TEXT NOT NULL,metric TEXT NOT NULL CHECK(metric IN ('disk','cpu','memory')),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=4096 AND json_valid(body)),PRIMARY KEY(id,metric))`
const MaxFleetMonitoringAssignments = 75

var ErrFleetMonitoringConflict = errors.New("group monitoring revision or ownership changed")
var ErrFleetMonitoringInvalid = errors.New("invalid group monitoring state")

type FleetMonitoringSetting struct {
	Metric           string `json:"metric"`
	Enabled          bool   `json:"enabled"`
	ThresholdPercent int    `json:"thresholdPercent"`
}
type FleetMonitoringDefinition struct {
	Version  string                   `json:"version"`
	GroupID  string                   `json:"groupId"`
	Manager  string                   `json:"manager"`
	Revision uint64                   `json:"revision"`
	Settings []FleetMonitoringSetting `json:"settings"`
}
type FleetMonitoringAssignment struct {
	Version         string `json:"version"`
	DeviceID        string `json:"deviceId"`
	Metric          string `json:"metric"`
	GroupID         string `json:"groupId"`
	Manager         string `json:"manager"`
	Identity        string `json:"identity"`
	InvitationID    string `json:"invitationId"`
	CertificateHash string `json:"certificateHash"`
	Revision        uint64 `json:"revision"`
	Active          bool   `json:"active"`
	Status          string `json:"status"`
	AppliedRevision uint64 `json:"appliedRevision"`
	PolicyRevision  uint64 `json:"policyRevision"`
}
type FleetMonitoringChange struct {
	DeviceID               string
	Metric                 string
	Identity               string
	InvitationID           string
	CertificateHash        string
	ExpectedRevision       uint64
	ExpectedPolicyRevision uint64
	Inherit                bool
}

func ValidFleetMonitoringMetric(metric string) bool {
	return metric == "disk" || metric == "cpu" || metric == "memory"
}
func validMonitoringSetting(s FleetMonitoringSetting) bool {
	return ValidFleetMonitoringMetric(s.Metric) && s.ThresholdPercent >= 50 && s.ThresholdPercent <= 99
}
func newMonitoringDefinition(manager, id string) FleetMonitoringDefinition {
	return FleetMonitoringDefinition{Version: "tracebolt.fleet-monitoring-definition.v1", GroupID: id, Manager: manager, Settings: []FleetMonitoringSetting{}}
}
func (d FleetMonitoringDefinition) Setting(metric string) (FleetMonitoringSetting, bool) {
	for _, s := range d.Settings {
		if s.Metric == metric {
			return s, true
		}
	}
	return FleetMonitoringSetting{}, false
}
func decodeMonitoringDefinition(id string, raw []byte) (FleetMonitoringDefinition, error) {
	var d FleetMonitoringDefinition
	if len(raw) > 4096 || json.Unmarshal(raw, &d) != nil || d.Version != "tracebolt.fleet-monitoring-definition.v1" || d.GroupID != id || !enrollmentcrypto.ValidID(id, "group_") || !enrollmentcrypto.ValidHash(d.Manager) || d.Revision < 1 || d.Revision > MaxFleetGroupRevision || d.Settings == nil || len(d.Settings) > 3 {
		return d, ErrFleetMonitoringInvalid
	}
	for i, s := range d.Settings {
		if !validMonitoringSetting(s) || i > 0 && d.Settings[i-1].Metric >= s.Metric {
			return d, ErrFleetMonitoringInvalid
		}
	}
	canonical, _ := json.Marshal(d)
	if !bytes.Equal(canonical, raw) {
		return d, ErrFleetMonitoringInvalid
	}
	return d, nil
}
func decodeMonitoringAssignment(id, metric string, raw []byte) (FleetMonitoringAssignment, error) {
	var a FleetMonitoringAssignment
	if len(raw) > 4096 || json.Unmarshal(raw, &a) != nil || a.Version != "tracebolt.fleet-monitoring-assignment.v1" || a.DeviceID != id || a.Metric != metric || !enrollmentcrypto.ValidID(id, "agent_") || !ValidFleetMonitoringMetric(metric) || !enrollmentcrypto.ValidID(a.GroupID, "group_") || !enrollmentcrypto.ValidHash(a.Manager) || !enrollmentcrypto.ValidHash(a.Identity) || !enrollmentcrypto.ValidID(a.InvitationID, "invite_") || !enrollmentcrypto.ValidHash(a.CertificateHash) || a.Revision < 1 || a.Revision > MaxFleetGroupRevision || a.AppliedRevision > MaxFleetGroupRevision || a.PolicyRevision > windowscapacity.MaxCounter || a.Active && a.Status != "active" || !a.Active && a.Status != "manual-override" && a.Status != "stopped" {
		return a, ErrFleetMonitoringInvalid
	}
	canonical, _ := json.Marshal(a)
	if !bytes.Equal(canonical, raw) {
		return a, ErrFleetMonitoringInvalid
	}
	return a, nil
}

type monitoringQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func monitoringDefinition(ctx context.Context, q monitoringQuery, manager, id string) (FleetMonitoringDefinition, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, "SELECT body FROM fleet_monitoring_definitions WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return newMonitoringDefinition(manager, id), nil
	}
	if err != nil {
		return FleetMonitoringDefinition{}, err
	}
	d, err := decodeMonitoringDefinition(id, raw)
	if err == nil && d.Manager != manager {
		err = ErrFleetMonitoringConflict
	}
	return d, err
}
func monitoringAssignments(ctx context.Context, q monitoringQuery) ([]FleetMonitoringAssignment, error) {
	rows, err := q.QueryContext(ctx, "SELECT id,metric,body FROM fleet_monitoring_assignments ORDER BY id,metric LIMIT 76")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetMonitoringAssignment{}
	devices := map[string]bool{}
	for rows.Next() {
		var id, metric string
		var raw []byte
		if err = rows.Scan(&id, &metric, &raw); err != nil {
			return nil, err
		}
		a, e := decodeMonitoringAssignment(id, metric, raw)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
		devices[id] = true
		if len(out) > 75 || len(devices) > 25 {
			return nil, ErrFleetMonitoringInvalid
		}
	}
	return out, rows.Err()
}
func (s *Store) FleetMonitoringDefinition(ctx context.Context, manager, id string) (FleetMonitoringDefinition, error) {
	return monitoringDefinition(ctx, s.db, manager, id)
}
func (s *Store) FleetMonitoringAssignments(ctx context.Context) ([]FleetMonitoringAssignment, error) {
	return monitoringAssignments(ctx, s.db)
}
func writeMonitoringAssignment(ctx context.Context, tx *sql.Tx, a FleetMonitoringAssignment) error {
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if _, err = decodeMonitoringAssignment(a.DeviceID, a.Metric, raw); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO fleet_monitoring_assignments(id,metric,body) VALUES(?,?,?) ON CONFLICT(id,metric) DO UPDATE SET body=excluded.body", a.DeviceID, a.Metric, raw)
	return err
}
func monitoringGroup(ctx context.Context, q monitoringQuery, manager, id string, revision uint64) (FleetGroup, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, "SELECT body FROM fleet_groups WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return FleetGroup{}, ErrFleetMonitoringConflict
	}
	if err != nil {
		return FleetGroup{}, err
	}
	g, err := decodeFleetGroup(id, raw)
	if err == nil && (g.Manager != manager || g.Revision != revision) {
		err = ErrFleetMonitoringConflict
	}
	return g, err
}
func monitoringMember(g FleetGroup, id, identity string) bool {
	for _, m := range g.Members {
		if m.DeviceID == id && m.Identity == identity {
			return true
		}
	}
	return false
}
func monitoringPolicy(ctx context.Context, q monitoringQuery, id, metric string) (windowscapacity.State, error) {
	var raw []byte
	var err error
	if metric == "disk" {
		err = q.QueryRowContext(ctx, "SELECT body FROM windows_capacity_devices WHERE id=?", id).Scan(&raw)
	} else {
		err = q.QueryRowContext(ctx, "SELECT body FROM windows_resource_devices WHERE id=? AND metric=?", id, metric).Scan(&raw)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return windowscapacity.New(), nil
	}
	if err != nil {
		return windowscapacity.State{}, err
	}
	if metric == "disk" {
		return decodeWindowsCapacity(id, raw)
	}
	v, e := decodeWindowsResource(id, windowsresource.Kind(metric), raw)
	return v.Assessment, e
}

// Definition and exact opt-in changes are a single guarded transaction. Settings
// merge by metric; existing explicitly armed assignments follow future edits,
// while absent/new members remain manual. There is only one owner per target.
func (s *Store) SaveFleetMonitoring(ctx context.Context, manager, id string, groupRevision, expected uint64, consent bool, settings []FleetMonitoringSetting, changes []FleetMonitoringChange, guard func() error) error {
	if guard == nil || expected >= MaxFleetGroupRevision || len(settings) > 3 || len(changes) > 75 || len(settings) == 0 && len(changes) == 0 {
		return ErrFleetMonitoringInvalid
	}
	seen := map[string]bool{}
	for _, v := range settings {
		if !consent || !validMonitoringSetting(v) || seen[v.Metric] {
			return ErrFleetMonitoringInvalid
		}
		seen[v.Metric] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = runPolicyGuards(ctx, []func() error{guard}); err != nil {
		return err
	}
	g, err := monitoringGroup(ctx, tx, manager, id, groupRevision)
	if err != nil {
		return err
	}
	d, err := monitoringDefinition(ctx, tx, manager, id)
	if err != nil {
		return err
	}
	if d.Revision != expected {
		return ErrFleetMonitoringConflict
	}
	assignments, err := monitoringAssignments(ctx, tx)
	if err != nil {
		return err
	}
	byKey := map[string]FleetMonitoringAssignment{}
	devices := map[string]bool{}
	for _, a := range assignments {
		byKey[a.DeviceID+"/"+a.Metric] = a
		devices[a.DeviceID] = true
	}
	merged := map[string]FleetMonitoringSetting{}
	for _, v := range d.Settings {
		merged[v.Metric] = v
	}
	for _, v := range settings {
		merged[v.Metric] = v
	}
	seen = map[string]bool{}
	for _, c := range changes {
		key := c.DeviceID + "/" + c.Metric
		if seen[key] || !ValidFleetMonitoringMetric(c.Metric) || c.ExpectedRevision >= MaxFleetGroupRevision || !monitoringMember(g, c.DeviceID, c.Identity) || c.Inherit && !consent {
			return ErrFleetMonitoringConflict
		}
		seen[key] = true
		old, exists := byKey[key]
		if old.Revision != c.ExpectedRevision || exists && old.Active && (old.GroupID != id || old.Manager != manager || old.Identity != c.Identity) || !c.Inherit && (!exists || old.GroupID != id || old.Identity != c.Identity) {
			return ErrFleetMonitoringConflict
		}
		state, e := monitoringPolicy(ctx, tx, c.DeviceID, c.Metric)
		if e != nil {
			return e
		}
		if state.Policy.Revision != c.ExpectedPolicyRevision || state.InvitationID != "" && (state.InvitationID != c.InvitationID || state.CertificateHash != c.CertificateHash) {
			return ErrFleetMonitoringConflict
		}
		if c.Inherit {
			if _, ok := merged[c.Metric]; !ok {
				return ErrFleetMonitoringInvalid
			}
		}
		if !exists && (len(byKey) >= 75 || !devices[c.DeviceID] && len(devices) >= 25) {
			return ErrLimit
		}
		a := FleetMonitoringAssignment{Version: "tracebolt.fleet-monitoring-assignment.v1", DeviceID: c.DeviceID, Metric: c.Metric, GroupID: id, Manager: manager, Identity: c.Identity, InvitationID: c.InvitationID, CertificateHash: c.CertificateHash, Revision: c.ExpectedRevision + 1, Active: c.Inherit, Status: "active", PolicyRevision: c.ExpectedPolicyRevision}
		if !c.Inherit {
			a.Status = "stopped"
			a.AppliedRevision = old.AppliedRevision
		}
		if err = writeMonitoringAssignment(ctx, tx, a); err != nil {
			return err
		}
		byKey[key] = a
		devices[c.DeviceID] = true
	}
	if len(settings) > 0 {
		d.Revision++
		d.Settings = []FleetMonitoringSetting{}
		for _, v := range merged {
			d.Settings = append(d.Settings, v)
		}
		sort.Slice(d.Settings, func(i, j int) bool { return d.Settings[i].Metric < d.Settings[j].Metric })
		raw, _ := json.Marshal(d)
		if _, err = decodeMonitoringDefinition(id, raw); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO fleet_monitoring_definitions(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", id, raw); err != nil {
			return err
		}
	} else if d.Revision == 0 {
		return ErrFleetMonitoringInvalid
	}
	if err = runPolicyGuards(ctx, []func() error{guard}); err != nil {
		return err
	}
	return tx.Commit()
}

// An ordinary successful Save deliberately detaches ownership, even when the
// percentage engine keeps an identical policy revision. It commits with the
// policy, so a reconciler cannot overwrite a same-value manual choice.
func detachFleetMonitoring(ctx context.Context, tx *sql.Tx, id, metric string) error {
	var raw []byte
	err := tx.QueryRowContext(ctx, "SELECT body FROM fleet_monitoring_assignments WHERE id=? AND metric=?", id, metric).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	a, err := decodeMonitoringAssignment(id, metric, raw)
	if err != nil {
		return err
	}
	if !a.Active {
		return nil
	}
	if a.Revision >= MaxFleetGroupRevision {
		return ErrFleetMonitoringConflict
	}
	a.Active = false
	a.Status = "manual-override"
	a.Revision++
	return writeMonitoringAssignment(ctx, tx, a)
}

// Called inside group membership/deletion transaction. Disarming never changes
// the device policy. Re-adding a member has no code path that re-arms ownership.
func disarmFleetMonitoring(ctx context.Context, tx *sql.Tx, g FleetGroup, remove bool) error {
	all, err := monitoringAssignments(ctx, tx)
	if err != nil {
		return err
	}
	for _, a := range all {
		if a.GroupID != g.ID || a.Manager != g.Manager {
			continue
		}
		if a.Active && (remove || !monitoringMember(g, a.DeviceID, a.Identity)) {
			if a.Revision >= MaxFleetGroupRevision {
				return ErrFleetMonitoringConflict
			}
			a.Active = false
			a.Status = "stopped"
			a.Revision++
			if err = writeMonitoringAssignment(ctx, tx, a); err != nil {
				return err
			}
		}
	}
	if remove {
		_, err = tx.ExecContext(ctx, "DELETE FROM fleet_monitoring_definitions WHERE id=?", g.ID)
	}
	return err
}

// Policy and applied ownership revision advance together under the enrollment
// lease. Re-read every optimistic binding after obtaining operator SQLite.
func (s *Store) ReconcileFleetMonitoring(ctx context.Context, in windowscapacity.Input, a FleetMonitoringAssignment, d FleetMonitoringDefinition, groupRevision uint64, now time.Time, guard func() error) error {
	setting, ok := d.Setting(a.Metric)
	if !ok || !a.Active || a.Revision >= MaxFleetGroupRevision || guard == nil || in.DeviceID != a.DeviceID || in.InvitationID != a.InvitationID || in.CertificateHash != a.CertificateHash {
		return ErrFleetMonitoringConflict
	}
	hook := func(tx *sql.Tx, state windowscapacity.State) error {
		g, err := monitoringGroup(ctx, tx, a.Manager, a.GroupID, groupRevision)
		if err != nil {
			return err
		}
		if !monitoringMember(g, a.DeviceID, a.Identity) {
			return ErrFleetMonitoringConflict
		}
		latest, err := monitoringDefinition(ctx, tx, a.Manager, a.GroupID)
		if err != nil {
			return err
		}
		if latest.Revision != d.Revision {
			return ErrFleetMonitoringConflict
		}
		var raw []byte
		if err = tx.QueryRowContext(ctx, "SELECT body FROM fleet_monitoring_assignments WHERE id=? AND metric=?", a.DeviceID, a.Metric).Scan(&raw); err != nil {
			return err
		}
		current, err := decodeMonitoringAssignment(a.DeviceID, a.Metric, raw)
		if err != nil {
			return err
		}
		if current != a {
			return ErrFleetMonitoringConflict
		}
		a.Revision++
		a.AppliedRevision = d.Revision
		a.PolicyRevision = state.Policy.Revision
		return writeMonitoringAssignment(ctx, tx, a)
	}
	if a.Metric == "disk" {
		_, err := s.updateWindowsCapacity(ctx, a.DeviceID, func(state *windowscapacity.State) error {
			return state.Configure(in, setting.Enabled, setting.ThresholdPercent, a.PolicyRevision, now)
		}, hook, guard)
		return err
	}
	kind := windowsresource.Kind(a.Metric)
	_, err := s.updateWindowsResource(ctx, a.DeviceID, kind, func(state *windowsresource.State) error {
		return state.Configure(in, kind, setting.Enabled, setting.ThresholdPercent, a.PolicyRevision, now)
	}, func(tx *sql.Tx, state windowsresource.State) error { return hook(tx, state.Assessment) }, guard)
	return err
}
