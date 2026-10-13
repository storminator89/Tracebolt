package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsresource"
	"localrmm/internal/windowsservicehealth"
)

// Operator acknowledgement is separate from every strict v1 assessment ledger.
// It neither evaluates nor closes an episode and never enters the Linux outbox.
const windowsIncidentAcknowledgementsSchema = `CREATE TABLE IF NOT EXISTS windows_incident_acknowledgements(key TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=1024 AND json_valid(body)))`
const MaxWindowsInboxIncidents = 25 * 100 * 5

var ErrWindowsIncident = errors.New("windows_incident_invalid")
var windowsIncidentID = regexp.MustCompile(`^(wcontact|wcapacity|wservice)_[0-9a-f]{16}$`)

// CertificateHash is the original issued certificate anchor, never the renewed
// leaf. Like the source ledgers, the target cannot transfer to a new enrollment.
type WindowsIncidentTarget struct {
	DeviceID        string    `json:"deviceId"`
	InvitationID    string    `json:"invitationId"`
	CertificateHash string    `json:"certificateHash"`
	Domain          string    `json:"domain"`
	IncidentID      string    `json:"incidentId"`
	OpenedAt        time.Time `json:"openedAt"`
}

func (v WindowsIncidentTarget) valid() bool {
	prefix := "wcapacity_"
	switch v.Domain {
	case "contact":
		prefix = "wcontact_"
	case "service":
		prefix = "wservice_"
	case "disk", "cpu", "memory":
	default:
		return false
	}
	return windowscontact.ValidDeviceID(v.DeviceID) && enrollmentcrypto.ValidID(v.InvitationID, "invite_") && enrollmentcrypto.ValidHash(v.CertificateHash) && windowsIncidentID.MatchString(v.IncidentID) && len(v.IncidentID) > len(prefix) && v.IncidentID[:len(prefix)] == prefix && !v.OpenedAt.IsZero() && v.OpenedAt.Year() >= 1970 && v.OpenedAt.Year() <= 9999 && v.OpenedAt.Location() == time.UTC
}
func (v WindowsIncidentTarget) Key() string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(append([]byte("tracebolt.windows-incident-target.v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

type WindowsIncidentAcknowledgement struct {
	Version        int                   `json:"version"`
	Target         WindowsIncidentTarget `json:"target"`
	AcknowledgedAt time.Time             `json:"acknowledgedAt"`
}

func decodeWindowsIncidentAcknowledgement(key string, raw []byte) (WindowsIncidentAcknowledgement, error) {
	var v WindowsIncidentAcknowledgement
	if len(raw) == 0 || len(raw) > 1024 || json.Unmarshal(raw, &v) != nil || v.Version != 1 || !v.Target.valid() || v.Target.Key() != key || v.AcknowledgedAt.Before(v.Target.OpenedAt) || v.AcknowledgedAt.Year() > 9999 || v.AcknowledgedAt.Location() != time.UTC {
		return v, ErrWindowsIncident
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(canonical, raw) {
		return WindowsIncidentAcknowledgement{}, ErrWindowsIncident
	}
	return v, nil
}

// All source families and acknowledgements are read in one transaction. A GET
// using this snapshot never repairs, prunes, evaluates or writes any table.
type WindowsIncidentSnapshot struct {
	Contacts         map[string]windowscontact.State
	Capacities       map[string]windowscapacity.State
	Resources        []windowsresource.State
	Services         map[string]windowsservicehealth.State
	Acknowledgements map[string]WindowsIncidentAcknowledgement
}

func (s *Store) WindowsIncidentSnapshot(ctx context.Context) (WindowsIncidentSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return WindowsIncidentSnapshot{}, err
	}
	defer tx.Rollback()
	v, err := readWindowsIncidentSnapshot(ctx, tx)
	if err != nil {
		return v, err
	}
	err = tx.Commit()
	return v, err
}
func readWindowsIncidentSnapshot(ctx context.Context, tx *sql.Tx) (WindowsIncidentSnapshot, error) {
	v := WindowsIncidentSnapshot{Contacts: map[string]windowscontact.State{}, Capacities: map[string]windowscapacity.State{}, Resources: []windowsresource.State{}, Services: map[string]windowsservicehealth.State{}, Acknowledgements: map[string]WindowsIncidentAcknowledgement{}}
	// Query names are fixed source domains, never interpolated caller input.
	for _, table := range []string{"windows_contact_devices", "windows_capacity_devices", "windows_resource_devices", "windows_service_devices"} {
		query := "SELECT id, '', body FROM " + table + " ORDER BY id LIMIT 26"
		max := 25
		if table == "windows_resource_devices" {
			query = "SELECT id, metric, body FROM windows_resource_devices ORDER BY id,metric LIMIT 51"
			max = 50
		}
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return v, err
		}
		count := 0
		devices := map[string]bool{}
		for rows.Next() {
			var id, metric string
			var raw []byte
			if err = rows.Scan(&id, &metric, &raw); err != nil {
				rows.Close()
				return v, err
			}
			count++
			devices[id] = true
			if count > max || len(devices) > 25 {
				rows.Close()
				return v, ErrWindowsIncident
			}
			switch table {
			case "windows_contact_devices":
				var st windowscontact.State
				st, err = decodeWindowsContact(id, raw)
				v.Contacts[id] = st
			case "windows_capacity_devices":
				var st windowscapacity.State
				st, err = decodeWindowsCapacity(id, raw)
				v.Capacities[id] = st
			case "windows_resource_devices":
				var st windowsresource.State
				st, err = decodeWindowsResource(id, windowsresource.Kind(metric), raw)
				v.Resources = append(v.Resources, st)
			case "windows_service_devices":
				var st windowsservicehealth.State
				st, err = decodeWindowsService(id, raw)
				v.Services[id] = st
			}
			if err != nil {
				rows.Close()
				return v, err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return v, err
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT key,body FROM windows_incident_acknowledgements ORDER BY key LIMIT 12501")
	if err != nil {
		return v, err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var raw []byte
		if err = rows.Scan(&key, &raw); err != nil {
			return v, err
		}
		ack, e := decodeWindowsIncidentAcknowledgement(key, raw)
		if e != nil {
			return v, e
		}
		v.Acknowledgements[key] = ack
		if len(v.Acknowledgements) > MaxWindowsInboxIncidents {
			return v, ErrWindowsIncident
		}
	}
	return v, rows.Err()
}
func (v WindowsIncidentSnapshot) Targets() map[string]WindowsIncidentTarget {
	out := map[string]WindowsIncidentTarget{}
	add := func(id, invitation, certificate, domain, incident string, opened time.Time) {
		t := WindowsIncidentTarget{id, invitation, certificate, domain, incident, opened}
		out[t.Key()] = t
	}
	for id, s := range v.Contacts {
		for _, i := range s.Incidents {
			add(id, s.InvitationID, s.CertificateHash, "contact", i.ID, i.OpenedAt)
		}
	}
	for id, s := range v.Capacities {
		for _, i := range s.Incidents {
			add(id, s.InvitationID, s.CertificateHash, "disk", i.ID, i.OpenedAt)
		}
	}
	for _, r := range v.Resources {
		s := r.Assessment
		for _, i := range s.Incidents {
			add(s.DeviceID, s.InvitationID, s.CertificateHash, string(r.Metric), i.ID, i.OpenedAt)
		}
	}
	for id, s := range v.Services {
		if s.SchemaVersion == windowsservicehealth.CompleteStateSchema {
			continue
		}
		for _, i := range s.Incidents {
			add(id, s.InvitationID, s.CertificateHash, "service", i.ID, i.OpenedAt)
		}
	}
	return out
}

// AcknowledgeWindowsIncident reloads the exact retained target after acquiring
// SQLite. Only this explicit mutation removes orphan acknowledgement metadata;
// all retained episodes keep their acknowledgement without age-based eviction.
// Both final guards must remain live, even for an already acknowledged target.
func (s *Store) AcknowledgeWindowsIncident(ctx context.Context, target WindowsIncidentTarget, clock func() time.Time, guard func(time.Time) error) (WindowsIncidentAcknowledgement, error) {
	if !target.valid() || guard == nil || clock == nil {
		return WindowsIncidentAcknowledgement{}, ErrWindowsIncident
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WindowsIncidentAcknowledgement{}, err
	}
	defer tx.Rollback()
	if err = runPolicyGuards(ctx, []func() error{func() error { return guard(clock().UTC()) }}); err != nil {
		return WindowsIncidentAcknowledgement{}, err
	}
	snapshot, err := readWindowsIncidentSnapshot(ctx, tx)
	if err != nil {
		return WindowsIncidentAcknowledgement{}, err
	}
	targets := snapshot.Targets()
	key := target.Key()
	if current, ok := targets[key]; !ok || current != target {
		return WindowsIncidentAcknowledgement{}, ErrWindowsIncident
	}
	at := clock().UTC()
	if at.Before(target.OpenedAt) || at.Year() > 9999 {
		return WindowsIncidentAcknowledgement{}, ErrWindowsIncident
	}
	ack, exists := snapshot.Acknowledgements[key]
	if exists && ack.AcknowledgedAt.After(at) {
		return WindowsIncidentAcknowledgement{}, ErrWindowsIncident
	}
	for stale := range snapshot.Acknowledgements {
		if _, retained := targets[stale]; !retained {
			if _, err = tx.ExecContext(ctx, "DELETE FROM windows_incident_acknowledgements WHERE key=?", stale); err != nil {
				return WindowsIncidentAcknowledgement{}, err
			}
			delete(snapshot.Acknowledgements, stale)
		}
	}
	if !exists {
		if len(snapshot.Acknowledgements) >= MaxWindowsInboxIncidents {
			return WindowsIncidentAcknowledgement{}, ErrWindowsIncident
		}
		ack = WindowsIncidentAcknowledgement{1, target, at}
		body, e := json.Marshal(ack)
		if e != nil {
			return ack, e
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO windows_incident_acknowledgements(key,body) VALUES(?,?)", key, body); err != nil {
			return ack, err
		}
	}
	final := clock().UTC()
	if final.Before(at) || final.Year() > 9999 {
		return WindowsIncidentAcknowledgement{}, ErrWindowsIncident
	}
	if err = runPolicyGuards(ctx, []func() error{func() error { return guard(final) }}); err != nil {
		return WindowsIncidentAcknowledgement{}, err
	}
	if err = tx.Commit(); err != nil {
		return WindowsIncidentAcknowledgement{}, err
	}
	return ack, nil
}
