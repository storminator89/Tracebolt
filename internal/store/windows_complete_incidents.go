package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsservicehealth"
)

// Complete-source acknowledgements have their own canonical namespace and
// storage. No v1 acknowledgement or recipient approval is inherited.
const windowsCompleteIncidentAcknowledgementsSchema = `CREATE TABLE IF NOT EXISTS windows_complete_incident_acknowledgements(key TEXT PRIMARY KEY, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=2048 AND json_valid(body)))`
const MaxWindowsCompleteInboxIncidents = windowsservicehealth.MaxDevices * windowsservicehealth.MaxIncidents

// Source is the opening observation's original local grant, not the current
// policy's binding. The embedded certificate anchor remains the issued original.
type WindowsCompleteIncidentTarget struct {
	WindowsIncidentTarget
	Source windowsservicehealth.SourceBinding `json:"source"`
}

func (v WindowsCompleteIncidentTarget) valid() bool {
	if v.Domain != "service-complete" || v.Source.Kind != windowsservicehealth.CompleteSourceKind || !windowsfullservices.ValidHex(v.Source.GrantID, 32) || !windowsfullservices.ValidSequence(v.Source.GrantRevision) {
		return false
	}
	identity := v.WindowsIncidentTarget
	identity.Domain = "service"
	return identity.valid()
}

func (v WindowsCompleteIncidentTarget) Key() string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(append([]byte("tracebolt.windows-incident-target.v2\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

type WindowsCompleteIncidentAcknowledgement struct {
	Version        int                           `json:"version"`
	Target         WindowsCompleteIncidentTarget `json:"target"`
	AcknowledgedAt time.Time                     `json:"acknowledgedAt"`
}

func decodeWindowsCompleteIncidentAcknowledgement(key string, raw []byte) (WindowsCompleteIncidentAcknowledgement, error) {
	var v WindowsCompleteIncidentAcknowledgement
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &v) != nil || v.Version != 2 || !v.Target.valid() || v.Target.Key() != key || v.AcknowledgedAt.Before(v.Target.OpenedAt) || v.AcknowledgedAt.Year() > 9999 || v.AcknowledgedAt.Location() != time.UTC {
		return v, ErrWindowsIncident
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(canonical, raw) {
		return WindowsCompleteIncidentAcknowledgement{}, ErrWindowsIncident
	}
	return v, nil
}

// A single operator transaction reads all five existing source families and both
// acknowledgement namespaces. The tagged service ledger still counts as one
// family, so combined source episodes remain bounded by MaxWindowsInboxIncidents.
type WindowsCompleteIncidentSnapshot struct {
	WindowsIncidentSnapshot
	CompleteAcknowledgements map[string]WindowsCompleteIncidentAcknowledgement
}

func (s *Store) WindowsCompleteIncidentSnapshot(ctx context.Context) (WindowsCompleteIncidentSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return WindowsCompleteIncidentSnapshot{}, err
	}
	defer tx.Rollback()
	v, err := readWindowsCompleteIncidentSnapshot(ctx, tx)
	if err != nil {
		return v, err
	}
	err = tx.Commit()
	return v, err
}

func readWindowsCompleteIncidentSnapshot(ctx context.Context, tx *sql.Tx) (WindowsCompleteIncidentSnapshot, error) {
	legacy, err := readWindowsIncidentSnapshot(ctx, tx)
	v := WindowsCompleteIncidentSnapshot{WindowsIncidentSnapshot: legacy, CompleteAcknowledgements: map[string]WindowsCompleteIncidentAcknowledgement{}}
	if err != nil {
		return v, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT key,body FROM windows_complete_incident_acknowledgements ORDER BY key LIMIT 2501")
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
		ack, e := decodeWindowsCompleteIncidentAcknowledgement(key, raw)
		if e != nil {
			return v, e
		}
		v.CompleteAcknowledgements[key] = ack
		if len(v.CompleteAcknowledgements) > MaxWindowsCompleteInboxIncidents {
			return v, ErrWindowsIncident
		}
	}
	return v, rows.Err()
}

// CompleteTargets never promotes a legacy service episode. Source-ledger decode
// has already validated each opening observation, including its native grant,
// generation identity, original capture/receipt and freshness at opening.
func (v WindowsCompleteIncidentSnapshot) CompleteTargets() map[string]WindowsCompleteIncidentTarget {
	out := map[string]WindowsCompleteIncidentTarget{}
	for id, s := range v.Services {
		if s.SchemaVersion != windowsservicehealth.CompleteStateSchema || s.DeviceID != id || s.Validate() != nil {
			continue
		}
		for _, i := range s.Incidents {
			if i.OpeningObservation.Source == nil {
				continue
			}
			target := WindowsCompleteIncidentTarget{
				WindowsIncidentTarget: WindowsIncidentTarget{DeviceID: id, InvitationID: s.InvitationID, CertificateHash: s.CertificateHash, Domain: "service-complete", IncidentID: i.ID, OpenedAt: i.OpenedAt},
				Source:                i.OpeningObservation.Source.Binding(),
			}
			if target.valid() {
				out[target.Key()] = target
			}
		}
	}
	return out
}

// AcknowledgeWindowsCompleteIncident reloads the exact retained target after the
// operator SQL wait. Only this explicit mutation may remove orphan complete
// acknowledgements. Retained acknowledgements never age out, and no source or v1
// record is changed. The caller holds its enrollment authority lease throughout.
func (s *Store) AcknowledgeWindowsCompleteIncident(ctx context.Context, target WindowsCompleteIncidentTarget, clock func() time.Time, guard func(time.Time) error) (WindowsCompleteIncidentAcknowledgement, error) {
	if !target.valid() || guard == nil || clock == nil {
		return WindowsCompleteIncidentAcknowledgement{}, ErrWindowsIncident
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WindowsCompleteIncidentAcknowledgement{}, err
	}
	defer tx.Rollback()
	admitted := clock().UTC()
	if admitted.Before(target.OpenedAt) || admitted.Year() > 9999 {
		return WindowsCompleteIncidentAcknowledgement{}, ErrWindowsIncident
	}
	if err = runPolicyGuards(ctx, []func() error{func() error { return guard(admitted) }}); err != nil {
		return WindowsCompleteIncidentAcknowledgement{}, err
	}
	snapshot, err := readWindowsCompleteIncidentSnapshot(ctx, tx)
	if err != nil {
		return WindowsCompleteIncidentAcknowledgement{}, err
	}
	targets := snapshot.CompleteTargets()
	key := target.Key()
	if current, ok := targets[key]; !ok || current != target {
		return WindowsCompleteIncidentAcknowledgement{}, ErrWindowsIncident
	}
	at := clock().UTC()
	if at.Before(admitted) || at.Year() > 9999 {
		return WindowsCompleteIncidentAcknowledgement{}, ErrWindowsIncident
	}
	ack, exists := snapshot.CompleteAcknowledgements[key]
	if exists && ack.AcknowledgedAt.After(at) {
		return WindowsCompleteIncidentAcknowledgement{}, ErrWindowsIncident
	}
	for stale := range snapshot.CompleteAcknowledgements {
		if _, retained := targets[stale]; !retained {
			if _, err = tx.ExecContext(ctx, "DELETE FROM windows_complete_incident_acknowledgements WHERE key=?", stale); err != nil {
				return WindowsCompleteIncidentAcknowledgement{}, err
			}
			delete(snapshot.CompleteAcknowledgements, stale)
		}
	}
	if !exists {
		if len(snapshot.CompleteAcknowledgements) >= MaxWindowsCompleteInboxIncidents {
			return WindowsCompleteIncidentAcknowledgement{}, ErrWindowsIncident
		}
		ack = WindowsCompleteIncidentAcknowledgement{Version: 2, Target: target, AcknowledgedAt: at}
		body, e := json.Marshal(ack)
		if e != nil {
			return WindowsCompleteIncidentAcknowledgement{}, e
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO windows_complete_incident_acknowledgements(key,body) VALUES(?,?)", key, body); err != nil {
			return WindowsCompleteIncidentAcknowledgement{}, err
		}
	}
	final := clock().UTC()
	if final.Before(at) || final.Year() > 9999 {
		return WindowsCompleteIncidentAcknowledgement{}, ErrWindowsIncident
	}
	if err = runPolicyGuards(ctx, []func() error{func() error { return guard(final) }}); err != nil {
		return WindowsCompleteIncidentAcknowledgement{}, err
	}
	if err = tx.Commit(); err != nil {
		return WindowsCompleteIncidentAcknowledgement{}, err
	}
	return ack, nil
}
