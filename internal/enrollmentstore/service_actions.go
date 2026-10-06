package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/keyvalidation"
	"time"
)

const serviceActionMetaSchema = `CREATE TABLE enrollment_service_action_meta(id INTEGER PRIMARY KEY CHECK(id=1),public_key BLOB NOT NULL CHECK(length(public_key)=32)) STRICT`

// Legacy records remain readable. New setup uses a distinct schema so missing
// credential markers cannot make fenced records appear to be legacy records.
const serviceActionFencedRecordsSchema = `CREATE TABLE enrollment_service_action_records(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=524288),setup_fence TEXT NOT NULL CHECK(length(setup_fence)=71)) STRICT`
const serviceActionRecordsSchema = `CREATE TABLE enrollment_service_action_records(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=524288)) STRICT`

func serviceActionSchemaObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_service_action_meta", SQL: serviceActionMetaSchema}, {Type: "table", Name: "enrollment_service_action_records", SQL: serviceActionRecordsSchema}}
}
func serviceActionFencedSchemaObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_service_action_meta", SQL: serviceActionMetaSchema}, {Type: "table", Name: "enrollment_service_action_records", SQL: serviceActionFencedRecordsSchema}}
}
func existingServiceActionSchemaObjects(ctx context.Context, c *sql.Conn) ([]inventoryledger.SchemaObject, error) {
	var definition string
	if c.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='enrollment_service_action_records'`).Scan(&definition) != nil {
		return nil, ErrStorage
	}
	switch definition {
	case serviceActionRecordsSchema:
		return serviceActionSchemaObjects(), nil
	case serviceActionFencedRecordsSchema:
		return serviceActionFencedSchemaObjects(), nil
	default:
		return nil, ErrStorage
	}
}
func serviceActionFenced(ctx context.Context, c *sql.Conn) (bool, error) {
	objects, err := existingServiceActionSchemaObjects(ctx, c)
	if err != nil {
		return false, err
	}
	return objects[1].SQL == serviceActionFencedRecordsSchema, nil
}
func serviceActionSchemaPresent(ctx context.Context, c *sql.Conn) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_service_action\_%' ESCAPE '\'`).Scan(&n) != nil {
		return false, ErrStorage
	}
	if n == 0 {
		return false, nil
	}
	if n != 2 {
		return false, ErrStorage
	}
	return true, nil
}

// InitializeServiceActions is the legacy provisioning seam retained for
// existing library/fixture callers. New guided setup must instead use
// SetupServiceActionsCreateOnly for the durable credential fence. Neither seam
// is called by runtime startup or ingress. Missing live state is not permission
// to recreate it or reset its job floors. This function creates no keys.
func (s *Store) InitializeServiceActions(ctx context.Context, key ed25519.PublicKey) error {
	if !keyvalidation.Ed25519(key) {
		return actionjob.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		if !completeProfile(s.config.Binding.CollectionProfile) {
			return enrollmentstate.ErrProof
		}
		present, e := serviceActionSchemaPresent(ctx, t.conn)
		if e != nil {
			return e
		}
		if !present {
			for _, o := range serviceActionSchemaObjects() {
				if _, e = t.conn.ExecContext(ctx, o.SQL); e != nil {
					return ErrStorage
				}
			}
			if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_service_action_meta VALUES(1,?)`, []byte(key)); e != nil {
				return ErrStorage
			}
		}
		return s.checkServiceActionKey(ctx, t, key)
	})
}
func (s *Store) checkServiceActionKey(ctx context.Context, t *transaction, key ed25519.PublicKey) error {
	present, e := serviceActionSchemaPresent(ctx, t.conn)
	if e != nil {
		return e
	}
	if !present {
		return actionjob.ErrUnavailable
	}
	var found []byte
	var n int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_service_action_meta`).Scan(&n) != nil || n != 1 || t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_service_action_meta WHERE id=1`).Scan(&found) != nil || !bytes.Equal(found, key) {
		return ErrStorage
	}
	return nil
}
func (s *Store) OpenServiceActions(ctx context.Context, key ed25519.PublicKey) error {
	if !keyvalidation.Ed25519(key) {
		return actionjob.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error { return s.checkServiceActionKey(ctx, t, key) })
}
func (s *Store) loadServiceActionRecords(ctx context.Context, t *transaction) error {
	present, e := serviceActionSchemaPresent(ctx, t.conn)
	if e != nil {
		return e
	}
	markers := map[string]*serviceActionSetupMarker{}
	for id, credential := range t.credentials {
		if credential.ServiceActionSetup != nil {
			markers[id] = credential.ServiceActionSetup
		}
	}
	if !present {
		if len(markers) != 0 {
			return ErrStorage
		}
		return nil
	}
	fenced, e := serviceActionFenced(ctx, t.conn)
	if e != nil || (!fenced && len(markers) != 0) || (fenced && len(markers) == 0) {
		return ErrStorage
	}
	var key []byte
	var n, max int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_service_action_meta`).Scan(&n) != nil || n != 1 || t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_service_action_meta WHERE id=1`).Scan(&key) != nil || !keyvalidation.Ed25519(key) {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(max(length(body)),0) FROM enrollment_service_action_records`).Scan(&n, &max) != nil || n > s.config.RecordLimit || max > actionjob.MaxRecordBytes {
		return ErrStorage
	}
	query := `SELECT invitation_id,body,'' FROM enrollment_service_action_records`
	if fenced {
		query = `SELECT invitation_id,body,setup_fence FROM enrollment_service_action_records`
	}
	rows, e := t.conn.QueryContext(ctx, query)
	if e != nil {
		return ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		var id, fence string
		var b []byte
		var r actionjob.Record
		if rows.Scan(&id, &b, &fence) != nil || len(b) == 0 || len(b) > actionjob.MaxRecordBytes || json.Unmarshal(b, &r) != nil || actionjob.Validate(r) != nil || !bytes.Equal(r.PublicKey, key) {
			return ErrStorage
		}
		canonical, _ := json.Marshal(r)
		snap, e := t.engine.Get(id)
		if e != nil || !bytes.Equal(b, canonical) || r.ManagerID != s.config.Binding.InstanceID || r.DeviceID != snap.Approval.DeviceID || r.IncarnationDigest != "sha256:"+snap.Issuance.CertificateHash || snap.Activation.At == 0 || r.ClockFloor.Unix() < snap.Activation.At || r.ClockFloor.Unix() >= snap.Intent.NotAfter || (snap.Termination.At != 0 && r.ClockFloor.Unix() > snap.Termination.At) {
			return ErrStorage
		}
		if fenced {
			marker := markers[id]
			if marker == nil || marker.KeyID != actionpermit.Digest(key) || marker.digest() != fence || r.ClockFloor.Before(marker.InitializedAt) {
				return ErrStorage
			}
			delete(markers, id)
		}
	}
	if rows.Err() != nil || len(markers) != 0 {
		return ErrStorage
	}
	return nil
}
func (s *Store) readServiceAction(ctx context.Context, t *transaction, snap enrollmentstate.Snapshot, key ed25519.PublicKey, now time.Time) (actionjob.Record, error) {
	if e := s.checkServiceActionKey(ctx, t, key); e != nil {
		return actionjob.Record{}, e
	}
	var b []byte
	e := t.conn.QueryRowContext(ctx, `SELECT body FROM enrollment_service_action_records WHERE invitation_id=?`, snap.InvitationID).Scan(&b)
	if e == sql.ErrNoRows {
		return actionjob.Record{}, actionjob.ErrUnavailable
	}
	if e != nil {
		return actionjob.Record{}, ErrStorage
	}
	var r actionjob.Record
	if json.Unmarshal(b, &r) != nil || actionjob.Validate(r) != nil || !bytes.Equal(r.PublicKey, key) || r.ManagerID != s.config.Binding.InstanceID || r.DeviceID != snap.Approval.DeviceID || r.IncarnationDigest != "sha256:"+snap.Issuance.CertificateHash || now.Before(r.ClockFloor) {
		return actionjob.Record{}, ErrStorage
	}
	return r, nil
}

// InitializeServiceActionIdentity is the legacy separately authorized identity
// provisioning seam. New setup must use SetupServiceActionsCreateOnly. No
// manager/agent/API/runtime calls it; recovery of lost live rows is unsupported.
func (s *Store) InitializeServiceActionIdentity(ctx context.Context, key ed25519.PublicKey, device string, now time.Time) error {
	return s.transact(ctx, func(t *transaction) error {
		if e := s.checkServiceActionKey(ctx, t, key); e != nil {
			return e
		}
		snap, e := systemDevice(t, device)
		if e != nil {
			return e
		}
		if _, e = s.systemAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now); e != nil {
			return e
		}
		r, e := actionjob.New(s.config.Binding.InstanceID, device, "sha256:"+snap.Issuance.CertificateHash, key, now)
		if e != nil {
			return e
		}
		b, _ := json.Marshal(r)
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_service_action_records VALUES(?,?)`, snap.InvitationID, b); e != nil {
			return ErrStorage
		}
		return nil
	})
}
func saveServiceAction(ctx context.Context, t *transaction, id string, r actionjob.Record) error {
	if actionjob.Validate(r) != nil {
		return actionjob.ErrInvalid
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > actionjob.MaxRecordBytes {
		return actionjob.ErrCapacity
	}
	result, e := t.conn.ExecContext(ctx, `UPDATE enrollment_service_action_records SET body=? WHERE invitation_id=?`, b, id)
	if e != nil {
		return ErrStorage
	}
	n, e := result.RowsAffected()
	if e != nil || n != 1 {
		return ErrStorage
	}
	return nil
}

func (s *Store) serviceActionTransaction(ctx context.Context, key ed25519.PublicKey, device, id, hash string, now time.Time, change bool, fn func(*actionjob.Record) error) (actionjob.Record, error) {
	var out actionjob.Record
	var operationErr error
	e := s.transact(ctx, func(t *transaction) error {
		var snap enrollmentstate.Snapshot
		var e error
		if device != "" {
			snap, e = systemDevice(t, device)
			if e != nil {
				return e
			}
			id, hash = snap.InvitationID, snap.Issuance.CertificateHash
		}
		snap, e = s.systemAuthority(t, id, hash, now)
		if e != nil {
			return e
		}
		r, e := s.readServiceAction(ctx, t, snap, key, now)
		if e != nil {
			return e
		}
		operationErr = fn(&r)
		if operationErr != nil && !errors.Is(operationErr, actionjob.ErrExpired) {
			return operationErr
		}
		expired := r.ObserveExpiry(now)
		if (change && operationErr == nil) || expired {
			if e = saveServiceAction(ctx, t, id, r); e != nil {
				return e
			}
		}
		out = r
		return nil
	})
	if e != nil {
		return actionjob.Record{}, e
	}
	if operationErr != nil {
		return actionjob.Record{}, operationErr
	}
	return out, nil
}

func (s *Store) ServiceActionView(ctx context.Context, key ed25519.PublicKey, device string, now time.Time) (actionjob.Record, error) {
	return s.serviceActionTransaction(ctx, key, device, "", "", now, false, func(*actionjob.Record) error { return nil })
}
func (s *Store) ReportServiceActions(ctx context.Context, key ed25519.PublicKey, id, hash string, c actionhelper.Capabilities, now time.Time) error {
	_, e := s.serviceActionTransaction(ctx, key, "", id, hash, now, true, func(r *actionjob.Record) error { return r.Report(c, now) })
	return e
}
func (s *Store) PreviewServiceAction(ctx context.Context, key ed25519.PublicKey, device, job, actor, unit, profile string, now time.Time) (actionjob.Record, error) {
	return s.serviceActionTransaction(ctx, key, device, "", "", now, true, func(r *actionjob.Record) error { _, e := r.MakePreview(job, actor, unit, profile, now); return e })
}
func (s *Store) ApproveServiceAction(ctx context.Context, key ed25519.PublicKey, device, id, digest, actor, profile string, now time.Time, sign func(actionpermit.Permit) ([]byte, error)) (actionjob.Record, error) {
	return s.serviceActionTransaction(ctx, key, device, "", "", now, true, func(r *actionjob.Record) error { _, e := r.Approve(id, digest, actor, profile, now, sign); return e })
}
func (s *Store) PeekServiceAction(ctx context.Context, key ed25519.PublicKey, id, hash string, now time.Time) (actionjob.Delivery, error) {
	r, e := s.serviceActionTransaction(ctx, key, "", id, hash, now, false, func(*actionjob.Record) error { return nil })
	if e != nil {
		return actionjob.Delivery{}, e
	}
	if len(r.Jobs) == 0 {
		return actionjob.Delivery{}, actionjob.ErrNotFound
	}
	j := r.Jobs[len(r.Jobs)-1]
	state := j.State(now)
	if state != actionjob.Approved && state != actionjob.Claimed {
		return actionjob.Delivery{}, actionjob.ErrNotFound
	}
	return actionjob.Delivery{Identity: j.Identity(), State: state, StartDeadline: j.Deadline()}, nil
}
func (s *Store) ClaimServiceAction(ctx context.Context, key ed25519.PublicKey, id, hash, profile string, identity actionjob.Identity, now time.Time) (actionjob.Grant, error) {
	var grant actionjob.Grant
	_, e := s.serviceActionTransaction(ctx, key, "", id, hash, now, true, func(r *actionjob.Record) error { var e error; grant, e = r.Claim(identity, profile, now); return e })
	if e != nil {
		return actionjob.Grant{}, e
	}
	return grant, nil
}
func (s *Store) AcceptServiceAction(ctx context.Context, key ed25519.PublicKey, id, hash string, result actionhelper.Result, now time.Time) error {
	_, e := s.serviceActionTransaction(ctx, key, "", id, hash, now, true, func(r *actionjob.Record) error { return r.Accept(result, now) })
	return e
}
