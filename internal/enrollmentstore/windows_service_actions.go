package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"time"
)

const windowsActionMetaSchema = `CREATE TABLE enrollment_windows_action_meta(id INTEGER PRIMARY KEY CHECK(id=1),public_key BLOB NOT NULL CHECK(length(public_key)=32)) STRICT`
const windowsActionRecordsSchema = `CREATE TABLE enrollment_windows_action_records(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=524288),setup_fence TEXT NOT NULL CHECK(length(setup_fence)=71)) STRICT`

type windowsActionSetupMarker struct {
	Version       string                `json:"version"`
	Binding       windowsaction.Binding `json:"binding"`
	InitializedAt time.Time             `json:"initializedAt"`
}

func (m windowsActionSetupMarker) digest() string {
	b, _ := json.Marshal(m)
	return windowsaction.Digest(b)
}
func validWindowsActionSetupMarker(s enrollmentstate.Snapshot, m *windowsActionSetupMarker, authorityExpiry ...int64) bool {
	notAfter := recordAuthorityExpiry(s, authorityExpiry...)
	return m == nil || s.Binding.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && s.Platform == "windows" && s.Activation.At != 0 && m.Version == "tracebolt.windows-service-action-setup.v1" && windowsaction.ValidBinding(m.Binding) && m.Binding.ManagerID == s.Binding.InstanceID && m.Binding.EndpointID == s.Approval.DeviceID && m.Binding.IncarnationDigest == "sha256:"+s.Issuance.CertificateHash && validStoreTime(m.InitializedAt) && m.InitializedAt.Unix() >= s.Activation.At && m.InitializedAt.Unix() < notAfter && (s.Termination.At == 0 || m.InitializedAt.Unix() <= s.Termination.At)
}
func windowsActionSchemaObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_windows_action_meta", SQL: windowsActionMetaSchema}, {Type: "table", Name: "enrollment_windows_action_records", SQL: windowsActionRecordsSchema}}
}
func windowsActionSchemaPresent(ctx context.Context, c *sql.Conn) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_windows_action\_%' ESCAPE '\'`).Scan(&n) != nil || n != 0 && n != 2 {
		return false, ErrStorage
	}
	return n == 2, nil
}
func windowsActionKeySeparate(t *transaction, key ed25519.PublicKey) error {
	if windowsManagedMSIKeyConflict(t, key) {
		return windowsaction.ErrBinding
	}
	digest := actionpermit.Digest(key)
	for _, credential := range t.credentials {
		if other := credential.WindowsSoftwareJobSetup; other != nil && (digest == other.Consent.Binding.KeyID || digest == other.Consent.Binding.ExecutorKeyID) {
			return windowsaction.ErrBinding
		}
	}
	return nil
}
func (s *Store) checkWindowsActionKey(ctx context.Context, t *transaction, key ed25519.PublicKey) error {
	if e := windowsActionKeySeparate(t, key); e != nil {
		return e
	}
	present, e := windowsActionSchemaPresent(ctx, t.conn)
	if e != nil {
		return e
	}
	if !present {
		return windowsaction.ErrUnavailable
	}
	var n int
	var found []byte
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_action_meta`).Scan(&n) != nil || n != 1 || t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_action_meta WHERE id=1`).Scan(&found) != nil || !bytes.Equal(key, found) {
		return ErrStorage
	}
	return nil
}

// SetupWindowsServiceActionsCreateOnly is an explicitly authorized provisioning
// seam. It creates no key or endpoint grant and is never called by startup/ingress.
// The credential marker and reciprocal row fence commit together; no adoption,
// reconstruction, reset or used-history pruning is supported.
func (s *Store) SetupWindowsServiceActionsCreateOnly(ctx context.Context, key ed25519.PublicKey, b windowsaction.Binding, now time.Time) error {
	if !keyvalidation.Ed25519(key) || !windowsaction.ValidBinding(b) || windowsaction.Digest(key) != b.KeyID || !validStoreTime(now) {
		return windowsaction.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		if e := windowsActionKeySeparate(t, key); e != nil {
			return e
		}
		present, e := windowsActionSchemaPresent(ctx, t.conn)
		if e != nil {
			return e
		}
		if present {
			return enrollmentstate.ErrConflict
		}
		for _, c := range t.credentials {
			if c.WindowsActionSetup != nil {
				return ErrStorage
			}
		}
		snap, e := systemDevice(t, b.EndpointID)
		if e != nil {
			return e
		}
		snap, e = s.windowsFullServicesAuthority(t, snap.InvitationID, t.currentCertificateHash(snap), now)
		if e != nil {
			return e
		}
		if t.credentials[snap.InvitationID].WindowsManagedMSISetup != nil || windowsManagedMSIKeyConflict(t, key) {
			return enrollmentstate.ErrConflict
		}
		marker := &windowsActionSetupMarker{"tracebolt.windows-service-action-setup.v1", b, now}
		if !validWindowsActionSetupMarker(snap, marker, t.currentCredentialNotAfter(snap)) {
			return enrollmentstate.ErrProof
		}
		r, e := windowsactionjob.New(b, key, now)
		if e != nil {
			return e
		}
		for _, o := range windowsActionSchemaObjects() {
			if _, e = t.conn.ExecContext(ctx, o.SQL); e != nil {
				return ErrStorage
			}
		}
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_action_meta VALUES(1,?)`, []byte(key)); e != nil {
			return ErrStorage
		}
		raw, _ := json.Marshal(r)
		if _, e = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_action_records VALUES(?,?,?)`, snap.InvitationID, raw, marker.digest()); e != nil {
			return ErrStorage
		}
		c := t.credentials[snap.InvitationID]
		c.WindowsActionSetup = marker
		t.credentials[snap.InvitationID] = c
		return nil
	})
}
func (s *Store) OpenWindowsServiceActions(ctx context.Context, key ed25519.PublicKey) error {
	if !keyvalidation.Ed25519(key) || s.config.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return windowsaction.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error { return s.checkWindowsActionKey(ctx, t, key) })
}
func (s *Store) loadWindowsActionRecords(ctx context.Context, t *transaction) error {
	present, e := windowsActionSchemaPresent(ctx, t.conn)
	if e != nil {
		return e
	}
	markers := map[string]*windowsActionSetupMarker{}
	for id, c := range t.credentials {
		if c.WindowsActionSetup != nil {
			markers[id] = c.WindowsActionSetup
		}
	}
	if !present {
		if len(markers) > 0 {
			return ErrStorage
		}
		return nil
	}
	if s.config.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || len(markers) == 0 {
		return ErrStorage
	}
	var key []byte
	var n, max int
	if t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_action_meta WHERE id=1`).Scan(&key) != nil || !keyvalidation.Ed25519(key) || s.checkWindowsActionKey(ctx, t, key) != nil {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(max(length(body)),0) FROM enrollment_windows_action_records`).Scan(&n, &max) != nil || n > s.config.RecordLimit || max > windowsactionjob.MaxRecordBytes {
		return ErrStorage
	}
	rows, e := t.conn.QueryContext(ctx, `SELECT invitation_id,body,setup_fence FROM enrollment_windows_action_records`)
	if e != nil {
		return ErrStorage
	}
	defer rows.Close()
	for rows.Next() {
		var id, fence string
		var raw []byte
		var r windowsactionjob.Record
		if rows.Scan(&id, &raw, &fence) != nil || windowsaction.DecodeCanonical(raw, &r, windowsactionjob.MaxRecordBytes) != nil || windowsactionjob.Validate(r) != nil || !bytes.Equal(key, r.PublicKey) {
			return ErrStorage
		}
		m := markers[id]
		if m == nil || m.digest() != fence || r.Binding != m.Binding || r.ClockFloor.Before(m.InitializedAt) || r.RejectedClockFloor != nil && r.RejectedClockFloor.Before(m.InitializedAt) {
			return ErrStorage
		}
		snap, e := t.engine.Get(id)
		// A rejection may observe time after enrollment expiry or revocation.
		// The floor is anti-rollback evidence, not renewed enrollment authority.
		if e != nil || !validWindowsActionSetupMarker(snap, m, t.currentCredentialNotAfter(snap)) || r.ClockFloor.Unix() >= t.currentCredentialNotAfter(snap) || (snap.Termination.At != 0 && r.ClockFloor.Unix() > snap.Termination.At) {
			return ErrStorage
		}
		delete(markers, id)
	}
	if rows.Err() != nil || len(markers) != 0 {
		return ErrStorage
	}
	return nil
}
func (s *Store) windowsActionTransaction(ctx context.Context, key ed25519.PublicKey, device, id, hash string, now time.Time, fn func(*windowsactionjob.Record, time.Time) error) (windowsactionjob.Record, time.Time, error) {
	return s.windowsActionTransactionExpected(ctx, key, device, id, hash, "", now, fn)
}

func (s *Store) windowsActionTransactionExpected(ctx context.Context, key ed25519.PublicKey, device, id, hash, expectedBinding string, now time.Time, fn func(*windowsactionjob.Record, time.Time) error) (windowsactionjob.Record, time.Time, error) {
	var out windowsactionjob.Record
	var operationErr error
	e := s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = overviewNow(ctx, now)
		if e != nil || !validStoreTime(now) {
			return windowsaction.ErrInvalid
		}
		if device != "" {
			snap, e := systemDevice(t, device)
			if e != nil {
				return e
			}
			id, hash = snap.InvitationID, t.currentCertificateHash(snap)
		}
		snap, e := s.windowsFullServicesAuthority(t, id, hash, now)
		if e != nil {
			return e
		}
		if e = s.checkWindowsActionKey(ctx, t, key); e != nil {
			return e
		}
		var raw []byte
		e = t.conn.QueryRowContext(ctx, `SELECT body FROM enrollment_windows_action_records WHERE invitation_id=?`, id).Scan(&raw)
		if e == sql.ErrNoRows {
			return windowsaction.ErrUnavailable
		}
		if e != nil {
			return ErrStorage
		}
		var r windowsactionjob.Record
		if windowsaction.DecodeCanonical(raw, &r, windowsactionjob.MaxRecordBytes) != nil || windowsactionjob.Validate(r) != nil || !bytes.Equal(r.PublicKey, key) || now.Before(r.EffectiveClockFloor()) {
			return ErrStorage
		}
		// Compare the complete immutable binding under the enrollment transaction,
		// before observation, preview creation, or a clock-floor write. Never fall
		// through to a replacement selected by the mutable device ID.
		if expectedBinding != "" && windowsaction.ServiceReviewBindingDigest(r.Binding) != expectedBinding {
			return windowsactionjob.ErrConflict
		}
		// Retain pre-operation bytes so a final-time rejection can commit only its
		// observed clock floor, without consuming or refreshing the saved request.
		original := bytes.Clone(raw)
		before := len(r.Jobs)
		wasClaimed := false
		if before > 0 {
			wasClaimed = r.Jobs[before-1].ClaimedAt != nil
		}
		beforePreview := r.Preview
		operationErr = fn(&r, now)
		madeReviewedPreview := expectedBinding != "" && operationErr == nil && r.Preview != nil && (beforePreview == nil || beforePreview.ID != r.Preview.ID || beforePreview.Digest != r.Preview.Digest)
		if operationErr != nil {
			// Even a stale/expired rejection advances trusted time; it cannot revive on rollback.
			if windowsaction.DecodeCanonical(raw, &r, windowsactionjob.MaxRecordBytes) != nil {
				return ErrStorage
			}
		}
		if len(r.Jobs) > before && r.Jobs[len(r.Jobs)-1].Deadline().Unix() > t.currentCredentialNotAfter(snap) {
			return windowsaction.ErrExpired
		}
		writeRecord := func() error {
			if windowsactionjob.Validate(r) != nil {
				return ErrStorage
			}
			body, e := json.Marshal(r)
			if e != nil || len(body) > windowsactionjob.MaxRecordBytes {
				return ErrStorage
			}
			result, e := t.conn.ExecContext(ctx, `UPDATE enrollment_windows_action_records SET body=? WHERE invitation_id=?`, body, id)
			if e != nil {
				return ErrStorage
			}
			n, e := result.RowsAffected()
			if e != nil || n != 1 {
				return ErrStorage
			}
			return nil
		}
		r.ClockFloor = now
		if e = writeRecord(); e != nil {
			return e
		}
		t.beforeCommit = append(t.beforeCommit, func() error {
			fresh, e := overviewNow(ctx, now)
			if e != nil || !validStoreTime(fresh) || fresh.Before(now) {
				return windowsaction.ErrInvalid
			}
			_, finalErr := s.windowsFullServicesAuthority(t, id, hash, fresh)
			if finalErr == nil && (len(r.Jobs) > before || len(r.Jobs) > 0 && !wasClaimed && r.Jobs[len(r.Jobs)-1].ClaimedAt != nil) && !fresh.Before(r.Jobs[len(r.Jobs)-1].Deadline()) {
				finalErr = windowsaction.ErrExpired
			}
			if finalErr == nil && madeReviewedPreview && !fresh.Before(r.Preview.ExpiresAt) {
				finalErr = windowsaction.ErrExpired
			}
			if finalErr != nil {
				if windowsaction.DecodeCanonical(original, &r, windowsactionjob.MaxRecordBytes) != nil {
					return ErrStorage
				}
				operationErr = finalErr
				r.RejectedClockFloor = &fresh
			} else {
				r.ClockFloor = fresh
			}
			// Returning the rejection here would roll this floor back as well.
			// Commit the original unclaimed job plus the final observation, then
			// return operationErr outside the transaction. No envelope escapes.
			if e = writeRecord(); e != nil {
				return e
			}
			if e = s.loadWindowsActionRecords(ctx, t); e != nil {
				return e
			}
			out, now = r, fresh
			return nil
		})
		out = r
		return nil
	})
	if e != nil {
		return windowsactionjob.Record{}, now, e
	}
	return out, now, operationErr
}
func (s *Store) WindowsServiceActionView(ctx context.Context, key ed25519.PublicKey, device string, now time.Time) (windowsactionjob.Record, time.Time, error) {
	return s.windowsActionTransaction(ctx, key, device, "", "", now, func(*windowsactionjob.Record, time.Time) error { return nil })
}
func (s *Store) ReportWindowsServiceActions(ctx context.Context, key ed25519.PublicKey, id, hash string, c windowsaction.Capabilities, now time.Time) error {
	_, _, e := s.windowsActionTransaction(ctx, key, "", id, hash, now, func(r *windowsactionjob.Record, now time.Time) error { return r.Report(c, now) })
	return e
}
func (s *Store) PreviewWindowsServiceAction(ctx context.Context, key ed25519.PublicKey, device, job, actor, target, op string, now time.Time) (windowsactionjob.Record, error) {
	r, _, e := s.windowsActionTransaction(ctx, key, device, "", "", now, func(r *windowsactionjob.Record, now time.Time) error {
		return r.MakePreview(job, actor, target, op, now)
	})
	return r, e
}
func (s *Store) ApproveWindowsServiceAction(ctx context.Context, key ed25519.PublicKey, device, id, digest, actor string, now time.Time, sign func(windowsaction.Permit) ([]byte, error)) (windowsactionjob.Record, error) {
	r, _, e := s.windowsActionTransaction(ctx, key, device, "", "", now, func(r *windowsactionjob.Record, now time.Time) error { return r.Approve(id, digest, actor, now, sign) })
	return r, e
}
func (s *Store) PeekWindowsServiceAction(ctx context.Context, key ed25519.PublicKey, id, hash string, now time.Time) (windowsactionjob.Delivery, error) {
	r, at, e := s.windowsActionTransaction(ctx, key, "", id, hash, now, func(*windowsactionjob.Record, time.Time) error { return nil })
	if e != nil {
		return windowsactionjob.Delivery{}, e
	}
	if len(r.Jobs) == 0 {
		return windowsactionjob.Delivery{}, windowsactionjob.ErrNotFound
	}
	j := r.Jobs[len(r.Jobs)-1]
	state := j.State(at)
	if state != "approved" && state != "claimed" && state != "needs_intervention" {
		return windowsactionjob.Delivery{}, windowsactionjob.ErrNotFound
	}
	return windowsactionjob.Delivery{Identity: j.Identity(), State: state, StartDeadline: j.Deadline()}, nil
}
func (s *Store) ClaimWindowsServiceAction(ctx context.Context, key ed25519.PublicKey, id, hash string, i windowsaction.Identity, now time.Time) (windowsactionjob.Grant, error) {
	var grant windowsactionjob.Grant
	_, _, e := s.windowsActionTransaction(ctx, key, "", id, hash, now, func(r *windowsactionjob.Record, now time.Time) error {
		var e error
		grant, e = r.Claim(i, now)
		return e
	})
	if e != nil {
		return windowsactionjob.Grant{}, e
	}
	return grant, nil
}
func (s *Store) AcceptWindowsServiceAction(ctx context.Context, key ed25519.PublicKey, id, hash string, result windowsaction.Result, now time.Time) error {
	_, _, e := s.windowsActionTransaction(ctx, key, "", id, hash, now, func(r *windowsactionjob.Record, now time.Time) error { return r.Accept(result) })
	return e
}

// WindowsServiceActionViewExpected observes only the exact reviewed binding.
// Like the ordinary view, it advances the durable clock floor but creates no action.
func (s *Store) WindowsServiceActionViewExpected(ctx context.Context, key ed25519.PublicKey, device, expectedBinding string, now time.Time) (windowsactionjob.Record, time.Time, error) {
	if !windowsaction.ValidDigest(expectedBinding) {
		return windowsactionjob.Record{}, now, windowsaction.ErrInvalid
	}
	return s.windowsActionTransactionExpected(ctx, key, device, "", "", expectedBinding, now, func(*windowsactionjob.Record, time.Time) error { return nil })
}

func (s *Store) PreviewWindowsServiceActionExpected(ctx context.Context, key ed25519.PublicKey, device, job, actor, target, op, expectedBinding string, now time.Time) (windowsactionjob.Record, error) {
	if !windowsaction.ValidDigest(expectedBinding) {
		return windowsactionjob.Record{}, windowsaction.ErrInvalid
	}
	r, _, err := s.windowsActionTransactionExpected(ctx, key, device, "", "", expectedBinding, now, func(r *windowsactionjob.Record, now time.Time) error {
		return r.MakePreview(job, actor, target, op, now)
	})
	return r, err
}
