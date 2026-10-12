package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/windowsmanagedmsi"
)

const windowsManagedMSIMetaSchema = `CREATE TABLE enrollment_windows_managed_msi_meta(id INTEGER PRIMARY KEY CHECK(id=1),public_key BLOB NOT NULL CHECK(length(public_key)=32)) STRICT`
const windowsManagedMSIRecordsSchema = `CREATE TABLE enrollment_windows_managed_msi_records(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=262144),setup_fence TEXT NOT NULL CHECK(length(setup_fence)=71),rejected_clock_floor INTEGER NOT NULL CHECK(rejected_clock_floor>=0 AND rejected_clock_floor<=253402300799)) STRICT`

type windowsManagedMSISetupMarker struct {
	Version       string                  `json:"version"`
	Grant         windowsmanagedmsi.Grant `json:"grant"`
	InitializedAt time.Time               `json:"initializedAt"`
}

func (m windowsManagedMSISetupMarker) digest() string {
	raw, _ := json.Marshal(m)
	return actionpermit.Digest(append([]byte("Tracebolt enrollment managed MSI setup v1\x00"), raw...))
}

func validWindowsManagedMSISetupMarker(s enrollmentstate.Snapshot, m *windowsManagedMSISetupMarker, authorityExpiry ...int64) bool {
	if m == nil {
		return true
	}
	c, b := m.Grant, m.Grant.Binding
	return s.Binding.Profile == "tls" && s.Binding.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && s.Platform == "windows" && s.Activation.At != 0 && m.Version == "tracebolt.windows-managed-msi-setup.v1" && c.Validate() == nil && c.DeliveryEnabled && c.DeliveryAcknowledged && c.ServiceRiskAcknowledged && b.ManagerID == s.Binding.InstanceID && b.DeviceID == s.Approval.DeviceID && b.IncarnationDigest == "sha256:"+s.Issuance.CertificateHash && validStoreTime(m.InitializedAt) && m.InitializedAt.Unix() >= s.Activation.At && m.InitializedAt.Unix() < recordAuthorityExpiry(s, authorityExpiry...) && m.InitializedAt.Unix() < c.ExpiresAt && (s.Termination.At == 0 || m.InitializedAt.Unix() <= s.Termination.At)
}

func windowsManagedMSISchemaObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_windows_managed_msi_meta", SQL: windowsManagedMSIMetaSchema}, {Type: "table", Name: "enrollment_windows_managed_msi_records", SQL: windowsManagedMSIRecordsSchema}}
}
func windowsManagedMSISchemaPresent(ctx context.Context, c *sql.Conn) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_windows_managed_msi\_%' ESCAPE '\'`).Scan(&n) != nil || n != 0 && n != 2 {
		return false, ErrStorage
	}
	return n == 2, nil
}
func (s *Store) checkWindowsManagedMSIKey(ctx context.Context, t *transaction, key ed25519.PublicKey) error {
	present, err := windowsManagedMSISchemaPresent(ctx, t.conn)
	if err != nil {
		return err
	}
	if !present {
		return windowsmanagedmsi.ErrUnavailable
	}
	var n int
	var found []byte
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_managed_msi_meta`).Scan(&n) != nil || n != 1 || t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_managed_msi_meta WHERE id=1`).Scan(&found) != nil {
		return ErrStorage
	}
	if !bytes.Equal(key, found) {
		return windowsmanagedmsi.ErrAuthority
	}
	return nil
}

// Both action keys are externally supplied and separate from each other, all
// enrollment/issuer keys, and the already-established service-control domain.
func (s *Store) windowsManagedMSIKeysDistinct(ctx context.Context, t *transaction, manager, executor ed25519.PublicKey) error {
	if !keyvalidation.Ed25519(manager) || !keyvalidation.Ed25519(executor) || bytes.Equal(manager, executor) {
		return windowsmanagedmsi.ErrAuthority
	}
	certs := [][]byte{s.issuerDER}
	for _, c := range t.credentials {
		if c.WindowsUpdateJobSetup != nil {
			old := c.WindowsUpdateJobSetup.Consent.Binding
			for _, digest := range []string{old.KeyID, old.ExecutorKeyID} {
				if digest == actionpermit.Digest(manager) || digest == actionpermit.Digest(executor) {
					return windowsmanagedmsi.ErrAuthority
				}
			}
		}
		if c.WindowsSoftwareJobSetup != nil {
			old := c.WindowsSoftwareJobSetup.Consent.Binding
			for _, digest := range []string{old.KeyID, old.ExecutorKeyID} {
				if digest == actionpermit.Digest(manager) || digest == actionpermit.Digest(executor) {
					return windowsmanagedmsi.ErrAuthority
				}
			}
		}
		certs = append(certs, c.DER)
	}
	for _, der := range certs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return ErrStorage
		}
		if key, ok := cert.PublicKey.(ed25519.PublicKey); ok && (bytes.Equal(manager, key) || bytes.Equal(executor, key)) {
			return windowsmanagedmsi.ErrAuthority
		}
	}
	present, err := windowsActionSchemaPresent(ctx, t.conn)
	if err != nil {
		return err
	}
	if present {
		var key []byte
		if t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_action_meta WHERE id=1`).Scan(&key) != nil {
			return ErrStorage
		}
		if bytes.Equal(manager, key) || bytes.Equal(executor, key) {
			return windowsmanagedmsi.ErrAuthority
		}
	}
	return nil
}

// SetupWindowsManagedMSICreateOnly is an explicitly approved source provisioning
// seam, never startup, API, or recovery. No key, executor, or host grant is made.
// Its immutable credential marker and reciprocal row are committed together.
func (s *Store) SetupWindowsManagedMSICreateOnly(ctx context.Context, key, executorKey ed25519.PublicKey, consent windowsmanagedmsi.Grant, now time.Time) error {
	return s.setupWindowsManagedMSICreateOnly(ctx, key, executorKey, consent, now, false)
}

func (s *Store) setupWindowsManagedMSICreateOnly(ctx context.Context, key, executorKey ed25519.PublicKey, consent windowsmanagedmsi.Grant, now time.Time, additional bool) error {
	if s == nil || s.storeState == nil || ctx == nil || !validStoreTime(now) || consent.Validate() != nil || !consent.DeliveryEnabled || !consent.DeliveryAcknowledged || !consent.ServiceRiskAcknowledged || !keyvalidation.Ed25519(key) || !keyvalidation.Ed25519(executorKey) || consent.Binding.KeyID != actionpermit.Digest(key) || consent.Binding.ExecutorKeyID != actionpermit.Digest(executorKey) {
		return windowsmanagedmsi.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		present, err := windowsManagedMSISchemaPresent(ctx, t.conn)
		if err != nil {
			return err
		}
		if present != additional {
			return windowsmanagedmsi.ErrConflict
		}
		for _, c := range t.credentials {
			if c.WindowsManagedMSISetup != nil {
				return ErrStorage
			}
		}
		if err = s.windowsManagedMSIKeysDistinct(ctx, t, key, executorKey); err != nil {
			return err
		}
		now, err = windowsManagedMSINow(ctx, now)
		if err != nil {
			return err
		}
		snap, err := systemDevice(t, consent.Binding.DeviceID)
		if err != nil {
			return windowsmanagedmsi.ErrAuthority
		}
		if c := t.credentials[snap.InvitationID]; c.WindowsActionSetup != nil || c.WindowsUpdateJobSetup != nil || c.WindowsSoftwareJobSetup != nil {
			return windowsmanagedmsi.ErrConflict
		}
		marker := &windowsManagedMSISetupMarker{Version: "tracebolt.windows-managed-msi-setup.v1", Grant: consent, InitializedAt: now}
		if !validWindowsManagedMSISetupMarker(snap, marker, t.currentCredentialNotAfter(snap)) {
			return windowsmanagedmsi.ErrAuthority
		}
		issuer, err := x509.ParseCertificate(s.issuerDER)
		if err != nil || consent.ExpiresAt > issuer.NotAfter.Unix() {
			return windowsmanagedmsi.ErrAuthority
		}
		current, err := s.windowsManagedMSICurrent(t, snap.InvitationID, consent.Binding, consent, now)
		if err != nil {
			return err
		}
		if err = checkWindowsManagedMSISetupExpectedLeaf(ctx, current); err != nil {
			return err
		}
		r, err := windowsmanagedmsi.NewRecord(consent, key, executorKey, now.Unix())
		if err != nil {
			return err
		}
		if !additional {
			for _, obj := range windowsManagedMSISchemaObjects() {
				if _, err = t.conn.ExecContext(ctx, obj.SQL); err != nil {
					return ErrStorage
				}
			}
			if _, err = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_managed_msi_meta VALUES(1,?)`, []byte(key)); err != nil {
				return ErrStorage
			}
		}
		raw, err := windowsmanagedmsi.EncodeRecord(r)
		if err != nil {
			return err
		}
		if _, err = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_managed_msi_records VALUES(?,?,?,0)`, snap.InvitationID, raw, marker.digest()); err != nil {
			return ErrStorage
		}
		c := t.credentials[snap.InvitationID]
		c.WindowsManagedMSISetup = marker
		t.credentials[snap.InvitationID] = c
		t.beforeCommit = append(t.beforeCommit, func() error {
			// Protected review inputs may block on reads. Check them before the
			// last fresh clock/current-authority sample, never after it.
			if err := windowsmanagedmsi.CheckFinal(ctx); err != nil {
				return err
			}
			fresh, err := windowsManagedMSINow(ctx, now)
			if err != nil || fresh.Before(now) {
				return windowsmanagedmsi.ErrExpired
			}
			final, err := s.windowsManagedMSICurrent(t, snap.InvitationID, consent.Binding, consent, fresh)
			if err != nil {
				return err
			}
			if final != current {
				return windowsmanagedmsi.ErrAuthority
			}
			return nil
		})
		return nil
	})
}

// OpenWindowsManagedMSI validates only existing fenced state. It never creates,
// adopts, or reconstructs a missing table, marker, consent, key, row, or history.
func (s *Store) OpenWindowsManagedMSI(ctx context.Context, key ed25519.PublicKey) error {
	if s == nil || s.storeState == nil || ctx == nil || !keyvalidation.Ed25519(key) {
		return windowsmanagedmsi.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error { return s.checkWindowsManagedMSIKey(ctx, t, key) })
}

func (s *Store) loadWindowsManagedMSIRecords(ctx context.Context, t *transaction) error {
	present, err := windowsManagedMSISchemaPresent(ctx, t.conn)
	if err != nil {
		return err
	}
	markers := map[string]*windowsManagedMSISetupMarker{}
	for id, c := range t.credentials {
		if c.WindowsManagedMSISetup != nil {
			if c.WindowsActionSetup != nil || c.WindowsUpdateJobSetup != nil || c.WindowsSoftwareJobSetup != nil {
				return ErrStorage
			}
			markers[id] = c.WindowsManagedMSISetup
		}
	}
	if !present {
		if len(markers) != 0 {
			return ErrStorage
		}
		return nil
	}
	if s.config.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || s.config.Binding.Profile != "tls" || len(markers) == 0 {
		return ErrStorage
	}
	var key []byte
	var n, maxBytes int
	if t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_managed_msi_meta WHERE id=1`).Scan(&key) != nil || !keyvalidation.Ed25519(key) || s.checkWindowsManagedMSIKey(ctx, t, key) != nil {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(max(length(body)),0) FROM enrollment_windows_managed_msi_records`).Scan(&n, &maxBytes) != nil || n != 1 || maxBytes > windowsmanagedmsi.MaxRecordBytes {
		return ErrStorage
	}
	issuer, err := x509.ParseCertificate(s.issuerDER)
	if err != nil {
		return ErrStorage
	}
	rows, err := t.conn.QueryContext(ctx, `SELECT invitation_id,body,setup_fence,rejected_clock_floor FROM enrollment_windows_managed_msi_records`)
	if err != nil {
		return ErrStorage
	}
	defer rows.Close()
	executors, devices, grants, executorIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var id, fence string
		var raw []byte
		var rejected int64
		if rows.Scan(&id, &raw, &fence, &rejected) != nil {
			return ErrStorage
		}
		r, err := windowsmanagedmsi.DecodeRecord(raw)
		m := markers[id]
		if err != nil || m == nil || m.digest() != fence || m.Grant != r.Grant || !bytes.Equal(key, r.PublicKey) || r.ClockFloor < m.InitializedAt.Unix() || rejected != 0 && (rejected < m.InitializedAt.Unix() || rejected > enrollmentstate.MaxTimestamp) || r.Grant.ExpiresAt > issuer.NotAfter.Unix() {
			return ErrStorage
		}
		snap, err := t.engine.Get(id)
		// Rejected observations may outlive the leaf or revocation. They carry
		// no successful-job authority and must never invalidate durable history.
		if err != nil || !validWindowsManagedMSISetupMarker(snap, m, t.currentCredentialNotAfter(snap)) || r.ClockFloor >= t.currentCredentialNotAfter(snap) || r.ClockFloor >= r.Grant.ExpiresAt || snap.Termination.At != 0 && r.ClockFloor > snap.Termination.At {
			return ErrStorage
		}
		if err = s.windowsManagedMSIKeysDistinct(ctx, t, key, r.ExecutorPublicKey); err != nil {
			return ErrStorage
		}
		b := r.Grant.Binding
		if executors[b.ExecutorKeyID] || devices[b.DeviceID] || grants[b.DeliveryGrantID] || executorIDs[b.ExecutorID] {
			return ErrStorage
		}
		executors[b.ExecutorKeyID], devices[b.DeviceID], grants[b.DeliveryGrantID], executorIDs[b.ExecutorID] = true, true, true, true
		delete(markers, id)
	}
	if rows.Err() != nil || len(markers) != 0 {
		return ErrStorage
	}
	return nil
}

func windowsManagedMSINow(ctx context.Context, fallback time.Time) (time.Time, error) {
	if ctx == nil || !validStoreTime(fallback) {
		return time.Time{}, windowsmanagedmsi.ErrInvalid
	}
	if clock, ok := ctx.Value(overviewClockKey{}).(overviewTrustedClock); ok {
		if clock.now == nil {
			return time.Time{}, windowsmanagedmsi.ErrInvalid
		}
		fallback = clock.now()
	}
	if !validStoreTime(fallback) {
		return time.Time{}, windowsmanagedmsi.ErrInvalid
	}
	return fallback.UTC(), nil
}

func (s *Store) windowsManagedMSICurrent(t *transaction, id string, binding windowsmanagedmsi.Binding, consent windowsmanagedmsi.Grant, now time.Time) (windowsmanagedmsi.Current, error) {
	var current windowsmanagedmsi.Current
	snap, err := t.engine.Get(id)
	if err != nil || snap.Binding.Profile != "tls" || snap.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || snap.Platform != "windows" || binding != consent.Binding || binding.ManagerID != snap.Binding.InstanceID || binding.DeviceID != snap.Approval.DeviceID || binding.IncarnationDigest != "sha256:"+snap.Issuance.CertificateHash {
		return current, windowsmanagedmsi.ErrAuthority
	}
	c, ok := t.credentials[id]
	if !ok {
		return current, ErrStorage
	}
	intent, _, hash, err := t.currentCredential(snap, c)
	if err != nil {
		return current, err
	}
	current = windowsmanagedmsi.Current{Binding: binding, LeafDigest: "sha256:" + hash, LeafGeneration: 1, LeafNotBefore: intent.NotBefore, LeafNotAfter: intent.NotAfter, Revoked: snap.State != enrollmentstate.Activated, Enabled: consent.DeliveryEnabled && consent.DeliveryAcknowledged && consent.ServiceRiskAcknowledged}
	if c.Renewal != nil {
		current.LeafGeneration = c.Renewal.Current.Generation
	}
	if current.Revoked || !current.Enabled {
		return current, windowsmanagedmsi.ErrAuthority
	}
	if !validStoreTime(now) || now.Unix() >= consent.ExpiresAt {
		return current, windowsmanagedmsi.ErrExpired
	}
	if err = t.authorizeCurrentCredential(snap, hash, now); err != nil {
		if errors.Is(err, enrollmentstate.ErrExpired) || errors.Is(err, enrollmentstate.ErrInvalid) {
			return current, windowsmanagedmsi.ErrExpired
		}
		if errors.Is(err, ErrStorage) {
			return current, err
		}
		return current, windowsmanagedmsi.ErrAuthority
	}
	return current, nil
}

func windowsManagedMSITransition(before, after windowsmanagedmsi.Record, now int64) error {
	if after.ClockFloor > now {
		return windowsmanagedmsi.ErrInvalid
	}
	return windowsmanagedmsi.Transition(before, after)
}
func windowsManagedMSIFinalDeadline(before, after windowsmanagedmsi.Record, current windowsmanagedmsi.Current, fresh int64) error {
	return windowsmanagedmsi.FinalDeadline(before, after, current, fresh)
}

// WindowsManagedMSITransaction owns both job writes and current enrollment
// authority in one transaction. No signed envelope may escape on a non-nil error.
// Business rejections commit only a monotonic observation floor, never rejected
// callback mutations. Persistence uncertainty is returned without automatic retry.
func (s *Store) WindowsManagedMSITransaction(ctx context.Context, binding windowsmanagedmsi.Binding, key ed25519.PublicKey, now time.Time, fn func(*windowsmanagedmsi.Record, windowsmanagedmsi.Current, time.Time) error) (windowsmanagedmsi.Record, time.Time, error) {
	var out windowsmanagedmsi.Record
	if s == nil || s.storeState == nil || ctx == nil || fn == nil || !windowsmanagedmsi.ValidBinding(binding) || !keyvalidation.Ed25519(key) || !validStoreTime(now) {
		return out, now, windowsmanagedmsi.ErrInvalid
	}
	var operationErr error
	writeStarted := false
	err := s.transact(ctx, func(t *transaction) error {
		if err := s.checkWindowsManagedMSIKey(ctx, t, key); err != nil {
			return err
		}
		snap, err := systemDevice(t, binding.DeviceID)
		if err != nil {
			return windowsmanagedmsi.ErrAuthority
		}
		var raw []byte
		var rejected int64
		if err = t.conn.QueryRowContext(ctx, `SELECT body,rejected_clock_floor FROM enrollment_windows_managed_msi_records WHERE invitation_id=?`, snap.InvitationID).Scan(&raw, &rejected); err == sql.ErrNoRows {
			return windowsmanagedmsi.ErrUnavailable
		} else if err != nil {
			return ErrStorage
		}
		original, err := windowsmanagedmsi.DecodeRecord(raw)
		if err != nil {
			return ErrStorage
		}
		r, err := windowsmanagedmsi.DecodeRecord(raw)
		if err != nil {
			return ErrStorage
		}
		initial, err := windowsManagedMSINow(ctx, now)
		if err != nil {
			return err
		}
		floor := max(original.ClockFloor, rejected)
		current, authorityErr := s.windowsManagedMSICurrent(t, snap.InvitationID, binding, original.Grant, initial)
		if initial.Before(now) || initial.Unix() < floor {
			operationErr = windowsmanagedmsi.ErrExpired
		} else {
			operationErr = authorityErr
		}
		if errors.Is(operationErr, ErrStorage) {
			return operationErr
		}
		if operationErr == nil {
			r.ClockFloor = initial.Unix()
			operationErr = fn(&r, current, initial)
			if operationErr == nil {
				operationErr = windowsManagedMSITransition(original, r, initial.Unix())
			}
			if operationErr == nil && r.Validate() != nil {
				operationErr = windowsmanagedmsi.ErrInvalid
			}
		}
		// Persistence is deferred until the final authority check. The common
		// transaction still validates all unrelated credentials and used state.
		t.beforeCommit = append(t.beforeCommit, func() error {
			fresh, clockErr := windowsManagedMSINow(ctx, initial)
			observed := max(floor, initial.Unix())
			if clockErr == nil {
				observed = max(observed, fresh.Unix())
			}
			if clockErr != nil {
				operationErr = clockErr
			} else if fresh.Before(initial) || fresh.Unix() < floor {
				operationErr = windowsmanagedmsi.ErrExpired
			}
			if operationErr == nil {
				final, err := s.windowsManagedMSICurrent(t, snap.InvitationID, binding, original.Grant, fresh)
				if errors.Is(err, ErrStorage) {
					return err
				}
				if err != nil {
					operationErr = err
				} else if final != current {
					operationErr = windowsmanagedmsi.ErrAuthority
				} else {
					operationErr = windowsManagedMSIFinalDeadline(original, r, final, fresh.Unix())
				}
			}
			if operationErr == nil {
				operationErr = windowsmanagedmsi.CheckFinal(ctx)
				// Configuration reads and the session fence can block or reject.
				// Retain their last observed time even on rejection.
				last, clockErr := windowsManagedMSINow(ctx, fresh)
				if clockErr != nil || last.Before(fresh) {
					operationErr = windowsmanagedmsi.ErrExpired
				} else {
					fresh = last
					observed = max(observed, last.Unix())
					if operationErr == nil {
						final, authorityErr := s.windowsManagedMSICurrent(t, snap.InvitationID, binding, original.Grant, last)
						if authorityErr != nil {
							operationErr = authorityErr
						} else if final != current {
							operationErr = windowsmanagedmsi.ErrAuthority
						} else {
							operationErr = windowsManagedMSIFinalDeadline(original, r, final, last.Unix())
						}
					}
				}
			}
			if operationErr != nil {
				r, err = windowsmanagedmsi.DecodeRecord(raw)
				if err != nil {
					return ErrStorage
				}
				rejected = observed
			} else {
				r.ClockFloor = fresh.Unix()
			}
			body, err := windowsmanagedmsi.EncodeRecord(r)
			if err != nil {
				return ErrStorage
			}
			if s.checkPath() != nil {
				return ErrStorage
			}
			writeStarted = true
			result, err := t.conn.ExecContext(ctx, `UPDATE enrollment_windows_managed_msi_records SET body=?,rejected_clock_floor=? WHERE invitation_id=?`, body, rejected, snap.InvitationID)
			if err != nil {
				return ErrStorage
			}
			if n, err := result.RowsAffected(); err != nil || n != 1 {
				return ErrStorage
			}
			if err = s.loadWindowsManagedMSIRecords(ctx, t); err != nil {
				return err
			}
			if s.checkPath() != nil {
				return ErrStorage
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			now = time.Unix(observed, 0).UTC()
			out = r
			return nil
		})
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrStorage) || writeStarted {
			return windowsmanagedmsi.Record{}, now, windowsmanagedmsi.ErrUncertain
		}
		return windowsmanagedmsi.Record{}, now, err
	}
	if operationErr != nil {
		return windowsmanagedmsi.Record{}, now, operationErr
	}
	return out, now, nil
}

func (s *Store) WindowsManagedMSIEnrollmentBinding() enrollmentstate.Binding {
	return s.Config().Binding
}

// ReadRegisteredWindowsManagedMSI is a trusted startup snapshot only. It opens
// validated reciprocal state even for a now-retired/expired member so that one
// unavailable device cannot prevent other devices from starting. It grants no
// operation authority; every Manager operation still uses the live transaction.
func (s *Store) ReadRegisteredWindowsManagedMSI(ctx context.Context, binding windowsmanagedmsi.Binding, key ed25519.PublicKey) (windowsmanagedmsi.Record, error) {
	var out windowsmanagedmsi.Record
	if s == nil || ctx == nil || !windowsmanagedmsi.ValidBinding(binding) || !keyvalidation.Ed25519(key) {
		return out, windowsmanagedmsi.ErrInvalid
	}
	err := s.transact(ctx, func(t *transaction) error {
		if err := s.checkWindowsManagedMSIKey(ctx, t, key); err != nil {
			return err
		}
		snap, err := systemDevice(t, binding.DeviceID)
		if err != nil {
			return windowsmanagedmsi.ErrAuthority
		}
		var raw []byte
		if err = t.conn.QueryRowContext(ctx, `SELECT body FROM enrollment_windows_managed_msi_records WHERE invitation_id=?`, snap.InvitationID).Scan(&raw); err != nil {
			return windowsmanagedmsi.ErrUnavailable
		}
		out, err = windowsmanagedmsi.DecodeRecord(raw)
		if err != nil || out.Grant.Binding != binding || !bytes.Equal(out.PublicKey, key) {
			return windowsmanagedmsi.ErrIntegrity
		}
		return windowsmanagedmsi.CheckFinal(ctx)
	})
	if err != nil {
		return windowsmanagedmsi.Record{}, err
	}
	return out, nil
}

// Reciprocal key-domain exclusion applies even when the fresh managed runtime
// is not currently configured. An immutable marker cannot become another key use.
func windowsManagedMSIKeyConflict(t *transaction, keys ...ed25519.PublicKey) bool {
	for _, c := range t.credentials {
		if c.WindowsManagedMSISetup != nil {
			b := c.WindowsManagedMSISetup.Grant.Binding
			for _, key := range keys {
				d := actionpermit.Digest(key)
				if d == b.KeyID || d == b.ExecutorKeyID {
					return true
				}
			}
		}
	}
	return false
}
