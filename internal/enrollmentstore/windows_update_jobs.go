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
	"localrmm/internal/windowsupdatejob"
)

const windowsUpdateJobMetaSchema = `CREATE TABLE enrollment_windows_update_job_meta(id INTEGER PRIMARY KEY CHECK(id=1),public_key BLOB NOT NULL CHECK(length(public_key)=32)) STRICT`
const windowsUpdateJobRecordsSchema = `CREATE TABLE enrollment_windows_update_job_records(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=524288),setup_fence TEXT NOT NULL CHECK(length(setup_fence)=71),rejected_clock_floor INTEGER NOT NULL CHECK(rejected_clock_floor>=0 AND rejected_clock_floor<=253402300799)) STRICT`

type windowsUpdateJobSetupMarker struct {
	Version       string                   `json:"version"`
	Consent       windowsupdatejob.Consent `json:"consent"`
	InitializedAt time.Time                `json:"initializedAt"`
}

func (m windowsUpdateJobSetupMarker) digest() string {
	raw, _ := json.Marshal(m)
	return actionpermit.Digest(append([]byte("Tracebolt enrollment selected Windows update setup v1\x00"), raw...))
}

func validWindowsUpdateJobSetupMarker(s enrollmentstate.Snapshot, m *windowsUpdateJobSetupMarker, authorityExpiry ...int64) bool {
	if m == nil {
		return true
	}
	c, b := m.Consent, m.Consent.Binding
	return s.Binding.Profile == "tls" && s.Binding.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && s.Platform == "windows" && s.Activation.At != 0 && m.Version == "tracebolt.windows-selected-update-setup.v1" && c.Validate() == nil && c.Enabled && c.Acknowledged && b.ManagerID == s.Binding.InstanceID && b.DeviceID == s.Approval.DeviceID && b.IncarnationDigest == "sha256:"+s.Issuance.CertificateHash && validStoreTime(m.InitializedAt) && m.InitializedAt.Unix() >= s.Activation.At && m.InitializedAt.Unix() < recordAuthorityExpiry(s, authorityExpiry...) && m.InitializedAt.Unix() < c.ExpiresAt && (s.Termination.At == 0 || m.InitializedAt.Unix() <= s.Termination.At)
}

func windowsUpdateJobSchemaObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_windows_update_job_meta", SQL: windowsUpdateJobMetaSchema}, {Type: "table", Name: "enrollment_windows_update_job_records", SQL: windowsUpdateJobRecordsSchema}}
}
func windowsUpdateJobSchemaPresent(ctx context.Context, c *sql.Conn) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_windows_update_job\_%' ESCAPE '\'`).Scan(&n) != nil || n != 0 && n != 2 {
		return false, ErrStorage
	}
	return n == 2, nil
}
func (s *Store) checkWindowsUpdateJobKey(ctx context.Context, t *transaction, key ed25519.PublicKey) error {
	present, err := windowsUpdateJobSchemaPresent(ctx, t.conn)
	if err != nil {
		return err
	}
	if !present {
		return windowsupdatejob.ErrUnavailable
	}
	var n int
	var found []byte
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_update_job_meta`).Scan(&n) != nil || n != 1 || t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_update_job_meta WHERE id=1`).Scan(&found) != nil {
		return ErrStorage
	}
	if !bytes.Equal(key, found) {
		return windowsupdatejob.ErrAuthority
	}
	return nil
}

// Both action keys are externally supplied and separate from each other, all
// enrollment/issuer keys, and the already-established service-control domain.
func (s *Store) windowsUpdateJobKeysDistinct(ctx context.Context, t *transaction, manager, executor ed25519.PublicKey) error {
	if windowsManagedMSIKeyConflict(t, manager, executor) {
		return windowsupdatejob.ErrConflict
	}
	if !keyvalidation.Ed25519(manager) || !keyvalidation.Ed25519(executor) || bytes.Equal(manager, executor) {
		return windowsupdatejob.ErrAuthority
	}
	for _, credential := range t.credentials {
		if other := credential.WindowsSoftwareJobSetup; other != nil {
			for _, digest := range []string{actionpermit.Digest(manager), actionpermit.Digest(executor)} {
				if digest == other.Consent.Binding.KeyID || digest == other.Consent.Binding.ExecutorKeyID {
					return windowsupdatejob.ErrAuthority
				}
			}
		}
	}
	certs := [][]byte{s.issuerDER}
	for _, c := range t.credentials {
		certs = append(certs, c.DER)
	}
	for _, der := range certs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return ErrStorage
		}
		if key, ok := cert.PublicKey.(ed25519.PublicKey); ok && (bytes.Equal(manager, key) || bytes.Equal(executor, key)) {
			return windowsupdatejob.ErrAuthority
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
			return windowsupdatejob.ErrAuthority
		}
	}
	return nil
}

// SetupWindowsUpdateJobsCreateOnly is an explicitly approved source provisioning
// seam, never startup, API, or recovery. No key, executor, or host grant is made.
// Its immutable credential marker and reciprocal row are committed together.
func (s *Store) SetupWindowsUpdateJobsCreateOnly(ctx context.Context, key, executorKey ed25519.PublicKey, consent windowsupdatejob.Consent, now time.Time) error {
	return s.setupWindowsUpdateJobsCreateOnly(ctx, key, executorKey, consent, now, false)
}

// RegisterWindowsUpdateDeviceCreateOnly adds one exact previously unregistered
// endpoint under the existing purpose-specific key. It never rewrites an earlier
// grant, marker, record, job, or clock floor, and cannot repair partial state.
func (s *Store) RegisterWindowsUpdateDeviceCreateOnly(ctx context.Context, key, executorKey ed25519.PublicKey, consent windowsupdatejob.Consent, now time.Time) error {
	return s.setupWindowsUpdateJobsCreateOnly(ctx, key, executorKey, consent, now, true)
}

func (s *Store) setupWindowsUpdateJobsCreateOnly(ctx context.Context, key, executorKey ed25519.PublicKey, consent windowsupdatejob.Consent, now time.Time, additional bool) error {
	if s == nil || s.storeState == nil || ctx == nil || !validStoreTime(now) || consent.Validate() != nil || !consent.Enabled || !consent.Acknowledged || !keyvalidation.Ed25519(key) || !keyvalidation.Ed25519(executorKey) || consent.Binding.KeyID != actionpermit.Digest(key) || consent.Binding.ExecutorKeyID != actionpermit.Digest(executorKey) {
		return windowsupdatejob.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		present, err := windowsUpdateJobSchemaPresent(ctx, t.conn)
		if err != nil {
			return err
		}
		if present != additional {
			return windowsupdatejob.ErrConflict
		}
		registered := 0
		for _, c := range t.credentials {
			if c.WindowsUpdateJobSetup == nil {
				continue
			}
			if !additional {
				return ErrStorage
			}
			registered++
			old := c.WindowsUpdateJobSetup.Consent.Binding
			if old.DeviceID == consent.Binding.DeviceID || old.ExecutorKeyID == consent.Binding.ExecutorKeyID || old.ExecutorID == consent.Binding.ExecutorID || old.GrantID == consent.Binding.GrantID {
				return windowsupdatejob.ErrConflict
			}
		}
		if additional {
			if registered == 0 || registered >= s.config.RecordLimit {
				return windowsupdatejob.ErrConflict
			}
			if err = s.checkWindowsUpdateJobKey(ctx, t, key); err != nil {
				return err
			}
		}
		if err = s.windowsUpdateJobKeysDistinct(ctx, t, key, executorKey); err != nil {
			return err
		}
		now, err = windowsUpdateJobNow(ctx, now)
		if err != nil {
			return err
		}
		snap, err := systemDevice(t, consent.Binding.DeviceID)
		if err != nil {
			return windowsupdatejob.ErrAuthority
		}
		if other := t.credentials[snap.InvitationID].WindowsManagedMSISetup; other != nil && !coordinatedWindowsMutationPair(other.Grant, consent) {
			return windowsupdatejob.ErrConflict
		}
		marker := &windowsUpdateJobSetupMarker{Version: "tracebolt.windows-selected-update-setup.v1", Consent: consent, InitializedAt: now}
		if !validWindowsUpdateJobSetupMarker(snap, marker, t.currentCredentialNotAfter(snap)) {
			return windowsupdatejob.ErrAuthority
		}
		issuer, err := x509.ParseCertificate(s.issuerDER)
		if err != nil || consent.ExpiresAt > issuer.NotAfter.Unix() {
			return windowsupdatejob.ErrAuthority
		}
		current, err := s.windowsUpdateJobCurrent(t, snap.InvitationID, consent.Binding, consent, now)
		if err != nil {
			return err
		}
		if err = checkWindowsUpdateSetupExpectedLeaf(ctx, current); err != nil {
			return err
		}
		r, err := windowsupdatejob.NewRecordWithExecutor(consent, key, executorKey, now.Unix())
		if err != nil {
			return err
		}
		if !additional {
			for _, obj := range windowsUpdateJobSchemaObjects() {
				if _, err = t.conn.ExecContext(ctx, obj.SQL); err != nil {
					return ErrStorage
				}
			}
			if _, err = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_update_job_meta VALUES(1,?)`, []byte(key)); err != nil {
				return ErrStorage
			}
		}
		raw, err := windowsupdatejob.EncodeRecord(r)
		if err != nil {
			return err
		}
		if _, err = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_update_job_records VALUES(?,?,?,0)`, snap.InvitationID, raw, marker.digest()); err != nil {
			return ErrStorage
		}
		c := t.credentials[snap.InvitationID]
		c.WindowsUpdateJobSetup = marker
		t.credentials[snap.InvitationID] = c
		t.beforeCommit = append(t.beforeCommit, func() error {
			// Protected review inputs may block on reads. Check them before the
			// last fresh clock/current-authority sample, never after it.
			if err := windowsupdatejob.CheckFinal(ctx); err != nil {
				return err
			}
			fresh, err := windowsUpdateJobNow(ctx, now)
			if err != nil || fresh.Before(now) {
				return windowsupdatejob.ErrExpired
			}
			final, err := s.windowsUpdateJobCurrent(t, snap.InvitationID, consent.Binding, consent, fresh)
			if err != nil {
				return err
			}
			if final != current {
				return windowsupdatejob.ErrAuthority
			}
			return nil
		})
		return nil
	})
}

// OpenWindowsUpdateJobs validates only existing fenced state. It never creates,
// adopts, or reconstructs a missing table, marker, consent, key, row, or history.
func (s *Store) OpenWindowsUpdateJobs(ctx context.Context, key ed25519.PublicKey) error {
	if s == nil || s.storeState == nil || ctx == nil || !keyvalidation.Ed25519(key) {
		return windowsupdatejob.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error { return s.checkWindowsUpdateJobKey(ctx, t, key) })
}

func (s *Store) loadWindowsUpdateJobRecords(ctx context.Context, t *transaction) error {
	present, err := windowsUpdateJobSchemaPresent(ctx, t.conn)
	if err != nil {
		return err
	}
	markers := map[string]*windowsUpdateJobSetupMarker{}
	for id, c := range t.credentials {
		if c.WindowsUpdateJobSetup != nil {
			markers[id] = c.WindowsUpdateJobSetup
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
	if t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_update_job_meta WHERE id=1`).Scan(&key) != nil || !keyvalidation.Ed25519(key) || s.checkWindowsUpdateJobKey(ctx, t, key) != nil {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(max(length(body)),0) FROM enrollment_windows_update_job_records`).Scan(&n, &maxBytes) != nil || n > s.config.RecordLimit || maxBytes > windowsupdatejob.MaxBytes {
		return ErrStorage
	}
	issuer, err := x509.ParseCertificate(s.issuerDER)
	if err != nil {
		return ErrStorage
	}
	rows, err := t.conn.QueryContext(ctx, `SELECT invitation_id,body,setup_fence,rejected_clock_floor FROM enrollment_windows_update_job_records`)
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
		r, err := windowsupdatejob.DecodeRecord(raw)
		m := markers[id]
		if err != nil || m == nil || m.digest() != fence || m.Consent != r.Consent || !bytes.Equal(key, r.PublicKey) || r.ClockFloor < m.InitializedAt.Unix() || rejected != 0 && (rejected < m.InitializedAt.Unix() || rejected > enrollmentstate.MaxTimestamp) || r.Consent.ExpiresAt > issuer.NotAfter.Unix() {
			return ErrStorage
		}
		snap, err := t.engine.Get(id)
		// Rejected observations may outlive the leaf or revocation. They carry
		// no successful-job authority and must never invalidate durable history.
		if err != nil || !validWindowsUpdateJobSetupMarker(snap, m, t.currentCredentialNotAfter(snap)) || r.ClockFloor >= t.currentCredentialNotAfter(snap) || r.ClockFloor >= r.Consent.ExpiresAt || snap.Termination.At != 0 && r.ClockFloor > snap.Termination.At {
			return ErrStorage
		}
		if err = s.windowsUpdateJobKeysDistinct(ctx, t, key, r.ExecutorPublicKey); err != nil {
			return ErrStorage
		}
		b := r.Consent.Binding
		if executors[b.ExecutorKeyID] || devices[b.DeviceID] || grants[b.GrantID] || executorIDs[b.ExecutorID] {
			return ErrStorage
		}
		executors[b.ExecutorKeyID], devices[b.DeviceID], grants[b.GrantID], executorIDs[b.ExecutorID] = true, true, true, true
		delete(markers, id)
	}
	if rows.Err() != nil || len(markers) != 0 {
		return ErrStorage
	}
	return nil
}

func windowsUpdateJobNow(ctx context.Context, fallback time.Time) (time.Time, error) {
	if ctx == nil || !validStoreTime(fallback) {
		return time.Time{}, windowsupdatejob.ErrInvalid
	}
	if clock, ok := ctx.Value(overviewClockKey{}).(overviewTrustedClock); ok {
		if clock.now == nil {
			return time.Time{}, windowsupdatejob.ErrInvalid
		}
		fallback = clock.now()
	}
	if !validStoreTime(fallback) {
		return time.Time{}, windowsupdatejob.ErrInvalid
	}
	return fallback.UTC(), nil
}

func (s *Store) windowsUpdateJobCurrent(t *transaction, id string, binding windowsupdatejob.Binding, consent windowsupdatejob.Consent, now time.Time) (windowsupdatejob.Current, error) {
	var current windowsupdatejob.Current
	snap, err := t.engine.Get(id)
	if err != nil || snap.Binding.Profile != "tls" || snap.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || snap.Platform != "windows" || binding != consent.Binding || binding.ManagerID != snap.Binding.InstanceID || binding.DeviceID != snap.Approval.DeviceID || binding.IncarnationDigest != "sha256:"+snap.Issuance.CertificateHash {
		return current, windowsupdatejob.ErrAuthority
	}
	c, ok := t.credentials[id]
	if !ok {
		return current, ErrStorage
	}
	intent, _, hash, err := t.currentCredential(snap, c)
	if err != nil {
		return current, err
	}
	current = windowsupdatejob.Current{Binding: binding, LeafDigest: "sha256:" + hash, LeafGeneration: 1, LeafNotBefore: intent.NotBefore, LeafNotAfter: intent.NotAfter, Revoked: snap.State != enrollmentstate.Activated, Enabled: consent.Enabled && consent.Acknowledged}
	if c.Renewal != nil {
		current.LeafGeneration = c.Renewal.Current.Generation
	}
	if current.Revoked || !current.Enabled {
		return current, windowsupdatejob.ErrAuthority
	}
	if !validStoreTime(now) || now.Unix() >= consent.ExpiresAt {
		return current, windowsupdatejob.ErrExpired
	}
	if err = t.authorizeCurrentCredential(snap, hash, now); err != nil {
		if errors.Is(err, enrollmentstate.ErrExpired) || errors.Is(err, enrollmentstate.ErrInvalid) {
			return current, windowsupdatejob.ErrExpired
		}
		if errors.Is(err, ErrStorage) {
			return current, err
		}
		return current, windowsupdatejob.ErrAuthority
	}
	return current, nil
}

// windowsUpdateJobTransition prevents callback code from changing consent/keys
// or erasing/replacing a consumed signed record. Unsigned readiness slots remain
// replaceable; signed history, original ages, envelopes and results do not.
func windowsUpdateJobTransition(before, after windowsupdatejob.Record, now int64) error {
	if windowsupdatejob.CheckMutationTransition(before, after) != nil {
		return windowsupdatejob.ErrIntegrity
	}
	if err := windowsupdatejob.CheckScheduleTransition(before, after); err != nil {
		return err
	}
	if before.Version != after.Version || before.Consent != after.Consent || !bytes.Equal(before.PublicKey, after.PublicKey) || !bytes.Equal(before.ExecutorPublicKey, after.ExecutorPublicKey) || after.Sequence < before.Sequence || after.ReadinessSequence < before.ReadinessSequence || after.ClockFloor < before.ClockFloor || after.ClockFloor > now || after.SchedulePolicyFloor > now {
		return windowsupdatejob.ErrInvalid
	}
	// Replacing the unsigned readiness slot must issue a strictly newer signed
	// challenge even when wall-clock issue/deadline values are unchanged.
	for _, next := range after.Jobs {
		unchanged := false
		for _, old := range before.Jobs {
			if bytes.Equal(old.Challenge, next.Challenge) {
				unchanged = true
				break
			}
		}
		if !unchanged {
			challenge, err := windowsupdatejob.VerifyChallenge(next.Challenge, after.PublicKey)
			if err != nil || challenge.Sequence <= before.ReadinessSequence {
				return windowsupdatejob.ErrInvalid
			}
		}
	}
	for _, old := range before.Jobs {
		if len(old.Envelope) == 0 || old.Schedule != nil {
			continue
		}
		found := false
		for _, next := range after.Jobs {
			if next.ID != old.ID {
				continue
			}
			found = true
			a, b := old, next
			if old.State == "approved" && next.State == "claimed" {
				a.State, a.ClaimedAt = b.State, b.ClaimedAt
			}
			if old.State == "claimed" && next.State == "complete" {
				a.State = b.State
			}
			if old.State == "claimed" && next.State == "complete" {
				a.Result, a.ResultReport = b.Result, b.ResultReport
			}
			x, _ := json.Marshal(a)
			y, _ := json.Marshal(b)
			if !bytes.Equal(x, y) {
				return windowsupdatejob.ErrConflict
			}
			break
		}
		if !found {
			return windowsupdatejob.ErrConflict
		}
	}
	return nil
}

func windowsUpdateJobFinalDeadline(before, after windowsupdatejob.Record, current windowsupdatejob.Current, fresh int64) error {
	old := make(map[string]windowsupdatejob.Job, len(before.Jobs))
	for _, j := range before.Jobs {
		old[j.ID] = j
	}
	for _, j := range after.Jobs {
		prior, exists := old[j.ID]
		if j.Schedule != nil && prior.Schedule == nil {
			a := j.Schedule.Approval
			if fresh >= a.Baseline.ExpiresAt || a.EndAt > current.LeafNotAfter || a.EndAt > after.Consent.ExpiresAt {
				return windowsupdatejob.ErrExpired
			}
		}
		newChallenge := !exists || !bytes.Equal(prior.Challenge, j.Challenge)
		newReadinessClaim := j.ReadinessClaimedAt != 0 && prior.ReadinessClaimedAt == 0
		if newChallenge || newReadinessClaim {
			challenge, err := windowsupdatejob.VerifyChallenge(j.Challenge, after.PublicKey)
			if err != nil || fresh >= challenge.Deadline || challenge.Deadline > current.LeafNotAfter || challenge.Deadline > after.Consent.ExpiresAt {
				return windowsupdatejob.ErrExpired
			}
		}
		for _, pair := range [][2][]byte{{prior.ReadinessReport, j.ReadinessReport}, {prior.ResultReport, j.ResultReport}} {
			if len(pair[1]) != 0 && !bytes.Equal(pair[0], pair[1]) {
				statement, err := windowsupdatejob.VerifyStatement(pair[1], after.ExecutorPublicKey)
				if err != nil || fresh >= statement.ExpiresAt {
					return windowsupdatejob.ErrExpired
				}
			}
		}
		newPreview := j.Preview != nil && (!exists || prior.Preview == nil || *prior.Preview != *j.Preview)
		newEnvelope := len(j.Envelope) != 0 && len(prior.Envelope) == 0
		newClaim := j.ClaimedAt != 0 && prior.ClaimedAt == 0
		if newClaim && (!exists || prior.State != "approved") {
			return windowsupdatejob.ErrConflict
		}
		if newPreview || newEnvelope || newClaim {
			if j.Preview == nil || fresh >= j.Preview.ExpiresAt || j.Preview.ExpiresAt > current.LeafNotAfter || j.Preview.ExpiresAt > after.Consent.ExpiresAt {
				return windowsupdatejob.ErrExpired
			}
		}
	}
	return nil
}

// WindowsUpdateJobTransaction owns both job writes and current enrollment
// authority in one transaction. No signed envelope may escape on a non-nil error.
// Business rejections commit only a monotonic observation floor, never rejected
// callback mutations. Persistence uncertainty is returned without automatic retry.
func (s *Store) WindowsUpdateJobTransaction(ctx context.Context, binding windowsupdatejob.Binding, key ed25519.PublicKey, now time.Time, fn func(*windowsupdatejob.Record, windowsupdatejob.Current, time.Time) error) (windowsupdatejob.Record, time.Time, error) {
	var out windowsupdatejob.Record
	if s == nil || s.storeState == nil || ctx == nil || fn == nil || !windowsupdatejob.ValidBinding(binding) || !keyvalidation.Ed25519(key) || !validStoreTime(now) {
		return out, now, windowsupdatejob.ErrInvalid
	}
	var operationErr error
	writeStarted := false
	err := s.transact(ctx, func(t *transaction) error {
		if err := s.checkWindowsUpdateJobKey(ctx, t, key); err != nil {
			return err
		}
		snap, err := systemDevice(t, binding.DeviceID)
		if err != nil {
			return windowsupdatejob.ErrAuthority
		}
		var raw []byte
		var rejected int64
		if err = t.conn.QueryRowContext(ctx, `SELECT body,rejected_clock_floor FROM enrollment_windows_update_job_records WHERE invitation_id=?`, snap.InvitationID).Scan(&raw, &rejected); err == sql.ErrNoRows {
			return windowsupdatejob.ErrUnavailable
		} else if err != nil {
			return ErrStorage
		}
		original, err := windowsupdatejob.DecodeRecord(raw)
		if err != nil {
			return ErrStorage
		}
		r, err := windowsupdatejob.DecodeRecord(raw)
		if err != nil {
			return ErrStorage
		}
		initial, err := windowsUpdateJobNow(ctx, now)
		if err != nil {
			return err
		}
		floor := max(original.ClockFloor, rejected, original.SchedulePolicyFloor)
		current, authorityErr := s.windowsUpdateJobCurrent(t, snap.InvitationID, binding, original.Consent, initial)
		if initial.Before(now) || initial.Unix() < floor {
			operationErr = windowsupdatejob.ErrExpired
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
				operationErr = windowsUpdateJobTransition(original, r, initial.Unix())
			}
			if operationErr == nil && r.Validate() != nil {
				operationErr = windowsupdatejob.ErrInvalid
			}
		}
		// Persistence is deferred until the final authority check. The common
		// transaction still validates all unrelated credentials and used state.
		t.beforeCommit = append(t.beforeCommit, func() error {
			fresh, clockErr := windowsUpdateJobNow(ctx, initial)
			observed := max(floor, initial.Unix())
			if clockErr == nil {
				observed = max(observed, fresh.Unix())
			}
			if clockErr != nil {
				operationErr = clockErr
			} else if fresh.Before(initial) || fresh.Unix() < floor {
				operationErr = windowsupdatejob.ErrExpired
			}
			if operationErr == nil {
				final, err := s.windowsUpdateJobCurrent(t, snap.InvitationID, binding, original.Consent, fresh)
				if errors.Is(err, ErrStorage) {
					return err
				}
				if err != nil {
					operationErr = err
				} else if final != current {
					operationErr = windowsupdatejob.ErrAuthority
				} else {
					operationErr = windowsUpdateJobFinalDeadline(original, r, final, fresh.Unix())
				}
			}
			if operationErr == nil {
				operationErr = windowsupdatejob.CheckFinal(ctx)
				// Configuration reads and the session fence can block or reject.
				// Retain their last observed time even on rejection.
				last, clockErr := windowsUpdateJobNow(ctx, fresh)
				if clockErr != nil || last.Before(fresh) {
					operationErr = windowsupdatejob.ErrExpired
				} else {
					fresh = last
					observed = max(observed, last.Unix())
					if operationErr == nil {
						final, authorityErr := s.windowsUpdateJobCurrent(t, snap.InvitationID, binding, original.Consent, last)
						if authorityErr != nil {
							operationErr = authorityErr
						} else if final != current {
							operationErr = windowsupdatejob.ErrAuthority
						} else {
							operationErr = windowsUpdateJobFinalDeadline(original, r, final, last.Unix())
						}
					}
				}
			}
			if operationErr != nil {
				r, err = windowsupdatejob.DecodeRecord(raw)
				if err != nil {
					return ErrStorage
				}
				rejected = observed
			} else {
				r.ClockFloor = fresh.Unix()
			}
			body, err := windowsupdatejob.EncodeRecord(r)
			if err != nil {
				return ErrStorage
			}
			if s.checkPath() != nil {
				return ErrStorage
			}
			writeStarted = true
			result, err := t.conn.ExecContext(ctx, `UPDATE enrollment_windows_update_job_records SET body=?,rejected_clock_floor=? WHERE invitation_id=?`, body, rejected, snap.InvitationID)
			if err != nil {
				return ErrStorage
			}
			if n, err := result.RowsAffected(); err != nil || n != 1 {
				return ErrStorage
			}
			if err = s.loadWindowsUpdateJobRecords(ctx, t); err != nil {
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
			return windowsupdatejob.Record{}, now, windowsupdatejob.ErrUncertain
		}
		return windowsupdatejob.Record{}, now, err
	}
	if operationErr != nil {
		return windowsupdatejob.Record{}, now, operationErr
	}
	return out, now, nil
}

func (s *Store) WindowsUpdateEnrollmentBinding() enrollmentstate.Binding {
	return s.Config().Binding
}

// ReadRegisteredWindowsUpdateJob is a trusted startup snapshot only. It opens
// validated reciprocal state even for a now-retired/expired member so that one
// unavailable device cannot prevent other devices from starting. It grants no
// operation authority; every Manager operation still uses the live transaction.
func (s *Store) ReadRegisteredWindowsUpdateJob(ctx context.Context, binding windowsupdatejob.Binding, key ed25519.PublicKey) (windowsupdatejob.Record, error) {
	var out windowsupdatejob.Record
	if s == nil || ctx == nil || !windowsupdatejob.ValidBinding(binding) || !keyvalidation.Ed25519(key) {
		return out, windowsupdatejob.ErrInvalid
	}
	err := s.transact(ctx, func(t *transaction) error {
		if err := s.checkWindowsUpdateJobKey(ctx, t, key); err != nil {
			return err
		}
		snap, err := systemDevice(t, binding.DeviceID)
		if err != nil {
			return windowsupdatejob.ErrAuthority
		}
		var raw []byte
		if err = t.conn.QueryRowContext(ctx, `SELECT body FROM enrollment_windows_update_job_records WHERE invitation_id=?`, snap.InvitationID).Scan(&raw); err != nil {
			return windowsupdatejob.ErrUnavailable
		}
		out, err = windowsupdatejob.DecodeRecord(raw)
		if err != nil || out.Consent.Binding != binding || !bytes.Equal(out.PublicKey, key) {
			return windowsupdatejob.ErrIntegrity
		}
		return windowsupdatejob.CheckFinal(ctx)
	})
	if err != nil {
		return windowsupdatejob.Record{}, err
	}
	return out, nil
}
