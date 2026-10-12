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
	"localrmm/internal/windowssoftwarejob"
)

const windowsSoftwareJobMetaSchema = `CREATE TABLE enrollment_windows_software_job_meta(id INTEGER PRIMARY KEY CHECK(id=1),public_key BLOB NOT NULL CHECK(length(public_key)=32)) STRICT`
const windowsSoftwareJobRecordsSchema = `CREATE TABLE enrollment_windows_software_job_records(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id),body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=524288),setup_fence TEXT NOT NULL CHECK(length(setup_fence)=71),rejected_clock_floor INTEGER NOT NULL CHECK(rejected_clock_floor>=0 AND rejected_clock_floor<=253402300799)) STRICT`

type windowsSoftwareJobSetupMarker struct {
	Version       string                     `json:"version"`
	Consent       windowssoftwarejob.Consent `json:"consent"`
	InitializedAt time.Time                  `json:"initializedAt"`
}

func (m windowsSoftwareJobSetupMarker) digest() string {
	raw, _ := json.Marshal(m)
	return actionpermit.Digest(append([]byte("Tracebolt enrollment prepared MSI setup v1\x00"), raw...))
}

func validWindowsSoftwareJobSetupMarker(s enrollmentstate.Snapshot, m *windowsSoftwareJobSetupMarker, authorityExpiry ...int64) bool {
	if m == nil {
		return true
	}
	c, b := m.Consent, m.Consent.Binding
	return s.Binding.Profile == "tls" && s.Binding.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && s.Platform == "windows" && s.Activation.At != 0 && m.Version == "tracebolt.windows-prepared-msi-setup.v1" && c.Validate() == nil && c.Enabled && c.Acknowledged && b.ManagerID == s.Binding.InstanceID && b.DeviceID == s.Approval.DeviceID && b.IncarnationDigest == "sha256:"+s.Issuance.CertificateHash && validStoreTime(m.InitializedAt) && m.InitializedAt.Unix() >= s.Activation.At && m.InitializedAt.Unix() < recordAuthorityExpiry(s, authorityExpiry...) && m.InitializedAt.Unix() < c.ExpiresAt && (s.Termination.At == 0 || m.InitializedAt.Unix() <= s.Termination.At)
}

func windowsSoftwareJobSchemaObjects() []inventoryledger.SchemaObject {
	return []inventoryledger.SchemaObject{{Type: "table", Name: "enrollment_windows_software_job_meta", SQL: windowsSoftwareJobMetaSchema}, {Type: "table", Name: "enrollment_windows_software_job_records", SQL: windowsSoftwareJobRecordsSchema}}
}
func windowsSoftwareJobSchemaPresent(ctx context.Context, c *sql.Conn) (bool, error) {
	var n int
	if c.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_windows_software_job\_%' ESCAPE '\'`).Scan(&n) != nil || n != 0 && n != 2 {
		return false, ErrStorage
	}
	return n == 2, nil
}
func (s *Store) checkWindowsSoftwareJobKey(ctx context.Context, t *transaction, key ed25519.PublicKey) error {
	present, err := windowsSoftwareJobSchemaPresent(ctx, t.conn)
	if err != nil {
		return err
	}
	if !present {
		return windowssoftwarejob.ErrUnavailable
	}
	var n int
	var found []byte
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_software_job_meta`).Scan(&n) != nil || n != 1 || t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_software_job_meta WHERE id=1`).Scan(&found) != nil {
		return ErrStorage
	}
	if !bytes.Equal(key, found) {
		return windowssoftwarejob.ErrAuthority
	}
	return nil
}

// Both action keys are externally supplied and separate from each other, all
// enrollment/issuer keys, and the already-established service-control domain.
func (s *Store) windowsSoftwareJobKeysDistinct(ctx context.Context, t *transaction, manager, executor ed25519.PublicKey) error {
	if windowsManagedMSIKeyConflict(t, manager, executor) {
		return windowssoftwarejob.ErrConflict
	}
	if !keyvalidation.Ed25519(manager) || !keyvalidation.Ed25519(executor) || bytes.Equal(manager, executor) {
		return windowssoftwarejob.ErrAuthority
	}
	certs := [][]byte{s.issuerDER}
	for _, c := range t.credentials {
		if c.WindowsUpdateJobSetup != nil {
			old := c.WindowsUpdateJobSetup.Consent.Binding
			for _, digest := range []string{old.KeyID, old.ExecutorKeyID} {
				if digest == actionpermit.Digest(manager) || digest == actionpermit.Digest(executor) {
					return windowssoftwarejob.ErrAuthority
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
			return windowssoftwarejob.ErrAuthority
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
			return windowssoftwarejob.ErrAuthority
		}
	}
	return nil
}

// SetupWindowsSoftwareJobsCreateOnly is an explicitly approved source provisioning
// seam, never startup, API, or recovery. No key, executor, or host grant is made.
// Its immutable credential marker and reciprocal row are committed together.
func (s *Store) SetupWindowsSoftwareJobsCreateOnly(ctx context.Context, key, executorKey ed25519.PublicKey, consent windowssoftwarejob.Consent, now time.Time) error {
	return s.setupWindowsSoftwareJobsCreateOnly(ctx, key, executorKey, consent, now, false)
}

// RegisterWindowsSoftwareDeviceCreateOnly adds one exact previously unregistered
// endpoint under the existing purpose-specific key. It never rewrites an earlier
// grant, marker, record, job, or clock floor, and cannot repair partial state.
func (s *Store) RegisterWindowsSoftwareDeviceCreateOnly(ctx context.Context, key, executorKey ed25519.PublicKey, consent windowssoftwarejob.Consent, now time.Time) error {
	return s.setupWindowsSoftwareJobsCreateOnly(ctx, key, executorKey, consent, now, true)
}

func (s *Store) setupWindowsSoftwareJobsCreateOnly(ctx context.Context, key, executorKey ed25519.PublicKey, consent windowssoftwarejob.Consent, now time.Time, additional bool) error {
	if s == nil || s.storeState == nil || ctx == nil || !validStoreTime(now) || consent.Validate() != nil || !consent.Enabled || !consent.Acknowledged || !keyvalidation.Ed25519(key) || !keyvalidation.Ed25519(executorKey) || consent.Binding.KeyID != actionpermit.Digest(key) || consent.Binding.ExecutorKeyID != actionpermit.Digest(executorKey) {
		return windowssoftwarejob.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		present, err := windowsSoftwareJobSchemaPresent(ctx, t.conn)
		if err != nil {
			return err
		}
		if present != additional {
			return windowssoftwarejob.ErrConflict
		}
		registered := 0
		for _, c := range t.credentials {
			if c.WindowsSoftwareJobSetup == nil {
				continue
			}
			if !additional {
				return ErrStorage
			}
			registered++
			old := c.WindowsSoftwareJobSetup.Consent.Binding
			if old.DeviceID == consent.Binding.DeviceID || old.ExecutorKeyID == consent.Binding.ExecutorKeyID || old.ExecutorID == consent.Binding.ExecutorID || old.GrantID == consent.Binding.GrantID {
				return windowssoftwarejob.ErrConflict
			}
		}
		if additional {
			if registered == 0 || registered >= s.config.RecordLimit {
				return windowssoftwarejob.ErrConflict
			}
			if err = s.checkWindowsSoftwareJobKey(ctx, t, key); err != nil {
				return err
			}
		}
		if err = s.windowsSoftwareJobKeysDistinct(ctx, t, key, executorKey); err != nil {
			return err
		}
		now, err = windowsSoftwareJobNow(ctx, now)
		if err != nil {
			return err
		}
		snap, err := systemDevice(t, consent.Binding.DeviceID)
		if err != nil {
			return windowssoftwarejob.ErrAuthority
		}
		if t.credentials[snap.InvitationID].WindowsManagedMSISetup != nil {
			return windowssoftwarejob.ErrConflict
		}
		marker := &windowsSoftwareJobSetupMarker{Version: "tracebolt.windows-prepared-msi-setup.v1", Consent: consent, InitializedAt: now}
		if !validWindowsSoftwareJobSetupMarker(snap, marker, t.currentCredentialNotAfter(snap)) {
			return windowssoftwarejob.ErrAuthority
		}
		issuer, err := x509.ParseCertificate(s.issuerDER)
		if err != nil || consent.ExpiresAt > issuer.NotAfter.Unix() {
			return windowssoftwarejob.ErrAuthority
		}
		current, err := s.windowsSoftwareJobCurrent(t, snap.InvitationID, consent.Binding, consent, now)
		if err != nil {
			return err
		}
		if err = checkWindowsSoftwareSetupExpectedLeaf(ctx, current); err != nil {
			return err
		}
		r, err := windowssoftwarejob.NewRecordWithExecutor(consent, key, executorKey, now.Unix())
		if err != nil {
			return err
		}
		if !additional {
			for _, obj := range windowsSoftwareJobSchemaObjects() {
				if _, err = t.conn.ExecContext(ctx, obj.SQL); err != nil {
					return ErrStorage
				}
			}
			if _, err = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_software_job_meta VALUES(1,?)`, []byte(key)); err != nil {
				return ErrStorage
			}
		}
		raw, err := windowssoftwarejob.EncodeRecord(r)
		if err != nil {
			return err
		}
		if _, err = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_software_job_records VALUES(?,?,?,0)`, snap.InvitationID, raw, marker.digest()); err != nil {
			return ErrStorage
		}
		c := t.credentials[snap.InvitationID]
		c.WindowsSoftwareJobSetup = marker
		t.credentials[snap.InvitationID] = c
		t.beforeCommit = append(t.beforeCommit, func() error {
			// Protected review inputs may block on reads. Check them before the
			// last fresh clock/current-authority sample, never after it.
			if err := windowssoftwarejob.CheckFinal(ctx); err != nil {
				return err
			}
			fresh, err := windowsSoftwareJobNow(ctx, now)
			if err != nil || fresh.Before(now) {
				return windowssoftwarejob.ErrExpired
			}
			final, err := s.windowsSoftwareJobCurrent(t, snap.InvitationID, consent.Binding, consent, fresh)
			if err != nil {
				return err
			}
			if final != current {
				return windowssoftwarejob.ErrAuthority
			}
			return nil
		})
		return nil
	})
}

// OpenWindowsSoftwareJobs validates only existing fenced state. It never creates,
// adopts, or reconstructs a missing table, marker, consent, key, row, or history.
func (s *Store) OpenWindowsSoftwareJobs(ctx context.Context, key ed25519.PublicKey) error {
	if s == nil || s.storeState == nil || ctx == nil || !keyvalidation.Ed25519(key) {
		return windowssoftwarejob.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error { return s.checkWindowsSoftwareJobKey(ctx, t, key) })
}

func (s *Store) loadWindowsSoftwareJobRecords(ctx context.Context, t *transaction) error {
	present, err := windowsSoftwareJobSchemaPresent(ctx, t.conn)
	if err != nil {
		return err
	}
	markers := map[string]*windowsSoftwareJobSetupMarker{}
	for id, c := range t.credentials {
		if c.WindowsSoftwareJobSetup != nil {
			markers[id] = c.WindowsSoftwareJobSetup
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
	if t.conn.QueryRowContext(ctx, `SELECT public_key FROM enrollment_windows_software_job_meta WHERE id=1`).Scan(&key) != nil || !keyvalidation.Ed25519(key) || s.checkWindowsSoftwareJobKey(ctx, t, key) != nil {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*),coalesce(max(length(body)),0) FROM enrollment_windows_software_job_records`).Scan(&n, &maxBytes) != nil || n > s.config.RecordLimit || maxBytes > windowssoftwarejob.MaxBytes {
		return ErrStorage
	}
	issuer, err := x509.ParseCertificate(s.issuerDER)
	if err != nil {
		return ErrStorage
	}
	rows, err := t.conn.QueryContext(ctx, `SELECT invitation_id,body,setup_fence,rejected_clock_floor FROM enrollment_windows_software_job_records`)
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
		r, err := windowssoftwarejob.DecodeRecord(raw)
		m := markers[id]
		if err != nil || m == nil || m.digest() != fence || m.Consent != r.Consent || !bytes.Equal(key, r.PublicKey) || r.ClockFloor < m.InitializedAt.Unix() || rejected != 0 && (rejected < m.InitializedAt.Unix() || rejected > enrollmentstate.MaxTimestamp) || r.Consent.ExpiresAt > issuer.NotAfter.Unix() {
			return ErrStorage
		}
		snap, err := t.engine.Get(id)
		// Rejected observations may outlive the leaf or revocation. They carry
		// no successful-job authority and must never invalidate durable history.
		if err != nil || !validWindowsSoftwareJobSetupMarker(snap, m, t.currentCredentialNotAfter(snap)) || r.ClockFloor >= t.currentCredentialNotAfter(snap) || r.ClockFloor >= r.Consent.ExpiresAt || snap.Termination.At != 0 && r.ClockFloor > snap.Termination.At {
			return ErrStorage
		}
		if err = s.windowsSoftwareJobKeysDistinct(ctx, t, key, r.ExecutorPublicKey); err != nil {
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

func windowsSoftwareJobNow(ctx context.Context, fallback time.Time) (time.Time, error) {
	if ctx == nil || !validStoreTime(fallback) {
		return time.Time{}, windowssoftwarejob.ErrInvalid
	}
	if clock, ok := ctx.Value(overviewClockKey{}).(overviewTrustedClock); ok {
		if clock.now == nil {
			return time.Time{}, windowssoftwarejob.ErrInvalid
		}
		fallback = clock.now()
	}
	if !validStoreTime(fallback) {
		return time.Time{}, windowssoftwarejob.ErrInvalid
	}
	return fallback.UTC(), nil
}

func (s *Store) windowsSoftwareJobCurrent(t *transaction, id string, binding windowssoftwarejob.Binding, consent windowssoftwarejob.Consent, now time.Time) (windowssoftwarejob.Current, error) {
	var current windowssoftwarejob.Current
	snap, err := t.engine.Get(id)
	if err != nil || snap.Binding.Profile != "tls" || snap.Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || snap.Platform != "windows" || binding != consent.Binding || binding.ManagerID != snap.Binding.InstanceID || binding.DeviceID != snap.Approval.DeviceID || binding.IncarnationDigest != "sha256:"+snap.Issuance.CertificateHash {
		return current, windowssoftwarejob.ErrAuthority
	}
	c, ok := t.credentials[id]
	if !ok {
		return current, ErrStorage
	}
	intent, _, hash, err := t.currentCredential(snap, c)
	if err != nil {
		return current, err
	}
	current = windowssoftwarejob.Current{Binding: binding, LeafDigest: "sha256:" + hash, LeafGeneration: 1, LeafNotBefore: intent.NotBefore, LeafNotAfter: intent.NotAfter, Revoked: snap.State != enrollmentstate.Activated, Enabled: consent.Enabled && consent.Acknowledged}
	if c.Renewal != nil {
		current.LeafGeneration = c.Renewal.Current.Generation
	}
	if current.Revoked || !current.Enabled {
		return current, windowssoftwarejob.ErrAuthority
	}
	if !validStoreTime(now) || now.Unix() >= consent.ExpiresAt {
		return current, windowssoftwarejob.ErrExpired
	}
	if err = t.authorizeCurrentCredential(snap, hash, now); err != nil {
		if errors.Is(err, enrollmentstate.ErrExpired) || errors.Is(err, enrollmentstate.ErrInvalid) {
			return current, windowssoftwarejob.ErrExpired
		}
		if errors.Is(err, ErrStorage) {
			return current, err
		}
		return current, windowssoftwarejob.ErrAuthority
	}
	return current, nil
}

// windowsSoftwareJobTransition prevents callback code from changing consent/keys
// or erasing/replacing a consumed signed record. Unsigned readiness slots remain
// replaceable; signed history, original ages, envelopes and results do not.
func windowsSoftwareJobTransition(before, after windowssoftwarejob.Record, now int64) error {

	if before.Version != after.Version || before.Consent != after.Consent || !bytes.Equal(before.PublicKey, after.PublicKey) || !bytes.Equal(before.ExecutorPublicKey, after.ExecutorPublicKey) || after.Sequence < before.Sequence || after.ReadinessSequence < before.ReadinessSequence || after.ClockFloor < before.ClockFloor || after.ClockFloor > now {
		return windowssoftwarejob.ErrInvalid
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
			challenge, err := windowssoftwarejob.VerifyChallenge(next.Challenge, after.PublicKey)
			if err != nil || challenge.Sequence <= before.ReadinessSequence {
				return windowssoftwarejob.ErrInvalid
			}
		}
	}
	for _, old := range before.Jobs {
		if len(old.Envelope) == 0 {
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
				return windowssoftwarejob.ErrConflict
			}
			break
		}
		if !found {
			return windowssoftwarejob.ErrConflict
		}
	}
	return nil
}

func windowsSoftwareJobFinalDeadline(before, after windowssoftwarejob.Record, current windowssoftwarejob.Current, fresh int64) error {
	old := make(map[string]windowssoftwarejob.Job, len(before.Jobs))
	for _, j := range before.Jobs {
		old[j.ID] = j
	}
	for _, j := range after.Jobs {
		prior, exists := old[j.ID]

		newChallenge := !exists || !bytes.Equal(prior.Challenge, j.Challenge)
		newReadinessClaim := j.ReadinessClaimedAt != 0 && prior.ReadinessClaimedAt == 0
		if newChallenge || newReadinessClaim {
			challenge, err := windowssoftwarejob.VerifyChallenge(j.Challenge, after.PublicKey)
			if err != nil || fresh >= challenge.Deadline || challenge.Deadline > current.LeafNotAfter || challenge.Deadline > after.Consent.ExpiresAt {
				return windowssoftwarejob.ErrExpired
			}
		}
		for _, pair := range [][2][]byte{{prior.ReadinessReport, j.ReadinessReport}, {prior.ResultReport, j.ResultReport}} {
			if len(pair[1]) != 0 && !bytes.Equal(pair[0], pair[1]) {
				statement, err := windowssoftwarejob.VerifyStatement(pair[1], after.ExecutorPublicKey)
				if err != nil || fresh >= statement.ExpiresAt {
					return windowssoftwarejob.ErrExpired
				}
			}
		}
		newPreview := j.Preview != nil && (!exists || prior.Preview == nil || *prior.Preview != *j.Preview)
		newEnvelope := len(j.Envelope) != 0 && len(prior.Envelope) == 0
		newClaim := j.ClaimedAt != 0 && prior.ClaimedAt == 0
		if newClaim && (!exists || prior.State != "approved") {
			return windowssoftwarejob.ErrConflict
		}
		if newPreview || newEnvelope || newClaim {
			if j.Preview == nil || fresh >= j.Preview.ExpiresAt || j.Preview.ExpiresAt > current.LeafNotAfter || j.Preview.ExpiresAt > after.Consent.ExpiresAt {
				return windowssoftwarejob.ErrExpired
			}
		}
	}
	return nil
}

// WindowsSoftwareJobTransaction owns both job writes and current enrollment
// authority in one transaction. No signed envelope may escape on a non-nil error.
// Business rejections commit only a monotonic observation floor, never rejected
// callback mutations. Persistence uncertainty is returned without automatic retry.
func (s *Store) WindowsSoftwareJobTransaction(ctx context.Context, binding windowssoftwarejob.Binding, key ed25519.PublicKey, now time.Time, fn func(*windowssoftwarejob.Record, windowssoftwarejob.Current, time.Time) error) (windowssoftwarejob.Record, time.Time, error) {
	var out windowssoftwarejob.Record
	if s == nil || s.storeState == nil || ctx == nil || fn == nil || !windowssoftwarejob.ValidBinding(binding) || !keyvalidation.Ed25519(key) || !validStoreTime(now) {
		return out, now, windowssoftwarejob.ErrInvalid
	}
	var operationErr error
	writeStarted := false
	err := s.transact(ctx, func(t *transaction) error {
		if err := s.checkWindowsSoftwareJobKey(ctx, t, key); err != nil {
			return err
		}
		snap, err := systemDevice(t, binding.DeviceID)
		if err != nil {
			return windowssoftwarejob.ErrAuthority
		}
		var raw []byte
		var rejected int64
		if err = t.conn.QueryRowContext(ctx, `SELECT body,rejected_clock_floor FROM enrollment_windows_software_job_records WHERE invitation_id=?`, snap.InvitationID).Scan(&raw, &rejected); err == sql.ErrNoRows {
			return windowssoftwarejob.ErrUnavailable
		} else if err != nil {
			return ErrStorage
		}
		original, err := windowssoftwarejob.DecodeRecord(raw)
		if err != nil {
			return ErrStorage
		}
		r, err := windowssoftwarejob.DecodeRecord(raw)
		if err != nil {
			return ErrStorage
		}
		initial, err := windowsSoftwareJobNow(ctx, now)
		if err != nil {
			return err
		}
		floor := max(original.ClockFloor, rejected)
		current, authorityErr := s.windowsSoftwareJobCurrent(t, snap.InvitationID, binding, original.Consent, initial)
		if initial.Before(now) || initial.Unix() < floor {
			operationErr = windowssoftwarejob.ErrExpired
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
				operationErr = windowsSoftwareJobTransition(original, r, initial.Unix())
			}
			if operationErr == nil && r.Validate() != nil {
				operationErr = windowssoftwarejob.ErrInvalid
			}
		}
		// Persistence is deferred until the final authority check. The common
		// transaction still validates all unrelated credentials and used state.
		t.beforeCommit = append(t.beforeCommit, func() error {
			fresh, clockErr := windowsSoftwareJobNow(ctx, initial)
			observed := max(floor, initial.Unix())
			if clockErr == nil {
				observed = max(observed, fresh.Unix())
			}
			if clockErr != nil {
				operationErr = clockErr
			} else if fresh.Before(initial) || fresh.Unix() < floor {
				operationErr = windowssoftwarejob.ErrExpired
			}
			if operationErr == nil {
				final, err := s.windowsSoftwareJobCurrent(t, snap.InvitationID, binding, original.Consent, fresh)
				if errors.Is(err, ErrStorage) {
					return err
				}
				if err != nil {
					operationErr = err
				} else if final != current {
					operationErr = windowssoftwarejob.ErrAuthority
				} else {
					operationErr = windowsSoftwareJobFinalDeadline(original, r, final, fresh.Unix())
				}
			}
			if operationErr == nil {
				operationErr = windowssoftwarejob.CheckFinal(ctx)
				// Configuration reads and the session fence can block or reject.
				// Retain their last observed time even on rejection.
				last, clockErr := windowsSoftwareJobNow(ctx, fresh)
				if clockErr != nil || last.Before(fresh) {
					operationErr = windowssoftwarejob.ErrExpired
				} else {
					fresh = last
					observed = max(observed, last.Unix())
					if operationErr == nil {
						final, authorityErr := s.windowsSoftwareJobCurrent(t, snap.InvitationID, binding, original.Consent, last)
						if authorityErr != nil {
							operationErr = authorityErr
						} else if final != current {
							operationErr = windowssoftwarejob.ErrAuthority
						} else {
							operationErr = windowsSoftwareJobFinalDeadline(original, r, final, last.Unix())
						}
					}
				}
			}
			if operationErr != nil {
				r, err = windowssoftwarejob.DecodeRecord(raw)
				if err != nil {
					return ErrStorage
				}
				rejected = observed
			} else {
				r.ClockFloor = fresh.Unix()
			}
			body, err := windowssoftwarejob.EncodeRecord(r)
			if err != nil {
				return ErrStorage
			}
			if s.checkPath() != nil {
				return ErrStorage
			}
			writeStarted = true
			result, err := t.conn.ExecContext(ctx, `UPDATE enrollment_windows_software_job_records SET body=?,rejected_clock_floor=? WHERE invitation_id=?`, body, rejected, snap.InvitationID)
			if err != nil {
				return ErrStorage
			}
			if n, err := result.RowsAffected(); err != nil || n != 1 {
				return ErrStorage
			}
			if err = s.loadWindowsSoftwareJobRecords(ctx, t); err != nil {
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
			return windowssoftwarejob.Record{}, now, windowssoftwarejob.ErrUncertain
		}
		return windowssoftwarejob.Record{}, now, err
	}
	if operationErr != nil {
		return windowssoftwarejob.Record{}, now, operationErr
	}
	return out, now, nil
}

func (s *Store) WindowsSoftwareEnrollmentBinding() enrollmentstate.Binding {
	return s.Config().Binding
}

// ReadRegisteredWindowsSoftwareJob is a trusted startup snapshot only. It opens
// validated reciprocal state even for a now-retired/expired member so that one
// unavailable device cannot prevent other devices from starting. It grants no
// operation authority; every Manager operation still uses the live transaction.
func (s *Store) ReadRegisteredWindowsSoftwareJob(ctx context.Context, binding windowssoftwarejob.Binding, key ed25519.PublicKey) (windowssoftwarejob.Record, error) {
	var out windowssoftwarejob.Record
	if s == nil || ctx == nil || !windowssoftwarejob.ValidBinding(binding) || !keyvalidation.Ed25519(key) {
		return out, windowssoftwarejob.ErrInvalid
	}
	err := s.transact(ctx, func(t *transaction) error {
		if err := s.checkWindowsSoftwareJobKey(ctx, t, key); err != nil {
			return err
		}
		snap, err := systemDevice(t, binding.DeviceID)
		if err != nil {
			return windowssoftwarejob.ErrAuthority
		}
		var raw []byte
		if err = t.conn.QueryRowContext(ctx, `SELECT body FROM enrollment_windows_software_job_records WHERE invitation_id=?`, snap.InvitationID).Scan(&raw); err != nil {
			return windowssoftwarejob.ErrUnavailable
		}
		out, err = windowssoftwarejob.DecodeRecord(raw)
		if err != nil || out.Consent.Binding != binding || !bytes.Equal(out.PublicKey, key) {
			return windowssoftwarejob.ErrIntegrity
		}
		return windowssoftwarejob.CheckFinal(ctx)
	})
	if err != nil {
		return windowssoftwarejob.Record{}, err
	}
	return out, nil
}
