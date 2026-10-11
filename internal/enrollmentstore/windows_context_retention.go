package enrollmentstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/inventoryledger"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssecuritycoverage"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstorage"
	"localrmm/internal/windowsstorageio"
	"localrmm/internal/windowsupdates"
	"time"
)

// Only bounded independent context snapshots, never a history or synthetic generation.
// This optional cache is not authority: the latest authenticated frame must
// still carry the same grant. Missing cache state loses availability only.
const windowsContextRetentionSchema = `CREATE TABLE enrollment_windows_context_retained(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id) ON DELETE CASCADE, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=81920)) STRICT`
const windowsContextRetentionBytes = 80 << 10

type WindowsContextRetained struct {
	Updates          *windowsupdates.Snapshot          `json:"updates,omitempty"`
	PatchContext     *windowspatchcontext.Snapshot     `json:"patchContext,omitempty"`
	SecurityPosture  *windowssecurity.Snapshot         `json:"securityPosture,omitempty"`
	SessionContext   *windowssessions.Snapshot         `json:"sessionContext,omitempty"`
	HardwareContext  *windowshardware.Snapshot         `json:"hardwareContext,omitempty"`
	StorageContext   *windowsstorage.Snapshot          `json:"storageContext,omitempty"`
	SecurityCoverage *windowssecuritycoverage.Snapshot `json:"securityCoverage,omitempty"`
	ResourceContext  *windowsresourcecontext.Snapshot  `json:"resourceContext,omitempty"`
	StorageIO        *windowsstorageio.Snapshot        `json:"storageIO,omitempty"`
}

func (v WindowsContextRetained) empty() bool {
	return v.Updates == nil && v.PatchContext == nil && v.SecurityPosture == nil && v.SessionContext == nil && v.HardwareContext == nil && v.StorageContext == nil && v.SecurityCoverage == nil && v.ResourceContext == nil && v.StorageIO == nil
}
func contextObserved(q string) bool { return q == "observed" || q == "partial" }
func usefulPatch(s *windowspatchcontext.Snapshot) bool {
	if s == nil {
		return false
	}
	return contextObserved(s.History.Quality) || s.OS.Edition.Value != nil || s.OS.Release.Value != nil || s.OS.Build.Value != nil || s.OS.Revision.Value != nil || s.Reboot.WindowsUpdate == "pending" || s.Reboot.WindowsUpdate == "clear" || s.Reboot.Servicing == "pending" || s.Reboot.Servicing == "clear" || s.Reboot.FileOperations == "pending" || s.Reboot.FileOperations == "clear"
}
func usefulSecurity(s *windowssecurity.Snapshot) bool {
	return s != nil && (contextObserved(s.Defender.Quality) || contextObserved(s.Firewall.Quality))
}
func usefulSessions(s *windowssessions.Snapshot) bool {
	return s != nil && (contextObserved(s.Sessions.Quality) || contextObserved(s.Join.Quality))
}
func usefulHardware(s *windowshardware.Snapshot) bool {
	if s == nil {
		return false
	}
	// A successful provider call can still contain only unknown sentinels.
	// Preserve the prior useful capture unless this whole scope has a value.
	return s.System.Manufacturer.Value != nil || s.System.Model.Value != nil ||
		s.Firmware.Vendor.Value != nil || s.Firmware.Version.Value != nil ||
		s.Firmware.ReleaseDate.Value != nil || s.Firmware.SerialNumber.Value != nil ||
		s.Chassis.SerialNumber.Value != nil || s.Power.ACLineStatus == "online" ||
		s.Power.ACLineStatus == "offline" || s.Power.BatteryPresence == "present" ||
		s.Power.BatteryPresence == "absent" || s.Power.Charging == "yes" ||
		s.Power.Charging == "no" || s.Power.BatteryPercent != nil || s.Power.EstimatedSeconds != nil
}

func usefulStorage(s *windowsstorage.Snapshot) bool {
	if s == nil {
		return false
	}
	if s.Drives.Quality == "observed" && s.Drives.Complete && len(s.Drives.Rows) == 0 || s.Disks.Quality == "observed" && s.Disks.Complete && len(s.Disks.Rows) == 0 {
		return true
	}
	for _, r := range s.Drives.Rows {
		if r.Quality == "observed" && r.VolumeGUID != nil {
			return true
		}
	}
	for _, r := range s.Disks.Rows {
		if r.DeviceID.Value != nil || r.FriendlyName.Value != nil || knownStorageHealth(r.HealthStatus) || knownStorageOperation(r.OperationalStatus) || knownStorageBus(r.BusType) || knownStorageMedia(r.MediaType) || r.SizeBytes != nil {
			return true
		}
	}
	return false
}

// Unknown, Other, reserved and unrecognized enum codes stay in the current
// observation, but alone cannot replace a prior useful capture or refresh age.
func knownStorageHealth(n *uint16) bool { return n != nil && *n <= 2 }
func knownStorageBus(n *uint16) bool {
	return n != nil && (*n >= 1 && *n <= 13 || *n >= 15 && *n <= 17)
}
func knownStorageMedia(n *uint16) bool { return n != nil && (*n == 3 || *n == 4 || *n == 5) }
func knownStorageOperation(values []uint16) bool {
	for _, n := range values {
		if n >= 2 && n <= 18 {
			return true
		}
	}
	return false
}

func windowsContextRetentionPresent(ctx context.Context, conn *sql.Conn) (bool, error) {
	var n int
	if conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name='enrollment_windows_context_retained'`).Scan(&n) != nil {
		return false, ErrStorage
	}
	return n == 1, nil
}
func windowsContextRetentionObject() inventoryledger.SchemaObject {
	return inventoryledger.SchemaObject{Type: "table", Name: "enrollment_windows_context_retained", SQL: windowsContextRetentionSchema}
}

func validRetainedContext(v WindowsContextRetained, f lanstore.Frame) bool {
	if f.WindowsInventory == nil {
		return v.empty()
	}
	valid := func(grant, currentGrant string, at time.Time) bool {
		return grant == currentGrant && !at.After(f.WindowsInventory.CollectedAt)
	}
	if s := v.Updates; s != nil && (f.WindowsUpdates == nil || windowsupdates.Validate(*s) != nil || !contextObserved(s.Quality) || !valid(s.GrantID, f.WindowsUpdates.GrantID, s.CollectedAt)) {
		return false
	}
	if s := v.PatchContext; s != nil && (f.WindowsPatchContext == nil || windowspatchcontext.Validate(*s) != nil || !usefulPatch(s) || !valid(s.GrantID, f.WindowsPatchContext.GrantID, s.CollectedAt)) {
		return false
	}
	if s := v.SecurityPosture; s != nil && (f.WindowsSecurityPosture == nil || windowssecurity.Validate(*s) != nil || !usefulSecurity(s) || !valid(s.GrantID, f.WindowsSecurityPosture.GrantID, s.CollectedAt)) {
		return false
	}
	if s := v.SessionContext; s != nil && (f.WindowsSessionContext == nil || windowssessions.Validate(*s) != nil || !usefulSessions(s) || !valid(s.GrantID, f.WindowsSessionContext.GrantID, s.CollectedAt)) {
		return false
	}
	if s := v.HardwareContext; s != nil && (f.WindowsHardwareContext == nil || windowshardware.Validate(*s) != nil || !usefulHardware(s) || !valid(s.GrantID, f.WindowsHardwareContext.GrantID, s.CollectedAt)) {
		return false
	}
	if s := v.StorageContext; s != nil && (f.WindowsStorageContext == nil || windowsstorage.Validate(*s) != nil || !usefulStorage(s) || !valid(s.GrantID, f.WindowsStorageContext.GrantID, s.CollectedAt)) {
		return false
	}
	if s := v.SecurityCoverage; s != nil && (f.WindowsSecurityCoverage == nil || windowssecuritycoverage.Validate(*s) != nil || !usefulCoverage(s) || !valid(s.GrantID, f.WindowsSecurityCoverage.GrantID, s.CollectedAt)) {
		return false
	}
	if s := v.ResourceContext; s != nil && (f.WindowsResourceContext == nil || windowsresourcecontext.Validate(*s) != nil || !usefulResource(s) || !valid(s.GrantID, f.WindowsResourceContext.GrantID, s.CollectedAt)) {
		return false
	}
	if s := v.StorageIO; s != nil && (f.WindowsStorageIO == nil || windowsstorageio.Validate(*s) != nil || !usefulStorageIO(s) || !valid(s.GrantID, f.WindowsStorageIO.GrantID, s.CollectedAt)) {
		return false
	}
	return true
}
func readRetainedWindowsContext(ctx context.Context, t *transaction, id string, f lanstore.Frame) (WindowsContextRetained, error) {
	var v WindowsContextRetained
	present, err := windowsContextRetentionPresent(ctx, t.conn)
	if err != nil || !present {
		return v, err
	}
	var raw []byte
	err = t.conn.QueryRowContext(ctx, `SELECT body FROM enrollment_windows_context_retained WHERE invitation_id=?`, id).Scan(&raw)
	if err == sql.ErrNoRows {
		return v, nil
	}
	if err != nil || len(raw) == 0 || len(raw) > windowsContextRetentionBytes || json.Unmarshal(raw, &v) != nil {
		return WindowsContextRetained{}, ErrStorage
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(raw, canonical) || v.empty() || !validRetainedContext(v, f) {
		return WindowsContextRetained{}, ErrStorage
	}
	return v, nil
}
func (v *WindowsContextRetained) expire(now time.Time) {
	if v.Updates != nil && now.Sub(v.Updates.CollectedAt) >= 24*time.Hour {
		v.Updates = nil
	}
	if v.PatchContext != nil && now.Sub(v.PatchContext.CollectedAt) >= 24*time.Hour {
		v.PatchContext = nil
	}
	if v.SecurityPosture != nil && now.Sub(v.SecurityPosture.CollectedAt) >= 24*time.Hour {
		v.SecurityPosture = nil
	}
	if v.SessionContext != nil && now.Sub(v.SessionContext.CollectedAt) >= 24*time.Hour {
		v.SessionContext = nil
	}
	if v.HardwareContext != nil && now.Sub(v.HardwareContext.CollectedAt) >= 24*time.Hour {
		v.HardwareContext = nil
	}
	if v.StorageContext != nil && now.Sub(v.StorageContext.CollectedAt) >= 24*time.Hour {
		v.StorageContext = nil
	}
	if v.SecurityCoverage != nil && now.Sub(v.SecurityCoverage.CollectedAt) >= 24*time.Hour {
		v.SecurityCoverage = nil
	}
	if v.ResourceContext != nil && now.Sub(v.ResourceContext.CollectedAt) >= 24*time.Hour {
		v.ResourceContext = nil
	}
	if v.StorageIO != nil && now.Sub(v.StorageIO.CollectedAt) >= 24*time.Hour {
		v.StorageIO = nil
	}
}
func retainWindowsContext(ctx context.Context, t *transaction, id string, old, current lanstore.Frame, now time.Time) error {
	if current.WindowsInventory == nil {
		return nil
	}
	v, err := readRetainedWindowsContext(ctx, t, id, old)
	if err != nil {
		return err
	}
	// Absence means disabled under the existing wire contract. Replacement is a
	// new grant, even if a later re-enable happens to use a familiar source.
	if current.WindowsUpdates == nil || v.Updates != nil && v.Updates.GrantID != current.WindowsUpdates.GrantID {
		v.Updates = nil
	}
	if current.WindowsPatchContext == nil || v.PatchContext != nil && v.PatchContext.GrantID != current.WindowsPatchContext.GrantID {
		v.PatchContext = nil
	}
	if current.WindowsSecurityPosture == nil || v.SecurityPosture != nil && v.SecurityPosture.GrantID != current.WindowsSecurityPosture.GrantID {
		v.SecurityPosture = nil
	}
	if current.WindowsSessionContext == nil || v.SessionContext != nil && v.SessionContext.GrantID != current.WindowsSessionContext.GrantID {
		v.SessionContext = nil
	}
	if current.WindowsHardwareContext == nil || v.HardwareContext != nil && v.HardwareContext.GrantID != current.WindowsHardwareContext.GrantID {
		v.HardwareContext = nil
	}
	if current.WindowsStorageContext == nil || v.StorageContext != nil && v.StorageContext.GrantID != current.WindowsStorageContext.GrantID {
		v.StorageContext = nil
	}
	if current.WindowsSecurityCoverage == nil || v.SecurityCoverage != nil && v.SecurityCoverage.GrantID != current.WindowsSecurityCoverage.GrantID {
		v.SecurityCoverage = nil
	}
	if current.WindowsResourceContext == nil || v.ResourceContext != nil && v.ResourceContext.GrantID != current.WindowsResourceContext.GrantID {
		v.ResourceContext = nil
	}
	if current.WindowsStorageIO == nil || v.StorageIO != nil && v.StorageIO.GrantID != current.WindowsStorageIO.GrantID {
		v.StorageIO = nil
	}
	if s := current.WindowsUpdates; s != nil && contextObserved(s.Quality) {
		v.Updates = s
	}
	if s := current.WindowsPatchContext; usefulPatch(s) {
		v.PatchContext = s
	}
	if s := current.WindowsSecurityPosture; usefulSecurity(s) {
		v.SecurityPosture = s
	}
	if s := current.WindowsSessionContext; usefulSessions(s) {
		v.SessionContext = s
	}
	if s := current.WindowsHardwareContext; usefulHardware(s) {
		v.HardwareContext = s
	}
	if s := current.WindowsStorageContext; usefulStorage(s) {
		v.StorageContext = s
	}
	if s := current.WindowsSecurityCoverage; usefulCoverage(s) {
		v.SecurityCoverage = s
	}
	if s := current.WindowsResourceContext; usefulResource(s) {
		v.ResourceContext = s
	}
	if s := current.WindowsStorageIO; usefulStorageIO(s) {
		v.StorageIO = s
	}
	v.expire(now)
	v.fitRetentionBudget()
	present, err := windowsContextRetentionPresent(ctx, t.conn)
	if err != nil {
		return err
	}
	if !present {
		if v.empty() {
			return nil
		}
		if _, err = t.conn.ExecContext(ctx, windowsContextRetentionSchema); err != nil {
			return ErrStorage
		}
	}
	if v.empty() {
		_, err = t.conn.ExecContext(ctx, `DELETE FROM enrollment_windows_context_retained WHERE invitation_id=?`, id)
	} else {
		raw, e := json.Marshal(v)
		if e != nil || len(raw) > windowsContextRetentionBytes || !validRetainedContext(v, current) {
			return ErrStorage
		}
		_, err = t.conn.ExecContext(ctx, `INSERT INTO enrollment_windows_context_retained(invitation_id,body) VALUES(?,?) ON CONFLICT(invitation_id) DO UPDATE SET body=excluded.body`, id, raw)
	}
	if err != nil {
		return ErrStorage
	}
	return nil
}

// Do not duplicate the current capture or replace its failure reason. The
// private response places an older useful observation alongside that attempt.
func retainedWindowsContextView(v WindowsContextRetained, f lanstore.Frame, now time.Time) *WindowsContextRetained {
	v.expire(now)
	if v.Updates != nil && f.WindowsUpdates != nil && !v.Updates.CollectedAt.Before(f.WindowsUpdates.CollectedAt) {
		v.Updates = nil
	}
	if v.PatchContext != nil && f.WindowsPatchContext != nil && !v.PatchContext.CollectedAt.Before(f.WindowsPatchContext.CollectedAt) {
		v.PatchContext = nil
	}
	if v.SecurityPosture != nil && f.WindowsSecurityPosture != nil && !v.SecurityPosture.CollectedAt.Before(f.WindowsSecurityPosture.CollectedAt) {
		v.SecurityPosture = nil
	}
	if v.SessionContext != nil && f.WindowsSessionContext != nil && !v.SessionContext.CollectedAt.Before(f.WindowsSessionContext.CollectedAt) {
		v.SessionContext = nil
	}
	if v.HardwareContext != nil && f.WindowsHardwareContext != nil && !v.HardwareContext.CollectedAt.Before(f.WindowsHardwareContext.CollectedAt) {
		v.HardwareContext = nil
	}
	if v.StorageContext != nil && f.WindowsStorageContext != nil && !v.StorageContext.CollectedAt.Before(f.WindowsStorageContext.CollectedAt) {
		v.StorageContext = nil
	}
	if v.SecurityCoverage != nil && f.WindowsSecurityCoverage != nil && !v.SecurityCoverage.CollectedAt.Before(f.WindowsSecurityCoverage.CollectedAt) {
		v.SecurityCoverage = nil
	}
	if v.ResourceContext != nil && f.WindowsResourceContext != nil && !v.ResourceContext.CollectedAt.Before(f.WindowsResourceContext.CollectedAt) {
		v.ResourceContext = nil
	}
	if v.StorageIO != nil && f.WindowsStorageIO != nil && !v.StorageIO.CollectedAt.Before(f.WindowsStorageIO.CollectedAt) {
		v.StorageIO = nil
	}
	if v.empty() {
		return nil
	}
	return &v
}

// Profile-bound rows are bounded by the existing credential/identity quota.
func validateWindowsContextRetentionCount(ctx context.Context, t *transaction, profile string) error {
	present, err := windowsContextRetentionPresent(ctx, t.conn)
	if err != nil || !present {
		return err
	}
	if profile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return ErrStorage
	}
	var count, orphans int
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_context_retained`).Scan(&count) != nil || count > len(t.credentials) {
		return ErrStorage
	}
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_context_retained r LEFT JOIN enrollment_credentials c ON c.invitation_id=r.invitation_id WHERE c.invitation_id IS NULL`).Scan(&orphans) != nil || orphans != 0 {
		return ErrStorage
	}
	return nil
}

// Scope omission/replacement deletes synchronously in retainWindowsContext.
// Identity termination deletes in the same transaction as the authority change.
func forgetWindowsContext(ctx context.Context, t *transaction, id string) error {
	present, err := windowsContextRetentionPresent(ctx, t.conn)
	if err != nil || !present {
		return err
	}
	if _, err = t.conn.ExecContext(ctx, `DELETE FROM enrollment_windows_context_retained WHERE invitation_id=?`, id); err != nil {
		return ErrStorage
	}
	return nil
}

// Reclaim one bounded credential row per existing manager maintenance step.
// The rolling slot chooses work only; latest identity/frame grant is authority.
func pruneWindowsContextStep(ctx context.Context, t *transaction, slot uint64, now time.Time) error {
	present, err := windowsContextRetentionPresent(ctx, t.conn)
	if err != nil || !present {
		return err
	}
	var count uint64
	if t.conn.QueryRowContext(ctx, `SELECT count(*) FROM enrollment_windows_context_retained`).Scan(&count) != nil || count > uint64(len(t.credentials)) {
		return ErrStorage
	}
	if count == 0 {
		return nil
	}
	var id string
	if t.conn.QueryRowContext(ctx, `SELECT invitation_id FROM enrollment_windows_context_retained ORDER BY invitation_id LIMIT 1 OFFSET ?`, slot%count).Scan(&id) != nil {
		return ErrStorage
	}
	identity, err := t.engine.Get(id)
	if err != nil {
		return ErrStorage
	}
	if identity.State != enrollmentstate.Activated || t.currentCredentialNotAfter(identity) <= now.Unix() {
		return forgetWindowsContext(ctx, t, id)
	}
	c, ok := t.credentials[id]
	if !ok || len(c.Frame) == 0 {
		return ErrStorage
	}
	frame, err := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
	if err != nil {
		return ErrStorage
	}
	v, err := readRetainedWindowsContext(ctx, t, id, frame)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(v)
	v.expire(now)
	if v.empty() {
		return forgetWindowsContext(ctx, t, id)
	}
	after, err := json.Marshal(v)
	if err != nil || len(after) > windowsContextRetentionBytes {
		return ErrStorage
	}
	if bytes.Equal(before, after) {
		return nil
	}
	if _, err = t.conn.ExecContext(ctx, `UPDATE enrollment_windows_context_retained SET body=? WHERE invitation_id=?`, after, id); err != nil {
		return ErrStorage
	}
	return nil
}

func (s *Store) MaintainWindowsContext(ctx context.Context, slot uint64, now time.Time) error {
	release, err := s.windowsFullServicesAdmission(ctx)
	if err != nil {
		return err
	}
	defer release()
	if !validStoreTime(now) {
		return enrollmentstate.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error { return pruneWindowsContextStep(ctx, t, slot, now.UTC()) })
}

// The cache is optional availability, not authority. Keep its historical 80 KiB
// table contract and evict oldest whole captures if independently full contexts
// would exceed it; no original age, scope or grant is rewritten.
func (v *WindowsContextRetained) fitRetentionBudget() {
	for {
		raw, e := json.Marshal(v)
		if e != nil || len(raw) <= windowsContextRetentionBytes {
			return
		}
		var oldest time.Time
		drop := func() {}
		choose := func(at time.Time, clear func()) {
			if oldest.IsZero() || at.Before(oldest) {
				oldest = at
				drop = clear
			}
		}
		if v.Updates != nil {
			choose(v.Updates.CollectedAt, func() { v.Updates = nil })
		}
		if v.PatchContext != nil {
			choose(v.PatchContext.CollectedAt, func() { v.PatchContext = nil })
		}
		if v.SecurityPosture != nil {
			choose(v.SecurityPosture.CollectedAt, func() { v.SecurityPosture = nil })
		}
		if v.SessionContext != nil {
			choose(v.SessionContext.CollectedAt, func() { v.SessionContext = nil })
		}
		if v.HardwareContext != nil {
			choose(v.HardwareContext.CollectedAt, func() { v.HardwareContext = nil })
		}
		if v.StorageContext != nil {
			choose(v.StorageContext.CollectedAt, func() { v.StorageContext = nil })
		}
		if v.SecurityCoverage != nil {
			choose(v.SecurityCoverage.CollectedAt, func() { v.SecurityCoverage = nil })
		}
		if v.ResourceContext != nil {
			choose(v.ResourceContext.CollectedAt, func() { v.ResourceContext = nil })
		}
		if v.StorageIO != nil {
			choose(v.StorageIO.CollectedAt, func() { v.StorageIO = nil })
		}
		if oldest.IsZero() {
			return
		}
		drop()
	}
}

func usefulCoverage(s *windowssecuritycoverage.Snapshot) bool {
	if s == nil {
		return false
	}
	if s.TPM.Presence != "unknown" || s.Antivirus.ReportedCount != nil && *s.Antivirus.ReportedCount == 0 && s.Antivirus.Quality == "observed" {
		return true
	}
	for _, p := range s.Antivirus.Rows {
		if p.Name != nil || p.State != "unknown" || p.SignatureStatus != "unknown" {
			return true
		}
	}
	return false
}

func usefulResource(s *windowsresourcecontext.Snapshot) bool {
	if s == nil {
		return false
	}
	for _, row := range s.Processors.Rows {
		if row.Name.Value != nil || row.Architecture.Value != nil || row.Cores.Value != nil || row.LogicalProcessors.Value != nil {
			return true
		}
	}
	return s.InstalledMemory.Quality == "observed" || s.Memory.Quality == "observed" || s.Pagefiles.Quality == "observed"
}

func usefulStorageIO(s *windowsstorageio.Snapshot) bool {
	return s != nil && windowsstorageio.Meaningful(*s)
}
