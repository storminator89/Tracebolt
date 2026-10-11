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
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsupdates"
	"time"
)

// Only four bounded context snapshots, never a history or synthetic generation.
// This optional cache is not authority: the latest authenticated frame must
// still carry the same grant. Missing cache state loses availability only.
const windowsContextRetentionSchema = `CREATE TABLE enrollment_windows_context_retained(invitation_id TEXT PRIMARY KEY NOT NULL REFERENCES enrollment_credentials(invitation_id) ON DELETE CASCADE, body BLOB NOT NULL CHECK(length(body)>0 AND length(body)<=81920)) STRICT`
const windowsContextRetentionBytes = 80 << 10

type WindowsContextRetained struct {
	Updates         *windowsupdates.Snapshot      `json:"updates,omitempty"`
	PatchContext    *windowspatchcontext.Snapshot `json:"patchContext,omitempty"`
	SecurityPosture *windowssecurity.Snapshot     `json:"securityPosture,omitempty"`
	SessionContext  *windowssessions.Snapshot     `json:"sessionContext,omitempty"`
}

func (v WindowsContextRetained) empty() bool {
	return v.Updates == nil && v.PatchContext == nil && v.SecurityPosture == nil && v.SessionContext == nil
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
	v.expire(now)
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
	if identity.State != enrollmentstate.Activated || identity.Intent.NotAfter <= now.Unix() {
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
