package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"time"

	"localrmm/internal/keyvalidation"
	job "localrmm/internal/windowsupdatejob"
)

// ReconcileWindowsUpdateSchedulePolicy is startup-only terminalization under
// the exact reciprocal grant, with no current-leaf admission or execution
// envelope output. It may never issue a challenge/permit, claim, reset or renew.
func (s *Store) ReconcileWindowsUpdateSchedulePolicy(ctx context.Context, binding job.Binding, key ed25519.PublicKey, now func() time.Time, allowed func(string) bool) (job.Record, error) {
	var out job.Record
	if s == nil || ctx == nil || !job.ValidBinding(binding) || !keyvalidation.Ed25519(key) || now == nil || allowed == nil {
		return out, job.ErrInvalid
	}
	wrote := false
	e := s.transact(ctx, func(t *transaction) error {
		if e := s.checkWindowsUpdateJobKey(ctx, t, key); e != nil {
			return e
		}
		snap, e := systemDevice(t, binding.DeviceID)
		if e != nil {
			return e
		}
		var raw []byte
		var rejected int64
		if e = t.conn.QueryRowContext(ctx, `SELECT body,rejected_clock_floor FROM enrollment_windows_update_job_records WHERE invitation_id=?`, snap.InvitationID).Scan(&raw, &rejected); e != nil {
			return ErrStorage
		}
		original, e := job.DecodeRecord(raw)
		if e != nil || original.Consent.Binding != binding || !bytes.Equal(original.PublicKey, key) {
			return job.ErrIntegrity
		}
		initial := now().UTC()
		if !validStoreTime(initial) {
			return job.ErrInvalid
		}
		t.beforeCommit = append(t.beforeCommit, func() error {
			if e := job.CheckFinal(ctx); e != nil {
				return e
			}
			fresh := now().UTC()
			if !validStoreTime(fresh) || fresh.Before(initial) {
				return job.ErrExpired
			}
			// Terminalization is safe even under rollback: use the retained floor,
			// never lower it or recreate dispatch eligibility.
			floor := max(fresh.Unix(), original.ClockFloor, original.SchedulePolicyFloor, rejected)
			next, e := job.DecodeRecord(raw)
			if e != nil {
				return e
			}
			if e = job.TerminalizeSchedulePolicy(&next, floor, allowed); e != nil {
				return e
			}
			if e = windowsUpdateJobTransition(original, next, floor); e != nil {
				return e
			}
			body, e := job.EncodeRecord(next)
			if e != nil {
				return e
			}
			if s.checkPath() != nil {
				return ErrStorage
			}
			wrote = true
			result, e := t.conn.ExecContext(ctx, `UPDATE enrollment_windows_update_job_records SET body=?,rejected_clock_floor=? WHERE invitation_id=?`, body, max(rejected, floor), snap.InvitationID)
			if e != nil {
				return ErrStorage
			}
			if n, e := result.RowsAffected(); e != nil || n != 1 {
				return ErrStorage
			}
			if e = s.loadWindowsUpdateJobRecords(ctx, t); e != nil {
				return e
			}
			if s.checkPath() != nil {
				return ErrStorage
			}
			out = next
			return ctx.Err()
		})
		return nil
	})
	if e != nil {
		if wrote {
			return job.Record{}, job.ErrUncertain
		}
		return job.Record{}, e
	}
	return out, nil
}
