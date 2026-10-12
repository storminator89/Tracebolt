package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"time"

	"localrmm/internal/keyvalidation"
	msi "localrmm/internal/windowsmanagedmsi"
)

// ReconcileWindowsManagedMSISchedulePolicy is startup-only terminalization under
// the exact reciprocal grant, without current-leaf admission or execution output.
// It cannot issue or change a permit, claim, readiness, grant, or original window.
func (s *Store) ReconcileWindowsManagedMSISchedulePolicy(ctx context.Context, binding msi.Binding, key ed25519.PublicKey, now func() time.Time, allowed func(string) bool) (msi.Record, error) {
	var out msi.Record
	if s == nil || s.storeState == nil || ctx == nil || !msi.ValidBinding(binding) || !keyvalidation.Ed25519(key) || now == nil || allowed == nil {
		return out, msi.ErrInvalid
	}
	wrote := false
	err := s.transact(ctx, func(t *transaction) error {
		if err := s.checkWindowsManagedMSIKey(ctx, t, key); err != nil {
			return err
		}
		snap, err := systemDevice(t, binding.DeviceID)
		if err != nil {
			return err
		}
		var raw []byte
		var rejected int64
		if err = t.conn.QueryRowContext(ctx, `SELECT body,rejected_clock_floor FROM enrollment_windows_managed_msi_records WHERE invitation_id=?`, snap.InvitationID).Scan(&raw, &rejected); err != nil {
			return ErrStorage
		}
		original, err := msi.DecodeRecord(raw)
		if err != nil || original.Grant.Binding != binding || !bytes.Equal(original.PublicKey, key) {
			return msi.ErrIntegrity
		}
		initial := now().UTC()
		if !validStoreTime(initial) {
			return msi.ErrInvalid
		}
		t.beforeCommit = append(t.beforeCommit, func() error {
			if err := msi.CheckFinal(ctx); err != nil {
				return err
			}
			fresh := now().UTC()
			if !validStoreTime(fresh) || fresh.Before(initial) {
				return msi.ErrExpired
			}
			// Revocation and leaf/grant expiry must not prevent removal of saved
			// authority. Retain every observed floor without advancing ClockFloor,
			// whose original successful-authority bounds must stay unchanged.
			floor := max(fresh.Unix(), original.ClockFloor, original.SchedulePolicyFloor, rejected)
			next, err := msi.DecodeRecord(raw)
			if err != nil {
				return err
			}
			if err = msi.TerminalizeSchedulePolicy(&next, floor, allowed); err != nil {
				return err
			}
			if err = windowsManagedMSITransition(original, next, floor); err != nil {
				return err
			}
			body, err := msi.EncodeRecord(next)
			if err != nil {
				return err
			}
			if s.checkPath() != nil {
				return ErrStorage
			}
			wrote = true
			result, err := t.conn.ExecContext(ctx, `UPDATE enrollment_windows_managed_msi_records SET body=?,rejected_clock_floor=? WHERE invitation_id=?`, body, max(rejected, floor), snap.InvitationID)
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
			out = next
			return ctx.Err()
		})
		return nil
	})
	if err != nil {
		if wrote {
			return msi.Record{}, msi.ErrUncertain
		}
		return msi.Record{}, err
	}
	return out, nil
}
