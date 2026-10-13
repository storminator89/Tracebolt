package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
	"time"
)

// WithWindowsMonitoringAuthority is the manager-policy variant of the existing
// enrollment-to-operator lease. One bounded exact roster shares one enrollment
// transaction, never nested locks. It neither evaluates nor changes enrollment.
func (s *Store) WithWindowsMonitoringAuthority(ctx context.Context, expected []windowscontact.Input, clock func() time.Time, fn func(func(time.Time) error) error) error {
	if s == nil || s.storeState == nil || ctx == nil || clock == nil || fn == nil || len(expected) < 1 || len(expected) > 25 || s.config.Binding.CollectionProfile != windowsmanaged.CollectionProfile {
		return enrollmentstate.ErrProof
	}
	seen := map[string]bool{}
	for _, in := range expected {
		if !in.Authorized || seen[in.DeviceID] {
			return enrollmentstate.ErrProof
		}
		seen[in.DeviceID] = true
	}
	started := clock().UTC()
	if !validStoreTime(started) {
		return enrollmentstate.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		snapshots := make([]enrollmentstate.Snapshot, 0, len(expected))
		for _, in := range expected {
			snap, err := systemDevice(t, in.DeviceID)
			if err != nil {
				return err
			}
			snapshots = append(snapshots, snap)
		}
		last := started
		guard := func(minimum time.Time) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			at := clock().UTC()
			if !validStoreTime(at) || at.Before(started) || at.Before(last) || at.Before(minimum) || at.Sub(started) > 5*time.Second {
				return enrollmentstate.ErrProof
			}
			last = at
			for i, in := range expected {
				snap := snapshots[i]
				if !at.Before(in.AuthorityUntil) || snap.Platform != "windows" || snap.Binding != s.config.Binding || snap.InvitationID != in.InvitationID || snap.Issuance.CertificateHash != in.CertificateHash || !time.Unix(t.currentCredentialNotAfter(snap), 0).UTC().Equal(in.AuthorityUntil) {
					return enrollmentstate.ErrProof
				}
				if err := t.authorizeCurrentCredential(snap, t.currentCertificateHash(snap), at); err != nil {
					return err
				}
			}
			return nil
		}
		if err := guard(started); err != nil {
			return err
		}
		return fn(guard)
	})
}
