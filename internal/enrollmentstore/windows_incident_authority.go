package enrollmentstore

import (
	"context"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
)

// WithWindowsIncidentAuthority holds the enrollment BEGIN IMMEDIATE lease while
// the caller commits manager-only acknowledgement metadata. Lock order is always
// enrollment then operator SQLite. Revocation/replacement/renewal cannot commit
// between this fresh authority admission and the acknowledgement commit.
// The callback must not call back into enrollment. Its guard uses this locked
// transaction and a fresh trusted clock after operator waits and before commit.
// This neither changes enrollment nor grants collection or endpoint actions.
func (s *Store) WithWindowsIncidentAuthority(ctx context.Context, expected windowscontact.Input, clock func() time.Time, fn func(func(time.Time) error) error) error {
	if s == nil || s.storeState == nil || ctx == nil || clock == nil || fn == nil || !expected.Authorized || s.config.Binding.CollectionProfile != windowsmanaged.CollectionProfile {
		return enrollmentstate.ErrProof
	}
	started := clock().UTC()
	if !validStoreTime(started) {
		return enrollmentstate.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		snap, err := systemDevice(t, expected.DeviceID)
		if err != nil {
			return err
		}
		last := started
		guard := func(minimum time.Time) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			at := clock().UTC()
			if !validStoreTime(at) || at.Before(started) || at.Before(last) || at.Before(minimum) || at.Sub(started) > 5*time.Second || !at.Before(expected.AuthorityUntil) || snap.Platform != "windows" || snap.Binding != s.config.Binding || snap.InvitationID != expected.InvitationID || snap.Issuance.CertificateHash != expected.CertificateHash || !time.Unix(t.currentCredentialNotAfter(snap), 0).UTC().Equal(expected.AuthorityUntil) {
				return enrollmentstate.ErrProof
			}
			last = at
			return t.authorizeCurrentCredential(snap, t.currentCertificateHash(snap), at)
		}
		if err := guard(started); err != nil {
			return err
		}
		return fn(guard)
	})
}
