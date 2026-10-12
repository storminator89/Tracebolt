package enrollmentstore

import (
	"context"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
)

// WithWindowsNotificationAuthority additionally pins the exact accepted report
// selected by WindowsCapacityInputs. The old acknowledgement lease is unchanged:
// seen metadata needs identity authority, while dispatch also needs current source
// evidence. Receipt sequence/time identify the validated immutable frame. The
// callback must never re-enter enrollment; this lease spans claim commit, not HTTP.
func (s *Store) WithWindowsNotificationAuthority(ctx context.Context, expected windowscontact.Input, clock func() time.Time, fn func(func(time.Time) error) error) error {
	if s == nil || s.storeState == nil || ctx == nil || clock == nil || fn == nil || !expected.Authorized || s.config.Binding.CollectionProfile != windowsmanaged.CollectionProfile {
		return enrollmentstate.ErrProof
	}
	started := clock().UTC()
	if !validStoreTime(started) {
		return enrollmentstate.ErrInvalid
	}
	return s.transact(ctx, func(t *transaction) error {
		snap, e := systemDevice(t, expected.DeviceID)
		if e != nil {
			return e
		}
		last := started
		guard := func(minimum time.Time) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			at := clock().UTC()
			credential, ok := t.credentials[snap.InvitationID]
			if !ok || credential.Replay.Sequence != expected.Sequence || !credential.Replay.ReceivedAt.Equal(expected.ReceivedAt) || !validStoreTime(at) || at.Before(started) || at.Before(last) || at.Before(minimum) || at.Sub(started) > 5*time.Second || !at.Before(expected.AuthorityUntil) || snap.Platform != "windows" || snap.Binding != s.config.Binding || snap.InvitationID != expected.InvitationID || snap.Issuance.CertificateHash != expected.CertificateHash || !time.Unix(t.currentCredentialNotAfter(snap), 0).UTC().Equal(expected.AuthorityUntil) {
				return enrollmentstate.ErrProof
			}
			last = at
			return t.authorizeCurrentCredential(snap, t.currentCertificateHash(snap), at)
		}
		if e := guard(started); e != nil {
			return e
		}
		return fn(guard)
	})
}
