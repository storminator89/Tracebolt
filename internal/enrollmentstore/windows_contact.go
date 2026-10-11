package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
	"time"
)

// WindowsContactInputs is a separate operator-only authority contract. It reads
// only original accepted receipt metadata, never inventory rows or an endpoint.
// The Linux HealthInputs contract also authorizes AI and remains unchanged.
func (s *Store) WindowsContactInputs(ctx context.Context, now time.Time) ([]windowscontact.Input, error) {
	if s == nil || s.storeState == nil || ctx == nil || !validStoreTime(now) {
		return nil, enrollmentstate.ErrInvalid
	}
	if s.config.Binding.CollectionProfile != windowsmanaged.CollectionProfile {
		return nil, enrollmentstate.ErrProof
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.operationalReads <- struct{}{}:
		defer func() { <-s.operationalReads }()
	default:
		return nil, ErrOperationalBusy
	}
	out := []windowscontact.Input{}
	err := s.transact(ctx, func(t *transaction) error {
		for _, snap := range t.engine.Snapshots() {
			if snap.Approval.DeviceID == "" {
				continue
			}
			in := windowscontact.Input{DeviceID: snap.Approval.DeviceID, InvitationID: snap.InvitationID, CertificateHash: snap.Issuance.CertificateHash}
			if snap.Platform != "windows" || snap.Binding.CollectionProfile != windowsmanaged.CollectionProfile {
				out = append(out, in)
				continue
			}
			if err := t.authorizeCurrentCredential(snap, t.currentCertificateHash(snap), now); err != nil {
				if errors.Is(err, ErrStorage) {
					return err
				}
				out = append(out, in)
				continue
			}
			c, ok := t.credentials[snap.InvitationID]
			if !ok {
				return ErrStorage
			}
			if !c.Replay.ReceivedAt.IsZero() && now.Before(c.Replay.ReceivedAt) {
				return enrollmentstate.ErrInvalid
			}
			in.Authorized = true
			in.AuthorityUntil = time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()
			// transact already validates the credential's exact frame, hash,
			// platform/profile and replay tuple. Never replace receipt time by now.
			in.ReceivedAt = c.Replay.ReceivedAt
			in.Sequence = c.Replay.Sequence
			out = append(out, in)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
