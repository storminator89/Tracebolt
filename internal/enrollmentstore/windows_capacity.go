package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
	"time"
)

// WindowsCapacityInputs reads the existing accepted basic percentage metrics and
// receipt in one authority transaction. It never reads a host or widens a grant.
// The Linux HealthInputs contract also authorizes AI and remains unchanged.
func (s *Store) WindowsCapacityInputs(ctx context.Context, now time.Time) ([]windowscapacity.Input, error) {
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
	out := []windowscapacity.Input{}
	err := s.transact(ctx, func(t *transaction) error {
		for _, snap := range t.engine.Snapshots() {
			if snap.Approval.DeviceID == "" {
				continue
			}
			in := windowscapacity.Input{Input: windowscontact.Input{DeviceID: snap.Approval.DeviceID, InvitationID: snap.InvitationID, CertificateHash: snap.Issuance.CertificateHash}}
			if snap.Platform != "windows" || snap.Binding.CollectionProfile != windowsmanaged.CollectionProfile || snap.State != enrollmentstate.Activated || now.Unix() < snap.UpdatedAt || now.Unix() < snap.Intent.NotBefore || now.Unix() >= snap.Intent.NotAfter {
				out = append(out, in)
				continue
			}
			c, ok := t.credentials[snap.InvitationID]
			if !ok {
				return ErrStorage
			}
			intent, err := t.engine.TrustedRecordedIntent(snap.InvitationID)
			if err != nil {
				return ErrStorage
			}
			cert, err := enrollmentcrypto.VerifyIssued(c.DER, s.issuerDER, intent, now)
			if err != nil || cert.CertificateHash() != snap.Issuance.CertificateHash {
				out = append(out, in)
				continue
			}
			if !c.Replay.ReceivedAt.IsZero() && now.Before(c.Replay.ReceivedAt) {
				return enrollmentstate.ErrInvalid
			}
			in.Authorized = true
			in.AuthorityUntil = time.Unix(snap.Intent.NotAfter, 0).UTC()
			// transact already validates the credential's exact frame, hash,
			// platform/profile and replay tuple. Never replace receipt time by now.
			in.ReceivedAt = c.Replay.ReceivedAt
			in.Sequence = c.Replay.Sequence
			if len(c.Frame) > 0 {
				frame, err := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
				if err != nil || frame.WindowsInventory == nil {
					return ErrStorage
				}
				in.Disk = frame.Observation.Observation.Disk
				in.CPU = frame.Observation.Observation.CPU
				in.Memory = frame.Observation.Observation.Memory
			}
			out = append(out, in)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
