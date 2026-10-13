package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowscapacity"
	"localrmm/internal/windowscontact"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsservicehealth"
	"time"
)

// WindowsCapacityInputs reads the existing accepted basic metrics, service metadata and
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
	selections, err := windowsservicehealth.CompleteSelections(ctx)
	if err != nil {
		return nil, err
	}
	out := []windowscapacity.Input{}
	err = s.transact(ctx, func(t *transaction) error {
		for _, snap := range t.engine.Snapshots() {
			if snap.Approval.DeviceID == "" {
				continue
			}
			in := windowscapacity.Input{Input: windowscontact.Input{DeviceID: snap.Approval.DeviceID, InvitationID: snap.InvitationID, CertificateHash: snap.Issuance.CertificateHash}}
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
			in.CurrentLeaf = t.currentCertificateHash(snap)
			in.AuthorityUntil = time.Unix(t.currentCredentialNotAfter(snap), 0).UTC()
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
				in.Services = windowsservicehealth.Sample{CollectedAt: frame.WindowsInventory.CollectedAt, Services: frame.WindowsInventory.Services}
			}
			if names, requested := selections[in.DeviceID]; requested {
				present, e := windowsFullServicesSchemaPresent(ctx, t.conn, s.config.Binding.CollectionProfile)
				if e != nil {
					return e
				}
				if present {
					in.Services.Complete, e = readCompleteServiceHealth(ctx, t, in.DeviceID, names, now)
					if e != nil {
						return e
					}
				}
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
