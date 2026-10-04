package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/linuxpackages"
	"time"
)

// PackageView exposes the latest exact package component only. Its original
// collection quality remains unchanged; Status describes receipt/identity age.
// View expiry hides old observations but does not erase the durable replay frame.
type PackageView struct {
	SchemaVersion string                  `json:"schemaVersion"`
	DeviceID      string                  `json:"deviceId"`
	Status        string                  `json:"status"`
	ServerNow     time.Time               `json:"serverNow"`
	ReceivedAt    *time.Time              `json:"receivedAt"`
	Sequence      *uint64                 `json:"sequence"`
	MaxAgeSeconds int64                   `json:"maxAgeSeconds"`
	Snapshot      *linuxpackages.Snapshot `json:"snapshot"`
}

func EmptyPackageView(id string, now time.Time) PackageView {
	return PackageView{SchemaVersion: "tracebolt.package-view.v1", DeviceID: id, Status: "not_configured", ServerNow: now.UTC(), MaxAgeSeconds: int64(lanstore.SampleMaxAge / time.Second)}
}
func (s *Store) PackageView(ctx context.Context, id string, now time.Time) (PackageView, error) {
	if s == nil || s.storeState == nil || ctx == nil {
		return PackageView{}, ErrStorage
	}
	if ctx.Err() != nil {
		return PackageView{}, ctx.Err()
	}
	select {
	case s.operationalReads <- struct{}{}:
		defer func() { <-s.operationalReads }()
	default:
		return PackageView{}, ErrOperationalBusy
	}
	if !validStoreTime(now) {
		return PackageView{}, enrollmentstate.ErrInvalid
	}
	out := EmptyPackageView(id, now)
	err := s.transact(ctx, func(t *transaction) error {
		var snapshot enrollmentstate.Snapshot
		found := false
		for _, entry := range t.engine.Snapshots() {
			if entry.Approval.DeviceID == id {
				snapshot = entry
				found = true
				break
			}
		}
		if !found {
			return enrollmentstate.ErrNotFound
		}
		if snapshot.Binding.CollectionProfile != enrollmentcrypto.CollectionProfilePackages {
			return nil
		}
		out.Status = "awaiting"
		if c, ok := t.credentials[snapshot.InvitationID]; ok && len(c.Frame) > 0 {
			frame, e := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
			if e != nil || frame.Packages == nil {
				return ErrStorage
			}
			sequence, received := c.Replay.Sequence, c.Replay.ReceivedAt
			out.Sequence = &sequence
			out.ReceivedAt = &received
			out.Status = "fresh"
			out.Snapshot = clonePackageSnapshot(frame.Packages)
			at := out.Snapshot.CollectedAt
			if now.Before(received) || now.Before(at) || now.Sub(received) > lanstore.SampleMaxAge || now.Sub(at) > lanstore.SampleMaxAge {
				out.Status = "stale"
			}
			if now.Sub(at) >= OperationalRetention {
				out.Status = "unavailable"
				out.Snapshot = nil
			}
		}
		if snapshot.State == enrollmentstate.Revoked || snapshot.State == enrollmentstate.Canceled || snapshot.State == enrollmentstate.Rejected || snapshot.State == enrollmentstate.Expired || snapshot.Intent.NotAfter > 0 && now.Unix() >= snapshot.Intent.NotAfter {
			out.Status = "revoked"
		}
		return nil
	})
	if err != nil {
		return PackageView{}, err
	}
	return out, nil
}
func clonePackageSnapshot(in *linuxpackages.Snapshot) *linuxpackages.Snapshot {
	if in == nil {
		return nil
	}
	out := *in
	out.Release.Fields.ID = copiedPointer(in.Release.Fields.ID)
	out.Release.Fields.VersionID = copiedPointer(in.Release.Fields.VersionID)
	out.Release.Fields.VersionCodename = copiedPointer(in.Release.Fields.VersionCodename)
	out.Inventory.ObservedCount = copiedPointer(in.Inventory.ObservedCount)
	out.Inventory.InstalledCount = copiedPointer(in.Inventory.InstalledCount)
	if in.Inventory.Items != nil {
		out.Inventory.Items = append(make([]linuxpackages.PackageRow, 0, len(in.Inventory.Items)), in.Inventory.Items...)
	}
	return &out
}
