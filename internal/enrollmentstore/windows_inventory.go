package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
	"time"
)

// WindowsInventoryView exposes only the latest profile-bound bounded frame.
// It has no fallback to Linux operations, an old healthy generation or host reads.
type WindowsInventoryView struct {
	SchemaVersion       string                          `json:"schemaVersion"`
	DeviceID            string                          `json:"deviceId"`
	CollectionProfile   string                          `json:"collectionProfile"`
	ServerNow           time.Time                       `json:"serverNow"`
	MaxAgeSeconds       int64                           `json:"maxAgeSeconds"`
	Status              string                          `json:"status"`
	Sequence            *uint64                         `json:"sequence"`
	ReceivedAt          *time.Time                      `json:"receivedAt"`
	Snapshot            *windowsmanaged.Snapshot        `json:"snapshot"`
	Events              *windowseventhealth.Snapshot    `json:"events,omitempty"`
	Volumes             *windowsvolumes.Snapshot        `json:"volumes,omitempty"`
	ProcessMetrics      *windowsprocessmetrics.Snapshot `json:"processMetrics,omitempty"`
	Network             *windowsnetwork.Snapshot        `json:"network,omitempty"`
	certificateNotAfter int64
}

func EmptyWindowsInventoryView(id string, now time.Time) WindowsInventoryView {
	return WindowsInventoryView{SchemaVersion: "tracebolt.windows-inventory-view.v1", DeviceID: id, CollectionProfile: windowsmanaged.CollectionProfile, ServerNow: now.UTC(), MaxAgeSeconds: int64(lanstore.SampleMaxAge / time.Second), Status: "not_configured"}
}
func (s *Store) WindowsInventoryView(ctx context.Context, id string, now time.Time) (WindowsInventoryView, error) {
	if s == nil || s.storeState == nil || ctx == nil {
		return WindowsInventoryView{}, ErrStorage
	}
	if !validStoreTime(now) || !enrollmentcrypto.ValidID(id, "agent_") {
		return WindowsInventoryView{}, enrollmentstate.ErrInvalid
	}
	select {
	case s.operationalReads <- struct{}{}:
		defer func() { <-s.operationalReads }()
	default:
		return WindowsInventoryView{}, ErrOperationalBusy
	}
	out := EmptyWindowsInventoryView(id, now)
	err := s.transact(ctx, func(t *transaction) error {
		var identity enrollmentstate.Snapshot
		found := false
		for _, v := range t.engine.Snapshots() {
			if v.Approval.DeviceID == id {
				identity = v
				found = true
				break
			}
		}
		if !found {
			return enrollmentstate.ErrNotFound
		}
		if identity.Binding.CollectionProfile != windowsmanaged.CollectionProfile || identity.Platform != "windows" || identity.Binding.Profile != "tls" && identity.Binding.Profile != "http-test" {
			return nil
		}
		out.Status = "awaiting"
		out.certificateNotAfter = identity.Intent.NotAfter
		c, ok := t.credentials[identity.InvitationID]
		if ok && len(c.Frame) > 0 {
			frame, err := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
			if err != nil || frame.WindowsInventory == nil {
				return ErrStorage
			}
			copy := *frame.WindowsInventory
			seq, received := c.Replay.Sequence, c.Replay.ReceivedAt
			if now.Before(received) {
				return enrollmentstate.ErrInvalid
			}
			out.Snapshot = &copy
			out.Events = frame.WindowsEvents
			out.Volumes = frame.WindowsVolumes
			out.ProcessMetrics = frame.WindowsProcessMetrics
			out.Network = frame.WindowsNetwork
			out.Sequence = &seq
			out.ReceivedAt = &received
			out.Status = "fresh"
			if now.Before(received) || now.Before(copy.CollectedAt) || now.Sub(received) > lanstore.SampleMaxAge || now.Sub(copy.CollectedAt) > lanstore.SampleMaxAge {
				out.Status = "stale"
			}
			if now.Sub(copy.CollectedAt) >= 24*time.Hour {
				out.Status = "unavailable"
				out.Snapshot = nil
				out.Events = nil
				out.Volumes = nil
				out.ProcessMetrics = nil
				out.Network = nil
			}
		}
		if identity.State == enrollmentstate.Revoked || identity.State == enrollmentstate.Canceled || identity.State == enrollmentstate.Rejected || identity.State == enrollmentstate.Expired || identity.Intent.NotAfter > 0 && now.Unix() >= identity.Intent.NotAfter {
			out.Status = "revoked"
			out.Snapshot = nil
			out.Events = nil
			out.Volumes = nil
			out.ProcessMetrics = nil
			out.Network = nil
		}
		return nil
	})
	if err != nil {
		return WindowsInventoryView{}, err
	}
	return out.RecheckAt(now)
}

// RecheckAt cannot refresh capture/receipt times. The operator calls it once
// more after the store read so a slow response cannot retain a fresh/valid label.
func (v WindowsInventoryView) RecheckAt(now time.Time) (WindowsInventoryView, error) {
	if !validStoreTime(now) || now.Before(v.ServerNow) || v.ReceivedAt != nil && now.Before(*v.ReceivedAt) {
		return WindowsInventoryView{}, enrollmentstate.ErrInvalid
	}
	v.ServerNow = now.UTC()
	if v.Status == "revoked" || v.certificateNotAfter > 0 && now.Unix() >= v.certificateNotAfter {
		v.Status = "revoked"
		v.Snapshot = nil
		v.Events = nil
		v.Volumes = nil
		v.ProcessMetrics = nil
		v.Network = nil
		return v, nil
	}
	if v.Snapshot != nil {
		if v.ReceivedAt == nil || v.Sequence == nil || *v.Sequence == 0 {
			return WindowsInventoryView{}, ErrStorage
		}
		if v.Snapshot.CollectedAt.Sub(now) > lanstore.AllowedClockSkew {
			return WindowsInventoryView{}, enrollmentstate.ErrInvalid
		}
		v.Status = "fresh"
		if now.Before(v.Snapshot.CollectedAt) || now.Sub(v.Snapshot.CollectedAt) > lanstore.SampleMaxAge || now.Sub(*v.ReceivedAt) > lanstore.SampleMaxAge {
			v.Status = "stale"
		}
		if now.Sub(v.Snapshot.CollectedAt) >= 24*time.Hour {
			v.Status = "unavailable"
			v.Snapshot = nil
			v.Events = nil
			v.Volumes = nil
			v.ProcessMetrics = nil
			v.Network = nil
		}
	}
	if v.Events != nil && now.Sub(v.Events.CollectedAt) >= 24*time.Hour {
		v.Events = nil
	}
	if v.Volumes != nil && now.Sub(v.Volumes.CollectedAt) >= 24*time.Hour {
		v.Volumes = nil
	}
	if v.ProcessMetrics != nil && now.Sub(v.ProcessMetrics.CollectedAt) >= 24*time.Hour {
		v.ProcessMetrics = nil
	}
	if v.Network != nil && now.Sub(v.Network.CollectedAt) >= 24*time.Hour {
		v.Network = nil
	}
	return v, nil
}
