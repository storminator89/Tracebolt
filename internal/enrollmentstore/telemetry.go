package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
)

func validStoreTime(t time.Time) bool {
	return !t.IsZero() && t.Unix() > 0 && t.Unix() <= enrollmentstate.MaxTimestamp
}

// SaveObservation requires transport-authenticated certificate identity. Body
// identity never supplies authority. The same transaction rechecks activation,
// revocation, certificate expiry, and replay floor before retaining one bounded
// exact frame. Exact old-frame retries return the original receipt without
// refreshing connection or collection freshness.
func (s *Store) SaveObservation(ctx context.Context, invitationID, certificateHash string, raw []byte, receivedAt time.Time) (lanstore.Receipt, error) {
	if !enrollmentcrypto.ValidID(invitationID, "invite_") || !enrollmentcrypto.ValidHash(certificateHash) || len(raw) == 0 || len(raw) > lanstore.MaxFrameBytes || !validStoreTime(receivedAt) {
		return lanstore.Receipt{}, enrollmentstate.ErrInvalid
	}
	raw = bytes.Clone(raw)
	receivedAt = receivedAt.UTC()
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	var out lanstore.Receipt
	err := s.transact(ctx, func(t *transaction) error {
		t.pruneOperational(receivedAt)
		snapshot, err := t.engine.Get(invitationID)
		if err != nil {
			return err
		}
		if snapshot.State != enrollmentstate.Activated {
			return enrollmentstate.ErrState
		}
		if snapshot.Issuance.CertificateHash != certificateHash {
			return enrollmentstate.ErrProof
		}
		if receivedAt.Unix() < snapshot.UpdatedAt || receivedAt.Unix() < snapshot.Intent.NotBefore {
			return enrollmentstate.ErrInvalid
		}
		if receivedAt.Unix() >= snapshot.Intent.NotAfter {
			return enrollmentstate.ErrExpired
		}
		c, ok := t.credentials[invitationID]
		if !ok {
			return ErrStorage
		}
		previous := c.Replay
		if previous != (Replay{}) && receivedAt.Before(previous.ReceivedAt) {
			return enrollmentstate.ErrInvalid
		}
		if previous != (Replay{}) && digest == previous.PayloadHash && bytes.Equal(raw, c.Frame) {
			out = lanstore.Receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: snapshot.Approval.DeviceID, Sequence: previous.Sequence, CollectedAt: previous.CollectedAt, ReceivedAt: previous.ReceivedAt, Duplicate: true}
			return nil
		}
		frame, err := t.validateFrame(raw, receivedAt)
		if err != nil {
			return err
		}
		if !lanstore.FrameMatchesCollectionProfile(frame, snapshot.Binding.CollectionProfile) || frame.Observation.Observation.Platform != snapshot.Platform {
			return enrollmentstate.ErrProof
		}
		if previous != (Replay{}) && (frame.Sequence <= previous.Sequence || !frame.Observation.GeneratedAt.After(previous.GeneratedAt) || !frame.Observation.Observation.LastSeen.After(previous.CollectedAt)) {
			return lanstore.ErrReplay
		}

		if frame.WindowsInventory != nil && previous != (Replay{}) {
			old, e := t.validateFrame(c.Frame, previous.ReceivedAt)
			if e != nil || old.WindowsInventory == nil {
				return ErrStorage
			}
			// A later base capture carries the startup capture floor through any
			// number of scope-absent frames without a new ledger or migration.
			if old.WindowsServiceStartup != nil && !frame.WindowsInventory.CollectedAt.After(old.WindowsServiceStartup.CollectedAt) {
				return lanstore.ErrReplay
			}
			if frame.WindowsServiceStartup != nil && old.WindowsServiceStartup != nil && !frame.WindowsServiceStartup.CollectedAt.After(old.WindowsServiceStartup.CollectedAt) {
				return lanstore.ErrReplay
			}
			// Advance the base capture past the previous network snapshot even when
			// this frame omits that optional scope. Future network captures cannot fall
			// below their own base, so omission cannot erase the durable capture floor.
			if old.WindowsNetwork != nil && !frame.WindowsInventory.CollectedAt.After(old.WindowsNetwork.CollectedAt) {
				return lanstore.ErrReplay
			}
			if frame.WindowsNetwork != nil && old.WindowsNetwork != nil && !frame.WindowsNetwork.CollectedAt.After(old.WindowsNetwork.CollectedAt) {
				return lanstore.ErrReplay
			}
			if frame.WindowsProcessMetrics != nil && old.WindowsProcessMetrics != nil && !frame.WindowsProcessMetrics.CollectedAt.After(old.WindowsProcessMetrics.CollectedAt) {
				return lanstore.ErrReplay
			}
			if frame.WindowsVolumes != nil && old.WindowsVolumes != nil && !frame.WindowsVolumes.CollectedAt.After(old.WindowsVolumes.CollectedAt) {
				return lanstore.ErrReplay
			}
			if frame.WindowsEvents != nil && old.WindowsEvents != nil && !frame.WindowsEvents.CollectedAt.After(old.WindowsEvents.CollectedAt) {
				return lanstore.ErrReplay
			}
			if !frame.WindowsInventory.CollectedAt.After(old.WindowsInventory.CollectedAt) || frame.WindowsInventory.GenerationID == old.WindowsInventory.GenerationID {
				return lanstore.ErrReplay
			}
		}
		if frame.Operational != nil {
			if previous != (Replay{}) {
				old, e := t.validateFrame(c.Frame, previous.ReceivedAt)
				if e != nil || old.Operational == nil {
					return ErrStorage
				}
				if !frame.Operational.CollectedAt.After(old.Operational.CollectedAt) || frame.Operational.GenerationID == old.Operational.GenerationID {
					return lanstore.ErrReplay
				}
			}
			t.retainOperational(invitationID, frame.Operational)
		}
		c.Replay = Replay{Sequence: frame.Sequence, PayloadHash: digest, GeneratedAt: frame.Observation.GeneratedAt.UTC(), CollectedAt: frame.Observation.Observation.LastSeen.UTC(), ReceivedAt: receivedAt}
		c.Frame = raw
		t.credentials[invitationID] = c
		// Every activated identity already has a credential row. Retain the
		// observation and advance its replay receipt in this same transaction.
		if err := retainResourcePoint(ctx, t, invitationID, frame.Sequence, frame.Observation.Observation, receivedAt); err != nil {
			return err
		}
		out = lanstore.Receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: snapshot.Approval.DeviceID, Sequence: frame.Sequence, CollectedAt: c.Replay.CollectedAt, ReceivedAt: receivedAt}
		return nil
	})
	if err != nil {
		return lanstore.Receipt{}, err
	}
	return out, nil
}

type Observation struct {
	Device  model.Device
	Receipt lanstore.Receipt
	State   enrollmentstate.State
}

// LatestObservations is an operator-side inspection result. Receipt timestamps
// are historical facts and must not be presented as evidence of a live service.
type DeviceView struct {
	Snapshot    enrollmentstate.Snapshot
	Observation *Observation
}

// DeviceViews joins identity state and current observation in one validated
// transaction. Approved identities with no observation remain visible.
func (s *Store) DeviceViews(ctx context.Context) ([]DeviceView, error) {
	out := []DeviceView{}
	err := s.transact(ctx, func(t *transaction) error {
		for _, snapshot := range t.engine.Snapshots() {
			if snapshot.Approval.DeviceID == "" {
				continue
			}
			c, ok := t.credentials[snapshot.InvitationID]
			if !ok || len(c.Frame) == 0 {
				out = append(out, DeviceView{Snapshot: snapshot})
				continue
			}
			frame, err := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
			if err != nil {
				return ErrStorage
			}
			d := frame.Observation.Observation
			d.ID = snapshot.Approval.DeviceID
			d.Name = d.ID
			d.Site = "Local network"
			d.Group = "Managed devices"
			d.Source = "lan"
			d.IP = nil
			d.Synthetic = false
			d.Status = "unknown"
			d.Tags = []string{"lan", "read-only", "guided-enrollment"}
			observation := Observation{Device: d, Receipt: lanstore.Receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: d.ID, Sequence: c.Replay.Sequence, CollectedAt: c.Replay.CollectedAt, ReceivedAt: c.Replay.ReceivedAt}, State: snapshot.State}
			out = append(out, DeviceView{Snapshot: snapshot, Observation: &observation})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) LatestObservations(ctx context.Context) ([]Observation, error) {
	views, e := s.DeviceViews(ctx)
	if e != nil {
		return nil, e
	}
	out := []Observation{}
	for _, view := range views {
		if view.Observation != nil {
			out = append(out, *view.Observation)
		}
	}
	return out, nil
}
