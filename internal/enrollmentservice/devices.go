package enrollmentservice

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/model"
	"time"
)

// Devices is operator-facing current-state inspection. It never turns receipt
// delivery into host health or installed-service evidence. Unknown/denied values
// remain distinct; valid old values are explicitly degraded to stale.
func (s *Service) Devices(ctx context.Context, now time.Time) ([]model.Device, error) {
	views, e := s.store.DeviceViews(ctx)
	if e != nil {
		return nil, e
	}
	snapshots := make([]enrollmentstate.Snapshot, 0, len(views))
	observations := make(map[string]model.Device, len(views))
	received := make(map[string]time.Time, len(views))
	for _, view := range views {
		snapshots = append(snapshots, view.Snapshot)
		if view.Observation != nil {
			sample := view.Observation
			observations[sample.Device.ID] = sample.Device
			received[sample.Device.ID] = sample.Receipt.ReceivedAt
		}
	}
	result := []model.Device{}
	for _, snapshot := range snapshots {
		id := snapshot.Approval.DeviceID
		if id == "" {
			continue
		}
		metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Awaiting activated enrolled agent observation"}
		d := model.Device{ID: id, Name: id, Platform: "unknown", OS: "Awaiting agent", Site: "Local network", Group: "Managed devices", Source: "lan", Status: "unknown", AgentVersion: "unknown", CPU: metric, Memory: metric, Disk: metric, Uptime: "Unknown", Tags: []string{"lan", "read-only", "guided-enrollment"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
		if snapshot.Binding.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && snapshot.Platform == "windows" {
			d.Platform = "windows"
			d.OS = "Awaiting Windows agent"
		}
		if observation, ok := observations[id]; ok {
			d = observation
			d.Capabilities = profileCapabilities(d.Capabilities, s.binding.CollectionProfile)
			old := now.Sub(received[id]) > 2*time.Minute || now.Sub(d.LastSeen) > 2*time.Minute || now.Before(received[id]) || now.Before(d.LastSeen)
			for _, m := range []model.Metric{d.CPU, d.Memory, d.Disk} {
				old = old || now.Sub(m.CollectedAt) > 2*time.Minute || now.Before(m.CollectedAt)
			}
			for _, e := range d.Evidence {
				old = old || now.Sub(e.CollectedAt) > 2*time.Minute || now.Before(e.CollectedAt)
			}
			if old {
				for _, m := range []*model.Metric{&d.CPU, &d.Memory, &d.Disk} {
					if m.Quality == "healthy" {
						m.Quality = "stale"
					}
				}
				for i := range d.Evidence {
					if d.Evidence[i].Quality == "healthy" {
						d.Evidence[i].Quality = "stale"
					}
				}
			}
		}
		// An issuance intent alone is not evidence that a certificate was issued.
		// Always overwrite any observation metadata with the committed ledger view.
		d.AgentCertificate = &model.AgentCertificate{Source: "guided-enrollment", CheckedAt: now.UTC()}
		if snapshot.Issuance.CertificateHash != "" && snapshot.Issuance.At > 0 && snapshot.Intent.NotAfter > 0 {
			expires := time.Unix(snapshot.Intent.NotAfter, 0).UTC()
			d.AgentCertificate.ExpiresAt = &expires
		}
		trust, detail := "limited", "Approval is recorded; credential activation and a first observation are still required."
		if snapshot.State == enrollmentstate.Activated {
			trust = "supported"
			detail = "Approved enrollment key and committed activation; this does not establish overall health or service installation."
		}
		if snapshot.State == enrollmentstate.Revoked || snapshot.State == enrollmentstate.Canceled || snapshot.State == enrollmentstate.Rejected || snapshot.State == enrollmentstate.Expired || snapshot.Intent.NotAfter > 0 && now.Unix() >= snapshot.Intent.NotAfter {
			trust = "denied"
			detail = "Enrollment is revoked, terminated or expired; new observations are rejected."
		}
		d.Capabilities = append(d.Capabilities, model.Capability{ID: "agent_identity", Name: "Enrolled agent identity", Status: trust, Detail: detail})
		result = append(result, d)
	}
	return result, nil
}
