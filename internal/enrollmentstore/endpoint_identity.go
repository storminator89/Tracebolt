package enrollmentstore

import (
	"context"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/enrollmentstate"
	"time"
)

// EndpointIdentityView is operator-only, untrusted display metadata. It is
// separate from Device, so it cannot become a device routing key or AI packet.
type EndpointIdentityView struct {
	SchemaVersion string                     `json:"schemaVersion"`
	DeviceID      string                     `json:"deviceId"`
	Status        string                     `json:"status"`
	ServerNow     time.Time                  `json:"serverNow"`
	MaxAgeSeconds int64                      `json:"maxAgeSeconds"`
	Sequence      *uint64                    `json:"sequence,string"`
	ReceivedAt    *time.Time                 `json:"receivedAt"`
	ExpiresAt     *time.Time                 `json:"expiresAt"`
	Latest        *endpointidentity.Snapshot `json:"latest"`
}

func (s *Store) EndpointIdentityView(ctx context.Context, device string, now time.Time) (EndpointIdentityView, error) {
	zero := EndpointIdentityView{}
	release, e := s.inventoryAdmission(ctx)
	if e != nil {
		return zero, e
	}
	defer release()
	if !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	now = now.UTC()
	out := EndpointIdentityView{SchemaVersion: "tracebolt.endpoint-identity-view.v1", DeviceID: device, Status: "unknown", ServerNow: now, MaxAgeSeconds: int64(SystemMaxAge / time.Second)}
	e = s.transact(ctx, func(t *transaction) error {
		snap, e := systemDevice(t, device)
		if e != nil {
			return e
		}
		status := systemIdentityStatus(snap, now)
		if status != "awaiting" {
			out.Status = status
			return nil
		}
		if _, e = s.systemAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now); e != nil {
			return e
		}
		out.Status = "not_collected"
		r, ok := t.system[snap.InvitationID]
		if !ok || r.EndpointIdentity == nil {
			return nil
		}
		identity := r.EndpointIdentity
		p := identity.Receipt
		seq, received, expires := p.Sequence, p.ReceivedAt, p.CollectedAt.Add(SystemRetention)
		out.Sequence = &seq
		out.ReceivedAt = &received
		out.ExpiresAt = &expires
		out.Status = systemAge(p.CollectedAt, now)
		if out.Status == "fresh" || out.Status == "stale" {
			out.Latest = identity.Snapshot
		}
		return nil
	})
	if e != nil {
		return zero, e
	}
	return out, nil
}
