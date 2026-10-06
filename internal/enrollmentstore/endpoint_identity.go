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
	readState     *systemViewReadState
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
	release, e := s.systemReadAdmission(ctx)
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
		var err error
		now, err = systemViewNow(ctx, now)
		if err != nil {
			return err
		}
		out.ServerNow = now
		snap, e := systemDevice(t, device)
		if e != nil {
			return e
		}
		out, e = s.endpointIdentityFromSnapshot(t, snap, now)
		return e
	})
	if e != nil {
		return zero, e
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	now, e = systemViewNow(ctx, now)
	if e != nil {
		return zero, e
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return out.RecheckAt(now)
}

// RecheckAt ages only authorized metadata using its original capture time and
// certificate boundary. It does not refresh receipts, retention or stored floors.
func (v EndpointIdentityView) RecheckAt(now time.Time) (EndpointIdentityView, error) {
	if v.readState == nil || !validStoreTime(now) || !validStoreTime(v.readState.checkedAt) || !validStoreTime(v.ServerNow) {
		return EndpointIdentityView{}, ErrStorage
	}
	now = now.UTC()
	if now.Before(v.readState.checkedAt) {
		now = v.readState.checkedAt
	}
	if now.Before(v.ServerNow) {
		now = v.ServerNow
	}
	v.ServerNow = now
	if v.Status == "revoked" {
		return v, nil
	}
	if v.readState.certificateNotAfter > 0 && now.Unix() >= v.readState.certificateNotAfter {
		v.Status = "expired"
		v.Latest = nil
		return v, nil
	}
	if !v.readState.observationAt.IsZero() {
		v.Status = systemAge(v.readState.observationAt, now)
		if v.Status != "fresh" && v.Status != "stale" {
			v.Latest = nil
		}
	}
	return v, nil
}

// endpointIdentityFromSnapshot is shared by the single-device and bounded fleet
// reads. Call only within an admitted transaction; retain original authority/age.
func (s *Store) endpointIdentityFromSnapshot(t *transaction, snap enrollmentstate.Snapshot, now time.Time) (EndpointIdentityView, error) {
	out := EndpointIdentityView{SchemaVersion: "tracebolt.endpoint-identity-view.v1", DeviceID: snap.Approval.DeviceID, Status: "unknown", ServerNow: now, MaxAgeSeconds: int64(SystemMaxAge / time.Second)}
	out.readState = &systemViewReadState{checkedAt: now, certificateNotAfter: snap.Intent.NotAfter}
	status := systemIdentityStatus(snap, now)
	if status != "awaiting" {
		out.Status = status
		return out, nil
	}
	if _, e := s.systemAuthority(t, snap.InvitationID, snap.Issuance.CertificateHash, now); e != nil {
		return EndpointIdentityView{}, e
	}
	out.Status = "not_collected"
	r, ok := t.system[snap.InvitationID]
	if !ok || r.EndpointIdentity == nil {
		return out, nil
	}
	identity := r.EndpointIdentity
	p := identity.Receipt
	seq, received, expires := p.Sequence, p.ReceivedAt, p.CollectedAt.Add(SystemRetention)
	out.Sequence = &seq
	out.ReceivedAt = &received
	out.ExpiresAt = &expires
	out.readState.observationAt = p.CollectedAt
	out.Status = systemAge(p.CollectedAt, now)
	if out.Status == "fresh" || out.Status == "stale" {
		out.Latest = identity.Snapshot
	}
	return out, nil
}
