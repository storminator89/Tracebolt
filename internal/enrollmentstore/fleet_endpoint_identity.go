package enrollmentstore

import (
	"context"
	"localrmm/internal/enrollmentstate"
	"sort"
	"time"
)

// Managed complete-profile enrollment is already limited to 25 records. This
// display-only projection uses that same bound, one admission and one transaction.
const FleetEndpointIdentityLimit = 25

type FleetEndpointIdentityView struct {
	SchemaVersion string                 `json:"schemaVersion"`
	ServerNow     time.Time              `json:"serverNow"`
	Items         []EndpointIdentityView `json:"items"`
}

func (s *Store) FleetEndpointIdentityView(ctx context.Context, now time.Time) (FleetEndpointIdentityView, error) {
	zero := FleetEndpointIdentityView{}
	release, err := s.systemReadAdmission(ctx)
	if err != nil {
		return zero, err
	}
	defer release()
	if !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	out := FleetEndpointIdentityView{SchemaVersion: "tracebolt.fleet-endpoint-identity.v1", ServerNow: now.UTC(), Items: make([]EndpointIdentityView, 0)}
	err = s.transact(ctx, func(t *transaction) error {
		var e error
		now, e = systemViewNow(ctx, now)
		if e != nil {
			return e
		}
		out.ServerNow = now
		snapshots := t.engine.Snapshots()
		if len(snapshots) > FleetEndpointIdentityLimit {
			return ErrStorage
		}
		for _, snap := range snapshots {
			if e := ctx.Err(); e != nil {
				return e
			}
			if snap.Approval.DeviceID == "" {
				continue
			}
			item, e := s.endpointIdentityFromSnapshot(t, snap, now)
			if e != nil {
				return e
			}
			out.Items = append(out.Items, item)
		}
		return nil
	})
	if err != nil {
		return zero, err
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	now, err = systemViewNow(ctx, now)
	if err != nil {
		return zero, err
	}
	if err = ctx.Err(); err != nil {
		return zero, err
	}
	sort.Slice(out.Items, func(i, j int) bool { return out.Items[i].DeviceID < out.Items[j].DeviceID })
	return out.RecheckAt(now)
}

func (v FleetEndpointIdentityView) RecheckAt(now time.Time) (FleetEndpointIdentityView, error) {
	if !validStoreTime(now) || !validStoreTime(v.ServerNow) || len(v.Items) > FleetEndpointIdentityLimit {
		return FleetEndpointIdentityView{}, ErrStorage
	}
	if now.Before(v.ServerNow) {
		now = v.ServerNow
	}
	v.ServerNow = now.UTC()
	for i, item := range v.Items {
		checked, err := item.RecheckAt(now)
		if err != nil {
			return FleetEndpointIdentityView{}, err
		}
		// A certificate can expire after its observation was authorized but before
		// the original 24-hour retention expires. Use the canonical value-free
		// expired wire form; do not make one authority-expired row invalidate the
		// whole strict browser batch. The durable receipt is never modified.
		if checked.Status == "expired" && checked.ExpiresAt != nil && checked.ServerNow.Before(*checked.ExpiresAt) {
			checked.Sequence, checked.ReceivedAt, checked.ExpiresAt = nil, nil, nil
		}
		v.Items[i] = checked
	}
	return v, nil
}

// ValidateAt checks already encoded metadata without mutating it or refreshing
// its timestamps. A changed freshness/authority state requires a fresh read;
// the caller must never emit bytes encoded before that boundary.
func (v FleetEndpointIdentityView) ValidateAt(now time.Time) error {
	if !validStoreTime(now) || !validStoreTime(v.ServerNow) || len(v.Items) > FleetEndpointIdentityLimit {
		return ErrStorage
	}
	if now.Before(v.ServerNow) {
		now = v.ServerNow
	}
	for _, item := range v.Items {
		checked, err := item.RecheckAt(now)
		if err != nil {
			return err
		}
		if checked.Status != item.Status || item.Latest != nil && checked.Latest == nil {
			return enrollmentstate.ErrExpired
		}
	}
	return nil
}
