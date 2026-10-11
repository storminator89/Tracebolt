package enrollmentstore

import (
	"context"
	"encoding/json"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsmanaged"
	"sort"
	"time"
)

// Two configured authorities each retain the existing 25-record bound.
const FleetIdentitiesLimit = 2 * FleetEndpointIdentityLimit

// FleetIdentityItem is a tagged wire union. Windows metadata never acquires the
// Linux endpointidentity scope, and neither alternative enters model.Device.
type FleetIdentityItem struct {
	Linux   *EndpointIdentityView
	Windows *WindowsFleetIdentityView
}

func (v FleetIdentityItem) MarshalJSON() ([]byte, error) {
	if (v.Linux == nil) == (v.Windows == nil) {
		return nil, ErrStorage
	}
	if v.Linux != nil {
		return json.Marshal(v.Linux)
	}
	return json.Marshal(v.Windows)
}

type FleetIdentitiesView struct {
	SchemaVersion string              `json:"schemaVersion"`
	ServerNow     time.Time           `json:"serverNow"`
	Items         []FleetIdentityItem `json:"items"`
}

// Only the original Windows hostname and interface-address sections are exposed.
// Source, scoped completeness and unavailable states are retained verbatim.
type WindowsFleetIdentitySnapshot struct {
	SchemaVersion     string                                                  `json:"schemaVersion"`
	CollectionProfile string                                                  `json:"collectionProfile"`
	GenerationID      string                                                  `json:"generationId"`
	CollectedAt       time.Time                                               `json:"collectedAt"`
	Hostname          windowsmanaged.Section[windowsmanaged.Hostname]         `json:"hostname"`
	Network           windowsmanaged.Section[windowsmanaged.InterfaceAddress] `json:"network"`
}
type WindowsFleetIdentityView struct {
	SchemaVersion       string                        `json:"schemaVersion"`
	DeviceID            string                        `json:"deviceId"`
	CollectionProfile   string                        `json:"collectionProfile"`
	ServerNow           time.Time                     `json:"serverNow"`
	MaxAgeSeconds       int64                         `json:"maxAgeSeconds"`
	Status              string                        `json:"status"`
	Sequence            *uint64                       `json:"sequence,string"`
	ReceivedAt          *time.Time                    `json:"receivedAt"`
	ExpiresAt           *time.Time                    `json:"expiresAt"`
	Latest              *WindowsFleetIdentitySnapshot `json:"latest"`
	certificateNotAfter int64
}

func (s *Store) FleetIdentitiesView(ctx context.Context, now time.Time) (FleetIdentitiesView, error) {
	zero := FleetIdentitiesView{}
	out := FleetIdentitiesView{SchemaVersion: "tracebolt.fleet-identities.v2", ServerNow: now.UTC(), Items: []FleetIdentityItem{}}
	if s == nil || s.storeState == nil || ctx == nil || !validStoreTime(now) {
		return zero, enrollmentstate.ErrInvalid
	}
	if s.config.Binding.CollectionProfile != windowsmanaged.CollectionProfile {
		// Keep the existing Linux read, admission, authority and byte semantics intact.
		linux, err := s.FleetEndpointIdentityView(ctx, now)
		if err != nil {
			return zero, err
		}
		out.ServerNow = linux.ServerNow
		for _, item := range linux.Items {
			out.Items = append(out.Items, FleetIdentityItem{Linux: &item})
		}
		return out, nil
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	// Share the Windows operational-read permit; no per-device read fanout.
	select {
	case s.operationalReads <- struct{}{}:
		defer func() { <-s.operationalReads }()
	default:
		return zero, ErrOperationalBusy
	}
	err := s.transact(ctx, func(t *transaction) error {
		var err error
		now, err = systemViewNow(ctx, now)
		if err != nil {
			return err
		}
		out.ServerNow = now
		snapshots := t.engine.Snapshots()
		if len(snapshots) > FleetEndpointIdentityLimit {
			return ErrStorage
		}
		sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].Approval.DeviceID < snapshots[j].Approval.DeviceID })
		for _, snap := range snapshots {
			if err := ctx.Err(); err != nil {
				return err
			}
			if snap.Approval.DeviceID == "" {
				continue
			}
			item, err := s.windowsFleetIdentityFromSnapshot(t, snap, now)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, FleetIdentityItem{Windows: &item})
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
	return out.RecheckAt(now)
}
func (s *Store) windowsFleetIdentityFromSnapshot(t *transaction, snap enrollmentstate.Snapshot, now time.Time) (WindowsFleetIdentityView, error) {
	out := WindowsFleetIdentityView{SchemaVersion: "tracebolt.windows-fleet-identity-view.v1", DeviceID: snap.Approval.DeviceID, CollectionProfile: windowsmanaged.CollectionProfile, ServerNow: now, MaxAgeSeconds: int64(lanstore.SampleMaxAge / time.Second), Status: "awaiting", certificateNotAfter: snap.Intent.NotAfter}
	if snap.Platform != "windows" || snap.Binding.CollectionProfile != windowsmanaged.CollectionProfile || snap.Binding.Profile != "tls" && snap.Binding.Profile != "http-test" {
		return WindowsFleetIdentityView{}, ErrStorage
	}
	switch snap.State {
	case enrollmentstate.Revoked, enrollmentstate.Canceled, enrollmentstate.Rejected:
		out.Status = "revoked"
		return out, nil
	case enrollmentstate.Expired:
		out.Status = "expired"
		return out, nil
	}
	if snap.Intent.NotAfter > 0 && now.Unix() >= snap.Intent.NotAfter {
		out.Status = "expired"
		return out, nil
	}
	if snap.State != enrollmentstate.Activated {
		return out, nil
	}
	if now.Unix() < snap.UpdatedAt || now.Unix() < snap.Intent.NotBefore {
		return WindowsFleetIdentityView{}, enrollmentstate.ErrInvalid
	}
	c, ok := t.credentials[snap.InvitationID]
	if !ok {
		return WindowsFleetIdentityView{}, ErrStorage
	}
	intent, err := t.engine.TrustedRecordedIntent(snap.InvitationID)
	if err != nil {
		return WindowsFleetIdentityView{}, ErrStorage
	}
	cert, err := enrollmentcrypto.VerifyIssued(c.DER, s.issuerDER, intent, now)
	if err != nil || cert.CertificateHash() != snap.Issuance.CertificateHash {
		return WindowsFleetIdentityView{}, enrollmentstate.ErrProof
	}
	if len(c.Frame) == 0 {
		return out, nil
	}
	frame, err := t.validateFrame(c.Frame, c.Replay.ReceivedAt)
	if err != nil || frame.WindowsInventory == nil {
		return WindowsFleetIdentityView{}, ErrStorage
	}
	original := frame.WindowsInventory
	sequence, received, expires := c.Replay.Sequence, c.Replay.ReceivedAt, original.CollectedAt.Add(24*time.Hour)
	authorityUntil := time.Unix(snap.Intent.NotAfter, 0).UTC()
	if authorityUntil.Before(expires) {
		expires = authorityUntil
	}
	out.Sequence, out.ReceivedAt, out.ExpiresAt = &sequence, &received, &expires
	out.Latest = &WindowsFleetIdentitySnapshot{SchemaVersion: "tracebolt.windows-fleet-identity.v1", CollectionProfile: original.CollectionProfile, GenerationID: original.GenerationID, CollectedAt: original.CollectedAt, Hostname: original.Hostname, Network: original.Network}
	return out.RecheckAt(now)
}
func (v WindowsFleetIdentityView) RecheckAt(now time.Time) (WindowsFleetIdentityView, error) {
	if !validStoreTime(now) || !validStoreTime(v.ServerNow) {
		return WindowsFleetIdentityView{}, ErrStorage
	}
	if now.Before(v.ServerNow) {
		now = v.ServerNow
	}
	v.ServerNow = now.UTC()
	if v.Status == "revoked" {
		v.Latest = nil
		return v, nil
	}
	if v.certificateNotAfter > 0 && now.Unix() >= v.certificateNotAfter || v.ExpiresAt != nil && !now.Before(*v.ExpiresAt) {
		v.Status = "expired"
		v.Latest = nil
		return v, nil
	}
	if v.Latest != nil {
		if v.Sequence == nil || *v.Sequence == 0 || v.ReceivedAt == nil || now.Before(*v.ReceivedAt) || v.ExpiresAt == nil || v.Latest.CollectedAt.Sub(now) > lanstore.AllowedClockSkew {
			return WindowsFleetIdentityView{}, ErrStorage
		}
		v.Status = "fresh"
		if now.Before(v.Latest.CollectedAt) || now.Sub(v.Latest.CollectedAt) > lanstore.SampleMaxAge || now.Sub(*v.ReceivedAt) > lanstore.SampleMaxAge {
			v.Status = "stale"
		}
	}
	return v, nil
}
func (v FleetIdentitiesView) RecheckAt(now time.Time) (FleetIdentitiesView, error) {
	if !validStoreTime(now) || !validStoreTime(v.ServerNow) || len(v.Items) > FleetIdentitiesLimit {
		return FleetIdentitiesView{}, ErrStorage
	}
	if now.Before(v.ServerNow) {
		now = v.ServerNow
	}
	v.ServerNow = now.UTC()
	// Detach the union list so validation never changes already-encoded data.
	v.Items = append([]FleetIdentityItem{}, v.Items...)
	for i, item := range v.Items {
		if (item.Linux == nil) == (item.Windows == nil) {
			return FleetIdentitiesView{}, ErrStorage
		}
		if item.Linux != nil {
			checked, err := (FleetEndpointIdentityView{ServerNow: v.ServerNow, Items: []EndpointIdentityView{*item.Linux}}).RecheckAt(now)
			if err != nil {
				return FleetIdentitiesView{}, err
			}
			v.Items[i].Linux = &checked.Items[0]
		} else {
			checked, err := item.Windows.RecheckAt(now)
			if err != nil {
				return FleetIdentitiesView{}, err
			}
			v.Items[i].Windows = &checked
		}
	}
	return v, nil
}
func (v FleetIdentitiesView) ValidateAt(now time.Time) error {
	checked, err := v.RecheckAt(now)
	if err != nil {
		return err
	}
	for i, item := range v.Items {
		if item.Linux != nil {
			if item.Linux.Status != checked.Items[i].Linux.Status || item.Linux.Latest != nil && checked.Items[i].Linux.Latest == nil {
				return enrollmentstate.ErrExpired
			}
		} else if item.Windows.Status != checked.Items[i].Windows.Status || item.Windows.Latest != nil && checked.Items[i].Windows.Latest == nil {
			return enrollmentstate.ErrExpired
		}
	}
	return nil
}
