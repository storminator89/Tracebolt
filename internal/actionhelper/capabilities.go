package actionhelper

import (
	"context"
	"encoding/json"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
)

const (
	CapabilitiesVersion = "tracebolt.action-capabilities.v1"
	maxCapabilitiesUnix = 253402300799
)

// CapabilityService is only public metadata from the independently loaded root
// policy. Input paths, review manifests and key bytes never leave the helper.
type CapabilityService struct {
	Unit             string `json:"unit"`
	UnitPolicyDigest string `json:"unitPolicyDigest"`
}

// Capabilities describes the local grant, not helper health or permission to
// execute. CapturedAt is its original observation time, never a receipt time.
// A signed permit, live policy checks and durable admission remain mandatory.
type Capabilities struct {
	Version              string              `json:"version"`
	Enabled              bool                `json:"enabled"`
	ManagerID            string              `json:"managerId"`
	KeyID                string              `json:"keyId"`
	EndpointID           string              `json:"endpointId"`
	IncarnationDigest    string              `json:"incarnationDigest"`
	RootPolicyDigest     string              `json:"rootPolicyDigest"`
	TransportProfile     string              `json:"transportProfile"`
	HTTPTestAcknowledged bool                `json:"httpTestAcknowledged"`
	CapturedAt           int64               `json:"capturedAt"`
	MaxLifetimeSeconds   int64               `json:"maxLifetimeSeconds"`
	Services             []CapabilityService `json:"services"`
}

// ValidateCapabilities validates shape only. A receiving manager must bind the
// identity/profile to its enrolled sender and check age using CapturedAt.
func ValidateCapabilities(c Capabilities) error {
	if c.Version != CapabilitiesVersion || !enrollmentcrypto.ValidID(c.ManagerID, "manager_") ||
		!enrollmentcrypto.ValidID(c.EndpointID, "agent_") || !actionpermit.ValidDigest(c.KeyID) ||
		!actionpermit.ValidDigest(c.IncarnationDigest) || !actionpermit.ValidDigest(c.RootPolicyDigest) ||
		c.CapturedAt <= 0 || c.CapturedAt > maxCapabilitiesUnix || c.MaxLifetimeSeconds < 1 ||
		c.MaxLifetimeSeconds > actionpermit.MaxLifetimeSeconds || len(c.Services) < 1 || len(c.Services) > 16 {
		return ErrRejected
	}
	switch c.TransportProfile {
	case ProductionTLS:
		if c.HTTPTestAcknowledged {
			return ErrRejected
		}
	case DisposableHTTPTest:
		if !c.HTTPTestAcknowledged {
			return ErrRejected
		}
	default:
		return ErrRejected
	}
	last := ""
	for _, r := range c.Services {
		if !canonicalUnit(r.Unit) || protectedUnit(r.Unit) || r.Unit <= last || !actionpermit.ValidDigest(r.UnitPolicyDigest) {
			return ErrRejected
		}
		last = r.Unit
	}
	return nil
}

func projectCapabilities(a Authority, now time.Time) (Capabilities, error) {
	if _, err := a.verifier(); err != nil || now.Location() != time.UTC {
		return Capabilities{}, ErrRejected
	}
	p := a.Policy
	raw, err := json.Marshal(p)
	if err != nil {
		return Capabilities{}, ErrRejected
	}
	c := Capabilities{Version: CapabilitiesVersion, Enabled: p.Enabled, ManagerID: p.ManagerID,
		KeyID: p.KeyID, EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest,
		RootPolicyDigest: actionpermit.Digest(raw), TransportProfile: p.TransportProfile,
		HTTPTestAcknowledged: p.HTTPTestAcknowledged, CapturedAt: now.Unix(),
		MaxLifetimeSeconds: p.MaxLifetimeSeconds, Services: make([]CapabilityService, 0, len(p.Targets))}
	for _, target := range p.Targets {
		digest, err := targetDigest(target)
		if err != nil {
			return Capabilities{}, ErrRejected
		}
		c.Services = append(c.Services, CapabilityService{Unit: target.Unit, UnitPolicyDigest: digest})
	}
	if err := ValidateCapabilities(c); err != nil {
		return Capabilities{}, err
	}
	return c, nil
}

// Capabilities is read-only: it does not inspect systemd, invoke the backend,
// admit a job, refresh the verifier, or modify the durable sequence/clock floor.
func (s *Server) Capabilities(ctx context.Context, peer Peer) (Capabilities, error) {
	if s == nil || s.inner == nil || ctx == nil || ctx.Err() != nil {
		return Capabilities{}, ErrRejected
	}
	x := s.inner
	initial, _, err := x.authority(peer)
	if err != nil {
		return Capabilities{}, err
	}
	now := x.deps.Now()
	c, err := projectCapabilities(initial, now)
	if err != nil {
		return Capabilities{}, err
	}
	// Advertising a live grant that the opened verifier cannot admit would let
	// the manager claim an unexecutable job. Only restart/reopen can adopt a new
	// policy; the existing consumption history remains in the same ledger.
	snapshotPolicy, policyErr := x.deps.State.RootPolicyDigest(ctx)
	if policyErr != nil || snapshotPolicy != c.RootPolicyDigest {
		return Capabilities{}, ErrRejected
	}
	// Reload root identity, caller binding and protected-file revision as the
	// last authority operation before returning this projection. Retain its
	// original timestamp even if this validation takes time.
	current, _, err := x.authority(peer)
	checkedAt := x.deps.Now()
	if err != nil || current.Revision != initial.Revision || ctx.Err() != nil || checkedAt.Location() != time.UTC || checkedAt.Unix() > maxCapabilitiesUnix || checkedAt.Before(now) {
		return Capabilities{}, ErrRejected
	}
	return c, nil
}
