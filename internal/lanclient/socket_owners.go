package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"localrmm/internal/lanconfig"
	"localrmm/internal/socketowner"
	"localrmm/internal/systeminventory"
	"path/filepath"
	"time"
)

const SocketOwnerConsentVersion = "tracebolt.socket-owner-consent.v1"
const socketOwnerConsentName = "socket-owner-consent.json"
const socketOwnerMaxConsentBytes = 4096
const socketOwnerSendReserve = time.Second

// SocketOwnerConsent is a private, historical scope approval bound to one
// activated endpoint and one exact root grant. It is not a second identity
// authority. The existing activated producer is reread independently every time.
// No setup writer or implicit opt-in is supplied by the source integration.
type SocketOwnerConsent struct {
	Version           string             `json:"version"`
	EndpointID        string             `json:"endpointId"`
	IncarnationDigest string             `json:"incarnationDigest"`
	Policy            socketowner.Policy `json:"policy"`
}

type socketOwnerHelper interface {
	Verify(context.Context, socketowner.Policy, *socketowner.Reference) (socketowner.Reference, error)
	Capture(context.Context, socketowner.Policy, string, socketowner.Reference) (socketowner.Observation, error)
}
type activatedMaterialReader func(string) (Material, uint32, uint32, error)
type socketOwnerConsentReader func(Material) (SocketOwnerConsent, error)

func socketOwnerConsentPath(m Material) string {
	return filepath.Join(m.config.StateDirectory, socketOwnerConsentName)
}

func readSocketOwnerConsent(m Material) (SocketOwnerConsent, error) {
	raw, err := lanconfig.ReadProtected(socketOwnerConsentPath(m), true, socketOwnerMaxConsentBytes)
	if err != nil {
		return SocketOwnerConsent{}, socketowner.ErrRejected
	}
	var c SocketOwnerConsent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil {
		return SocketOwnerConsent{}, socketowner.ErrRejected
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(raw, canonical) {
		return SocketOwnerConsent{}, socketowner.ErrRejected
	}
	return c, nil
}

func validateSocketOwnerConsent(c SocketOwnerConsent, m Material, uid, gid uint32) bool {
	p := c.Policy
	return c.Version == SocketOwnerConsentVersion && c.EndpointID == m.config.AgentID &&
		c.IncarnationDigest == "sha256:"+journalLeaf(m) && p.Enabled && socketowner.PolicyDigest(p) != "" &&
		p.SenderBinding == m.binding && p.ManagerOrigin == m.config.ManagerOrigin &&
		p.TransportProfile == m.config.Profile && p.CollectionProfile == m.config.CollectionProfile &&
		p.AgentUID == uid && p.AgentGID == gid
}

func (s *systemSender) currentSocketOwnerConsent() (SocketOwnerConsent, bool) {
	if s.socketIdentity == nil || s.socketConsent == nil || s.socketHelper == nil || s.material.configPath == "" {
		return SocketOwnerConsent{}, false
	}
	current, uid, gid, err := s.socketIdentity(s.material.configPath)
	if err != nil || !current.valid() || !current.config.complete() || current.configPath != s.material.configPath ||
		current.config != s.material.config || current.binding != s.material.binding || journalLeaf(current) != journalLeaf(s.material) {
		return SocketOwnerConsent{}, false
	}
	c, err := s.socketConsent(current)
	return c, err == nil && validateSocketOwnerConsent(c, current, uid, gid)
}

func socketReference(p systeminventory.SocketOwnerProvenance) socketowner.Reference {
	return socketowner.Reference{GrantEpoch: p.GrantEpoch, PolicyDigest: p.PolicyDigest, AuthorityRevision: p.AuthorityRevision, ContextID: p.ContextID}
}

// verifySocketOwners never replaces a captured reference with readiness. This
// exact check runs before staging and every send/retry/restart. Failures mean
// abandoning all tagged bytes, not removing rows from an already used sequence.
func (s *systemSender) verifySocketOwners(ctx context.Context, p systeminventory.SocketOwnerProvenance, snapshot systeminventory.Snapshot) bool {
	if ctx == nil || ctx.Err() != nil || systeminventory.ValidateSocketOwnerProvenance(p, snapshot.CollectedAt, snapshot.DurationMS) != nil {
		return false
	}
	now := s.now().UTC()
	if now.Before(p.FinishedAt) || now.Sub(p.StartedAt) > 2*time.Minute {
		return false
	}
	local, ok := s.currentSocketOwnerConsent()
	expected := socketReference(p)
	if !ok || local.Policy.Epoch != expected.GrantEpoch || socketowner.PolicyDigest(local.Policy) != expected.PolicyDigest {
		return false
	}
	budget := time.Second
	if deadline, exists := ctx.Deadline(); exists {
		if remaining := time.Until(deadline) - socketOwnerSendReserve; remaining < budget {
			budget = remaining
		}
	}
	if budget <= 0 {
		return false
	}
	child, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	got, err := s.socketHelper.Verify(child, local.Policy, &expected)
	if err != nil || got != expected || child.Err() != nil {
		return false
	}
	current, ok := s.currentSocketOwnerConsent()
	now = s.now().UTC()
	return ok && current == local && child.Err() == nil && !now.Before(p.FinishedAt) && now.Sub(p.StartedAt) <= 2*time.Minute
}

// collectSocketOwners is optional and synchronous. Ordinary inventory is always
// collected first and is kept unchanged on any denial, malformed response,
// missing identity/grant, unsupported native profile or exhausted child budget.
func (s *systemSender) collectSocketOwners(ctx context.Context, ordinary systeminventory.Snapshot) (systeminventory.Snapshot, *systeminventory.SocketOwnerProvenance) {
	local, ok := s.currentSocketOwnerConsent()
	if !ok || ctx.Err() != nil {
		return ordinary, nil
	}
	budget := socketowner.ConnectionTimeout
	if deadline, exists := ctx.Deadline(); exists {
		if remaining := time.Until(deadline) - socketOwnerSendReserve; remaining < budget {
			budget = remaining
		}
	}
	if budget <= 0 {
		return ordinary, nil
	}
	child, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	ref, err := s.socketHelper.Verify(child, local.Policy, nil)
	if err != nil || ref.GrantEpoch != local.Policy.Epoch || ref.PolicyDigest != socketowner.PolicyDigest(local.Policy) {
		return ordinary, nil
	}
	current, ok := s.currentSocketOwnerConsent()
	if !ok || current != local || child.Err() != nil {
		return ordinary, nil
	}
	began := s.now().UTC()
	observation, err := s.socketHelper.Capture(child, local.Policy, ordinary.GenerationID, ref)
	if err != nil || child.Err() != nil {
		return ordinary, nil
	}
	current, ok = s.currentSocketOwnerConsent()
	finished := s.now().UTC()
	if !ok || current != local || observation.GenerationID != ordinary.GenerationID || observation.StartedAt.Before(began) ||
		observation.StartedAt.Before(ordinary.CollectedAt) || observation.FinishedAt.After(finished) || observation.Sockets == nil {
		return ordinary, nil
	}
	p := systeminventory.SocketOwnerProvenance{SchemaVersion: systeminventory.SocketOwnerSourceVersion, Scope: systeminventory.SocketOwnerSourceScope,
		GrantEpoch: ref.GrantEpoch, PolicyDigest: ref.PolicyDigest, AuthorityRevision: ref.AuthorityRevision, ContextID: ref.ContextID,
		StartedAt: observation.StartedAt, FinishedAt: observation.FinishedAt}
	snapshot := ordinary
	n := uint64(len(observation.Sockets))
	// SectionMeta retains the v1 batch timestamp. Exact helper times remain in
	// the separate source provenance and are never relabelled on retry.
	snapshot.Sockets = systeminventory.SocketSection{Meta: systeminventory.SectionMeta{GenerationID: ordinary.GenerationID, ObservedAt: ordinary.CollectedAt,
		Coverage: systeminventory.Complete, Reason: systeminventory.ReasonNone, ObservedCount: &n, CountExact: true}, Items: observation.Sockets}
	elapsed := observation.FinishedAt.Sub(ordinary.CollectedAt)
	duration := elapsed.Milliseconds()
	if elapsed%time.Millisecond != 0 {
		duration++
	}
	if duration > snapshot.DurationMS {
		snapshot.DurationMS = duration
	}
	if systeminventory.Validate(snapshot) != nil || systeminventory.ValidateSocketOwnerProvenance(p, snapshot.CollectedAt, snapshot.DurationMS) != nil {
		return ordinary, nil
	}
	return snapshot, &p
}
