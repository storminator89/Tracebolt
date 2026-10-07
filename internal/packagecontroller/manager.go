// Package packagecontroller connects explicit named approval and durable native
// package work to the enrolled endpoint transport. It never runs host commands.
package packagecontroller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorauth"
	"localrmm/internal/packagehelper"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageupdate"
	"localrmm/internal/packageupdatestore"
	"localrmm/internal/packagewire"
)

const ConfigVersion = "tracebolt.native-package-manager.v1"

var ErrConfiguration = errors.New("native_package_manager_configuration_invalid")

type Config struct {
	Version                string `json:"version"`
	Enabled                bool   `json:"enabled"`
	ManagerID              string `json:"managerId"`
	EndpointID             string `json:"endpointId"`
	IncarnationDigest      string `json:"incarnationDigest"`
	RootPolicyDigest       string `json:"rootPolicyDigest"`
	TransportProfile       string `json:"transportProfile"`
	HTTPTestAcknowledged   bool   `json:"httpTestAcknowledged"`
	StateFile              string `json:"stateFile"`
	PrivateKeyFile         string `json:"privateKeyFile"`
	LocalScopeAcknowledged bool   `json:"localScopeAcknowledged"`
}
type DeviceAuthority func(context.Context, string, string, time.Time) error
type ActorAuthority func(string, operatorauth.Capability) bool
type Manager struct {
	mu     *sync.Mutex
	config Config
	path   string
	raw    []byte
	key    ed25519.PrivateKey
	store  packageupdate.DurableStore
	owned  *packageupdatestore.Store
	device DeviceAuthority
	actor  ActorAuthority
	now    func() time.Time
	caps   *packagehelper.Capabilities
	closed bool
}

func (Manager) String() string               { return "packagecontroller.Manager{authority:redacted}" }
func (m Manager) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, m.String()) }
func (Manager) MarshalJSON() ([]byte, error) { return []byte(`{"authorityRedacted":true}`), nil }
func valid(c Config) bool {
	return c.Version == ConfigVersion && c.LocalScopeAcknowledged && enrollmentcrypto.ValidID(c.ManagerID, "manager_") && enrollmentcrypto.ValidID(c.EndpointID, "agent_") && actionpermit.ValidDigest(c.IncarnationDigest) && actionpermit.ValidDigest(c.RootPolicyDigest) && filepath.IsAbs(c.StateFile) && filepath.Clean(c.StateFile) == c.StateFile && filepath.IsAbs(c.PrivateKeyFile) && filepath.Clean(c.PrivateKeyFile) == c.PrivateKeyFile && ((c.TransportProfile == "production-tls" && !c.HTTPTestAcknowledged) || (c.TransportProfile == "disposable-http-test" && c.HTTPTestAcknowledged))
}
func (c Config) Binding() packageupdate.Binding {
	return packageupdate.Binding{ManagerID: c.ManagerID, DeviceID: c.EndpointID, IncarnationDigest: c.IncarnationDigest, RootPolicyDigest: c.RootPolicyDigest, TransportProfile: c.TransportProfile}
}

// Load opens an explicitly initialized native store and existing signing key.
// Missing/corrupt/uncertain state is not recreated. There is no simulation fallback.
func Load(ctx context.Context, path string, device DeviceAuthority, actor ActorAuthority, forbidden ...ed25519.PublicKey) (*Manager, error) {
	raw, e := lanconfig.ReadProtected(path, true, 8192)
	if e != nil {
		return nil, ErrConfiguration
	}
	var c Config
	if lanconfig.StrictObject(raw, &c, "version", "enabled", "managerId", "endpointId", "incarnationDigest", "rootPolicyDigest", "transportProfile", "httpTestAcknowledged", "stateFile", "privateKeyFile", "localScopeAcknowledged") != nil || !valid(c) || device == nil || actor == nil {
		return nil, ErrConfiguration
	}
	key, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, ed25519.PrivateKeySize)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrConfiguration
	}
	defer clear(key)
	derived := ed25519.NewKeyFromSeed(key[:32])
	defer clear(derived)
	if !bytes.Equal(key, derived) || !keyvalidation.Ed25519(derived.Public().(ed25519.PublicKey)) {
		return nil, ErrConfiguration
	}
	for _, k := range forbidden {
		if bytes.Equal(k, derived.Public().(ed25519.PublicKey)) {
			return nil, ErrConfiguration
		}
	}
	store, e := packageupdatestore.OpenExisting(ctx, c.StateFile, c.Binding())
	if e != nil {
		return nil, e
	}
	m, e := newManager(ctx, c, key, store, device, actor, time.Now)
	if e != nil {
		store.Close()
		return nil, e
	}
	m.path = path
	m.raw = bytes.Clone(raw)
	m.owned = store
	return m, nil
}
func newManager(ctx context.Context, c Config, key []byte, store packageupdate.DurableStore, device DeviceAuthority, actor ActorAuthority, now func() time.Time) (*Manager, error) {
	if !valid(c) || len(key) != 64 || store == nil || device == nil || actor == nil || now == nil {
		return nil, ErrConfiguration
	}
	raw, e := store.Open(ctx, c.Binding())
	if e != nil {
		return nil, e
	}
	r, e := packageupdate.Decode(ctx, raw)
	if e != nil || r.Mode != "native" || !bytes.Equal(r.PublicKey, ed25519.PrivateKey(key).Public().(ed25519.PublicKey)) {
		return nil, ErrConfiguration
	}
	return &Manager{mu: &sync.Mutex{}, config: c, key: bytes.Clone(key), store: store, device: device, actor: actor, now: now}, nil
}
func (m *Manager) Close() {
	if m == nil || m.mu == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	clear(m.key)
	if m.owned != nil {
		_ = m.owned.Close()
	}
}
func (m *Manager) MatchesBinding(b enrollmentstate.Binding) bool {
	return m != nil && m.config.ManagerID == b.InstanceID && b.CollectionProfile == enrollmentcrypto.CollectionProfileComplete && m.config.TransportProfile == map[string]string{"tls": "production-tls", "http-test": "disposable-http-test"}[b.Profile]
}
func (m *Manager) TransportProfile() string {
	if m == nil || m.mu == nil {
		return ""
	}
	return m.config.TransportProfile
}
func (m *Manager) live(ctx context.Context, device, incarnation string, now time.Time) error {
	if m == nil || m.closed || device != m.config.EndpointID || incarnation != m.config.IncarnationDigest {
		return packageupdate.ErrUnavailable
	}
	if m.path != "" {
		raw, e := lanconfig.ReadProtected(m.path, true, 8192)
		if e != nil || !bytes.Equal(raw, m.raw) {
			return packageupdate.ErrUnavailable
		}
		key, e := lanconfig.ReadProtected(m.config.PrivateKeyFile, true, 64)
		defer clear(key)
		if e != nil || !bytes.Equal(key, m.key) {
			return packageupdate.ErrUnavailable
		}
	}
	return m.device(ctx, device, incarnation, now)
}
func (m *Manager) read(ctx context.Context, now int64) (packageupdate.Record, error) {
	raw, e := m.store.Open(ctx, m.config.Binding())
	if e != nil {
		return packageupdate.Record{}, e
	}
	r, e := packageupdate.Decode(ctx, raw)
	if e != nil {
		return packageupdate.Record{}, e
	}
	next, e := packageupdate.Observe(ctx, r, now)
	if e != nil {
		return packageupdate.Record{}, e
	}
	if e = m.save(ctx, r, next); e != nil {
		return packageupdate.Record{}, e
	}
	return next, nil
}
func (m *Manager) save(ctx context.Context, old, next packageupdate.Record) error {
	if e := packageupdate.ValidateSuccessor(ctx, old, next); e != nil {
		return e
	}
	raw, e := packageupdate.Encode(ctx, next)
	if e != nil {
		return e
	}
	return m.store.CompareAndSwap(ctx, old.Binding, old.Revision, raw)
}
func (m *Manager) ready(now int64) bool {
	return m.config.Enabled && m.caps != nil && m.caps.Enabled && m.caps.CapturedAt <= now && now-m.caps.CapturedAt < 60
}
func (m *Manager) permit(r packageupdate.Record, j packageupdate.Job, action string, now int64) ([]byte, error) {
	selections := make([]packagepermit.Selection, len(j.Request.Packages))
	for i, s := range j.Request.Packages {
		selections[i] = packagepermit.Selection{Name: s.Name, Architecture: s.Architecture}
	}
	p := packagepermit.Permit{Version: packagepermit.Version, Action: action, ManagerID: r.Binding.ManagerID, KeyID: actionpermit.Digest(r.PublicKey), EndpointID: r.Binding.DeviceID, IncarnationDigest: r.Binding.IncarnationDigest, RootPolicyDigest: r.Binding.RootPolicyDigest, JobID: j.Request.RequestID, Sequence: j.Sequence, ActorID: j.ActorID, IssuedAt: now, NotBefore: now, StartDeadline: now + 120, Selection: selections}
	if action == packagepermit.Execute {
		p.Plan = &j.Preview.Plan
		p.PlanDigest = j.Preview.PlanDigest
		p.PreviewDigest = j.Preview.Digest
		p.StartDeadline = j.Preview.Plan.ExpiresAt
	}
	return packagepermit.Sign(context.Background(), p, m.key)
}
func (m *Manager) Prepare(ctx context.Context, device, actor string, req packageupdate.PrepareRequest) error {
	if m == nil || m.mu == nil {
		return packageupdate.ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if e := m.live(ctx, device, m.config.IncarnationDigest, now); e != nil {
		return e
	}
	if !m.actor(actor, operatorauth.PlanUpdates) {
		return packageupdate.ErrUnavailable
	}
	if e := packageupdate.ValidatePrepare(req); e != nil {
		return e
	}
	r, e := m.read(ctx, now.Unix())
	if e != nil {
		return e
	}
	for _, j := range r.Jobs {
		if j.Request.RequestID == req.RequestID {
			next, e := packageupdate.PrepareNative(ctx, r, req, actor, now.Unix(), j.PreparationEnvelope)
			if e != nil {
				return e
			}
			return m.save(ctx, r, next)
		}
	}
	if !m.ready(now.Unix()) {
		return packageupdate.ErrUnavailable
	}
	allowed := map[packagepermit.Selection]bool{}
	for _, s := range m.caps.Allowed {
		allowed[s] = true
	}
	for _, s := range req.Packages {
		if !allowed[packagepermit.Selection{Name: s.Name, Architecture: s.Architecture}] {
			return packageupdate.ErrInvalid
		}
	}
	prospective := packageupdate.Job{Sequence: uint64(len(r.Jobs) + 1), Request: req, ActorID: actor}
	signed, e := m.permit(r, prospective, packagepermit.Prepare, now.Unix())
	if e != nil {
		return e
	}
	next, e := packageupdate.PrepareNative(ctx, r, req, actor, now.Unix(), signed)
	if e != nil {
		return e
	}
	return m.save(ctx, r, next)
}
func (m *Manager) Approve(ctx context.Context, device, actor string, req packageupdate.ApprovalRequest) error {
	if m == nil || m.mu == nil {
		return packageupdate.ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if e := m.live(ctx, device, m.config.IncarnationDigest, now); e != nil {
		return e
	}
	if !m.actor(actor, operatorauth.ExecuteUpdates) {
		return packageupdate.ErrUnavailable
	}
	r, e := m.read(ctx, now.Unix())
	if e != nil {
		return e
	}
	for _, j := range r.Jobs {
		if j.Request.RequestID != req.RequestID {
			continue
		}
		signed := j.ExecutionEnvelope
		if j.ApprovedAt == 0 {
			if !m.ready(now.Unix()) || j.Preview == nil {
				return packageupdate.ErrUnavailable
			}
			signed, e = m.permit(r, j, packagepermit.Execute, now.Unix())
			if e != nil {
				return e
			}
		}
		next, e := packageupdate.ApproveNative(ctx, r, req, actor, now.Unix(), signed)
		if e != nil {
			return e
		}
		return m.save(ctx, r, next)
	}
	return packageupdate.ErrNotFound
}
func (m *Manager) Report(ctx context.Context, device, inc string, c packagehelper.Capabilities) error {
	if m == nil || m.mu == nil {
		return packageupdate.ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if e := m.live(ctx, device, inc, now); e != nil {
		return e
	}
	if packagehelper.ValidateCapabilities(c) != nil || c.ManagerID != m.config.ManagerID || c.EndpointID != device || c.IncarnationDigest != inc || c.RootPolicyDigest != m.config.RootPolicyDigest || c.KeyID != actionpermit.Digest(m.key.Public().(ed25519.PublicKey)) || c.TransportProfile != m.config.TransportProfile || c.HTTPTestAcknowledged != m.config.HTTPTestAcknowledged || c.CapturedAt > now.Unix() || now.Unix()-c.CapturedAt >= 60 {
		return packageupdate.ErrInvalid
	}
	if m.caps != nil && c.CapturedAt < m.caps.CapturedAt {
		return packageupdate.ErrConflict
	}
	raw, _ := json.Marshal(c)
	var owned packagehelper.Capabilities
	_ = json.Unmarshal(raw, &owned)
	m.caps = &owned
	return nil
}
func delivery(j packageupdate.Job) (packagewire.Delivery, error) {
	var raw []byte
	kind, state := packagepermit.Prepare, "pending"
	if j.State == packageupdate.Preparing {
		raw = j.PreparationEnvelope
		if j.PreparationClaimedAt != 0 {
			state = "claimed"
		}
	} else if len(j.ExecutionEnvelope) > 0 && (j.State == packageupdate.Approved || j.State == packageupdate.DeliveryUnknown || j.State == packageupdate.Applying || j.State == packageupdate.Verifying || j.State == packageupdate.NeedsIntervention) {
		raw = j.ExecutionEnvelope
		kind = packagepermit.Execute
		if j.ClaimedAt != 0 {
			state = "claimed"
		}
	} else {
		return packagewire.Delivery{}, packageupdate.ErrNotFound
	}
	p, _, e := packagepermit.Decode(context.Background(), raw)
	if e != nil {
		return packagewire.Delivery{}, e
	}
	return packagewire.Delivery{Identity: packagewire.Identity{JobID: j.Request.RequestID, Sequence: j.Sequence, Kind: kind, EnvelopeDigest: actionpermit.Digest(raw)}, State: state, StartDeadline: p.StartDeadline}, nil
}
func (m *Manager) Peek(ctx context.Context, device, inc string) (packagewire.Delivery, error) {
	if m == nil || m.mu == nil {
		return packagewire.Delivery{}, packageupdate.ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if e := m.live(ctx, device, inc, now); e != nil {
		return packagewire.Delivery{}, e
	}
	r, e := m.read(ctx, now.Unix())
	if e != nil {
		return packagewire.Delivery{}, e
	}
	if len(r.Jobs) == 0 {
		return packagewire.Delivery{}, packageupdate.ErrNotFound
	}
	return delivery(r.Jobs[len(r.Jobs)-1])
}
func (m *Manager) Claim(ctx context.Context, device, inc string, id packagewire.Identity) (packagewire.Grant, error) {
	if m == nil || m.mu == nil || !packagewire.ValidIdentity(id) {
		return packagewire.Grant{}, packageupdate.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if e := m.live(ctx, device, inc, now); e != nil {
		return packagewire.Grant{}, e
	}
	if !m.ready(now.Unix()) {
		return packagewire.Grant{}, packageupdate.ErrUnavailable
	}
	r, e := m.read(ctx, now.Unix())
	if e != nil {
		return packagewire.Grant{}, e
	}
	if len(r.Jobs) == 0 {
		return packagewire.Grant{}, packageupdate.ErrNotFound
	}
	j := r.Jobs[len(r.Jobs)-1]
	d, e := delivery(j)
	if e != nil || d.Identity != id || d.State != "pending" {
		return packagewire.Grant{}, packageupdate.ErrConflict
	}
	cap := operatorauth.PlanUpdates
	if id.Kind == packagepermit.Execute {
		cap = operatorauth.ExecuteUpdates
	}
	if !m.actor(j.ActorID, cap) {
		return packagewire.Grant{}, packageupdate.ErrUnavailable
	}
	var next packageupdate.Record
	var envelope []byte
	if id.Kind == packagepermit.Prepare {
		envelope = j.PreparationEnvelope
		next, e = packageupdate.ClaimPreparation(ctx, r, id.JobID, id.EnvelopeDigest, now.Unix())
	} else {
		envelope = j.ExecutionEnvelope
		next, e = packageupdate.ClaimExecution(ctx, r, id.JobID, j.Preview.Digest, now.Unix())
	}
	if e != nil {
		return packagewire.Grant{}, e
	}
	if e = m.save(ctx, r, next); e != nil {
		return packagewire.Grant{}, e
	}
	return packagewire.Grant{Identity: id, Envelope: bytes.Clone(envelope)}, nil
}
func (m *Manager) Accept(ctx context.Context, device, inc string, s packagehelper.Snapshot) error {
	if m == nil || m.mu == nil || packagehelper.ValidateSnapshot(s) != nil {
		return packageupdate.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if e := m.live(ctx, device, inc, now); e != nil {
		return e
	}
	if s.UpdatedAt > now.Unix() {
		return packageupdate.ErrInvalid
	}
	r, e := m.read(ctx, now.Unix())
	if e != nil {
		return e
	}
	index := -1
	for i, j := range r.Jobs {
		if j.Request.RequestID == s.JobID {
			index = i
			break
		}
	}
	if index < 0 {
		return packageupdate.ErrNotFound
	}
	j := r.Jobs[index]
	if j.Sequence != s.Sequence || j.PreparationClaimedAt == 0 || s.PreparationEnvelopeDigest != actionpermit.Digest(j.PreparationEnvelope) {
		return packageupdate.ErrConflict
	}
	if s.Preview != nil {
		if j.Preview != nil {
			a, _ := json.Marshal(j.Preview)
			b, _ := json.Marshal(s.Preview)
			if !bytes.Equal(a, b) {
				return packageupdate.ErrConflict
			}
		} else {
			next, e := packageupdate.AttachNativePreview(ctx, r, *s.Preview, now.Unix())
			if e != nil {
				return e
			}
			if e = m.save(ctx, r, next); e != nil {
				return e
			}
			r = next
			j = r.Jobs[index]
		}
	}
	if s.State == packageupdate.PreparationFailed && j.State == packageupdate.Preparing && s.Preview == nil {
		next, e := packageupdate.FailPreparation(ctx, r, s.JobID, now.Unix())
		if e != nil {
			return e
		}
		return m.save(ctx, r, next)
	}
	if len(s.Results) == 0 {
		if s.State == packageupdate.NeedsIntervention && s.ExecutionEnvelopeDigest == "" {
			next, e := packageupdate.MarkPreparationUncertain(ctx, r, s.JobID, now.Unix())
			if e != nil {
				return e
			}
			return m.save(ctx, r, next)
		}
		return nil
	}
	if j.ClaimedAt == 0 || j.Preview == nil || len(j.ExecutionEnvelope) == 0 || s.ExecutionEnvelopeDigest != actionpermit.Digest(j.ExecutionEnvelope) {
		return packageupdate.ErrConflict
	}
	for _, result := range s.Results {
		next, e := packageupdate.ObserveResult(ctx, r, s.JobID, j.Preview.Digest, result, now.Unix())
		if e != nil {
			return e
		}
		if e = m.save(ctx, r, next); e != nil {
			return e
		}
		r = next
	}
	return nil
}
func (m *Manager) View(ctx context.Context, device string, now time.Time) (packageupdate.View, error) {
	return m.view(ctx, device, "", now)
}
func (m *Manager) ViewJob(ctx context.Context, device, id string, now time.Time) (packageupdate.View, error) {
	if !enrollmentcrypto.ValidID(id, "update_") {
		return packageupdate.View{}, packageupdate.ErrInvalid
	}
	return m.view(ctx, device, id, now)
}
func (m *Manager) view(ctx context.Context, device, id string, now time.Time) (packageupdate.View, error) {
	if m == nil || m.mu == nil {
		return packageupdate.View{}, packageupdate.ErrUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.live(ctx, device, m.config.IncarnationDigest, now); e != nil {
		return packageupdate.View{}, e
	}
	r, e := m.read(ctx, now.Unix())
	if e != nil {
		return packageupdate.View{}, e
	}
	v, e := packageupdate.Project(ctx, r, now)
	if e != nil {
		return v, e
	}
	available := v.Available && m.ready(now.Unix())
	if id != "" {
		found := false
		for i, j := range r.Jobs {
			if j.Request.RequestID == id {
				found = true
				r.Jobs = r.Jobs[:i+1]
				break
			}
		}
		if !found {
			return v, packageupdate.ErrNotFound
		}
		v, e = packageupdate.Project(ctx, r, now)
		if e != nil {
			return v, e
		}
	}
	v.Available = available
	if v.Reason == "simulation_only" {
		v.Reason = "ready"
	}
	if !m.ready(now.Unix()) {
		v.Reason = "native_adapter_unavailable"
	}
	return v, nil
}
