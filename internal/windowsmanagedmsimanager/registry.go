package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	msi "localrmm/internal/windowsmanagedmsi"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

const ReusableRegistryVersion = "tracebolt.windows-managed-msi-manager-registry.v3"
const ReusableConfigVersion = "tracebolt.windows-managed-msi-manager-config.v3"
const ReusableSetupPlanVersion = "tracebolt.windows-managed-msi-manager-setup.v3"
const RegistryVersion = "tracebolt.windows-managed-msi-manager-registry.v2"
const FleetConfigVersion = "tracebolt.windows-managed-msi-manager-config.v2"
const FleetSetupPlanVersion = "tracebolt.windows-managed-msi-manager-setup.v2"
const maxRegistryBytes = 65536

type RegistryConfig struct {
	Version     string   `json:"version"`
	Enabled     bool     `json:"enabled"`
	ManagerID   string   `json:"managerId"`
	ConfigFiles []string `json:"configFiles"`
}

func fleetPath(state, name string) string {
	return filepath.Join(state, "windows-managed-msi-fleet", name)
}
func fleetDevicePath(state, device, name string) string {
	return filepath.Join(state, "windows-managed-msi-fleet-"+device, name)
}
func validFleetConfig(c Config) bool {
	return (c.Version == FleetConfigVersion || c.Version == ReusableConfigVersion) && c.Enabled && c.Binding.Validate() == nil && absolute(c.StateDirectory) && c.PrivateKeyFile == fleetPath(c.StateDirectory, "manager.key") && c.SetupReceiptFile == fleetDevicePath(c.StateDirectory, c.Binding.DeviceID, "complete.json") && msi.ValidDigest(c.SetupPlanDigest) && msi.ValidDigest(c.SetupRegistrationDigest)
}
func checkFleetReceipt(c Config) error {
	var r setupComplete
	if _, e := canonicalRead(c.SetupReceiptFile, &r); e != nil {
		return ErrConfiguration
	}
	raw, _ := json.Marshal(c)
	if (r.Version != FleetSetupPlanVersion && r.Version != ReusableSetupPlanVersion) || (r.Version == ReusableSetupPlanVersion) != (c.Version == ReusableConfigVersion) || r.PlanDigest != c.SetupPlanDigest || r.RegistrationDigest != c.SetupRegistrationDigest || r.ConfigurationDigest != msi.Digest(raw) {
		return ErrConfiguration
	}
	return nil
}
func readFleetRegistry(path, state string, limit int) (RegistryConfig, []Config, []byte, error) {
	var r RegistryConfig
	raw, e := lanconfig.ReadProtected(path, true, maxRegistryBytes)
	if e != nil || msi.Canonical(raw, &r, maxRegistryBytes) != nil || (r.Version != RegistryVersion && r.Version != ReusableRegistryVersion) || !r.Enabled || len(r.ConfigFiles) == 0 || len(r.ConfigFiles) > min(limit, msi.MaxDevices) {
		return r, nil, nil, ErrConfiguration
	}
	configs := []Config{}
	paths := map[string]bool{}
	bindings := []msi.Binding{}
	for _, p := range r.ConfigFiles {
		if !absolute(p) || paths[p] {
			return r, nil, nil, ErrConfiguration
		}
		paths[p] = true
		var c Config
		if _, e := canonicalRead(p, &c); e != nil || !validFleetConfig(c) || (r.Version == ReusableRegistryVersion) != (c.Version == ReusableConfigVersion) || c.StateDirectory != state || c.Binding.ManagerID != r.ManagerID || p != fleetDevicePath(state, c.Binding.DeviceID, "manager.json") || checkFleetReceipt(c) != nil {
			return r, nil, nil, ErrConfiguration
		}
		for _, b := range bindings {
			if bindingAlias(b, c.Binding) || b.KeyID != c.Binding.KeyID {
				return r, nil, nil, ErrConfiguration
			}
		}
		bindings = append(bindings, c.Binding)
		configs = append(configs, c)
	}
	return r, configs, raw, nil
}
func bindingAlias(a, b msi.Binding) bool {
	return a.DeviceID == b.DeviceID || a.ExecutorID == b.ExecutorID || a.ExecutorKeyID == b.ExecutorKeyID || a.DeliveryGrantID == b.DeliveryGrantID || a.DeliveryGrantID == b.InstallGrantID || a.InstallGrantID == b.DeliveryGrantID || a.InstallGrantID == b.InstallGrantID
}

type Registry struct {
	managers map[string]*Manager
	ordered  []*Manager
	artifact *ArtifactManager
}

func NewRegistry(managers []*Manager) (*Registry, error) {
	if len(managers) == 0 || len(managers) > msi.MaxDevices || managers[0] == nil {
		return nil, msi.ErrInvalid
	}
	r := &Registry{managers: map[string]*Manager{}, artifact: managers[0].artifact}
	for _, m := range managers {
		if m == nil || m.binding.Validate() != nil || !m.MatchesStore(managers[0].store) || m.artifact != r.artifact || m.spool != managers[0].spool || !bytes.Equal(m.key, managers[0].key) || len(managers) > 1 && r.artifact == nil {
			return nil, msi.ErrAuthority
		}
		for _, old := range r.ordered {
			if bindingAlias(old.binding, m.binding) {
				return nil, msi.ErrAuthority
			}
		}
		r.managers[m.binding.DeviceID] = m
		r.ordered = append(r.ordered, m)
	}
	return r, nil
}
func (r *Registry) Manager(device string) *Manager {
	if r == nil {
		return nil
	}
	return r.managers[device]
}
func (r *Registry) Managers() []*Manager {
	if r == nil {
		return nil
	}
	return append([]*Manager(nil), r.ordered...)
}
func (r *Registry) Close() {
	for _, m := range r.Managers() {
		m.Close()
	}
}
func (r *Registry) PublicKeys() []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for i, m := range r.Managers() {
		keys := m.PublicKeys()
		if len(keys) != 2 {
			return nil
		}
		if i == 0 {
			out = append(out, keys[0])
		}
		out = append(out, keys[1])
	}
	return out
}
func (r *Registry) ConfigureOperatorPolicy(delivery, install func(string) bool) error {
	if r == nil || delivery == nil || install == nil {
		return msi.ErrInvalid
	}
	for _, m := range r.ordered {
		if e := m.ConfigureOperatorPolicy(delivery, install); e != nil {
			return e
		}
	}
	if r.artifact != nil {
		r.artifact.mu.Lock()
		defer r.artifact.mu.Unlock()
		if r.artifact.deliveryAllowed != nil {
			return msi.ErrConflict
		}
		r.artifact.deliveryAllowed = delivery
	}
	return nil
}
func (r *Registry) MatchesBinding(b enrollmentstate.Binding) bool {
	if r == nil || len(r.ordered) == 0 {
		return false
	}
	for _, m := range r.ordered {
		if !m.MatchesBinding(b) || !m.OperatorPolicyConfigured() {
			return false
		}
	}
	return true
}
func (r *Registry) Artifact() *ArtifactManager {
	if r == nil {
		return nil
	}
	return r.artifact
}

// Explicit v2, exact registered coverage, one key and one physical spool. Legacy
// singleton loading retains its original configuration and receipt bytes.
func LoadRegistry(ctx context.Context, store *enrollmentstore.Store, path, state string, forbidden ...ed25519.PublicKey) (*Registry, error) {
	if ctx == nil || store == nil || !absolute(path) || !absolute(state) {
		return nil, ErrConfiguration
	}
	raw, e := lanconfig.ReadProtected(path, true, maxRegistryBytes)
	if e != nil {
		return nil, ErrConfiguration
	}
	var h struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return nil, ErrConfiguration
	}
	if h.Version == ConfigVersion {
		m, e := Load(ctx, store, path, state, forbidden...)
		if e != nil {
			return nil, e
		}
		r, e := NewRegistry([]*Manager{m})
		if e != nil {
			m.Close()
		}
		return r, e
	}
	_, configs, raw, e := readFleetRegistry(path, state, store.Config().RecordLimit)
	if e != nil {
		return nil, e
	}
	key, e := lanconfig.ReadProtected(fleetPath(state, "manager.key"), true, 64)
	defer clear(key)
	if e != nil || len(key) != 64 || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32])) {
		return nil, ErrConfiguration
	}
	pub := ed25519.PublicKey(key[32:])
	hash := sha256.Sum256(key)
	for _, other := range forbidden {
		if bytes.Equal(other, pub) {
			return nil, ErrConfiguration
		}
	}
	bindings, e := store.WindowsManagedMSIFleetBindings(ctx, pub)
	if e != nil || len(bindings) != len(configs) {
		return nil, ErrConfiguration
	}
	expected := map[string]msi.Binding{}
	for _, b := range bindings {
		expected[b.DeviceID] = b
	}
	for _, c := range configs {
		saved, err := store.ReadRegisteredWindowsManagedMSI(ctx, c.Binding, pub)
		if err != nil || (c.Version == ReusableConfigVersion) != (saved.Grant.Version == msi.ReusableGrantVersion) {
			return nil, ErrConfiguration
		}
		if expected[c.Binding.DeviceID] != c.Binding {
			return nil, ErrConfiguration
		}
	}
	check := func() error {
		current, e := lanconfig.ReadProtected(path, true, maxRegistryBytes)
		if e != nil || !bytes.Equal(raw, current) {
			return ErrConfiguration
		}
		currentKey, e := lanconfig.ReadProtected(fleetPath(state, "manager.key"), true, 64)
		defer clear(currentKey)
		if e != nil || sha256.Sum256(currentKey) != hash {
			return ErrConfiguration
		}
		return nil
	}
	spool, e := OpenSpool(state)
	if e != nil {
		return nil, e
	}
	artifact, e := newArtifactManager(ctx, store, pub, spool, time.Now, check)
	if e != nil {
		return nil, e
	}
	managers := []*Manager{}
	fail := func(e error) (*Registry, error) {
		for _, m := range managers {
			m.Close()
		}
		return nil, e
	}
	for _, c := range configs {
		config := c
		expectedRaw, _ := json.Marshal(c)
		guard := func() error {
			if e := check(); e != nil {
				return e
			}
			current, e := lanconfig.ReadProtected(fleetDevicePath(state, config.Binding.DeviceID, "manager.json"), true, 32768)
			if e != nil || !bytes.Equal(expectedRaw, current) || checkFleetReceipt(config) != nil {
				return ErrConfiguration
			}
			return nil
		}
		m, e := open(ctx, store, c.Binding, ed25519.PrivateKey(key), spool, time.Now, guard, artifact)
		if e != nil {
			return fail(e)
		}
		managers = append(managers, m)
		for _, k := range m.PublicKeys() {
			for _, other := range forbidden {
				if bytes.Equal(k, other) {
					return fail(ErrConfiguration)
				}
			}
		}
	}
	if e = check(); e != nil {
		return fail(e)
	}
	r, e := NewRegistry(managers)
	if e != nil {
		return fail(e)
	}
	return r, nil
}

type ArtifactTarget struct {
	DeviceID      string `json:"deviceId"`
	BindingDigest string `json:"bindingDigest"`
}
type ArtifactView struct {
	CanRetire               *bool                 `json:"canRetire,omitempty"`
	RetirementBlocked       *string               `json:"retirementBlocked,omitempty"`
	Reusable                bool                  `json:"reusable,omitempty"`
	PublisherStatus         string                `json:"publisherStatus,omitempty"`
	PublisherEvidenceDigest string                `json:"publisherEvidenceDigest,omitempty"`
	RetiredCount            string                `json:"retiredCount,omitempty"`
	Recent                  []msi.RetiredArtifact `json:"recent,omitempty"`
	MaxRetainedPayloadBytes int64                 `json:"maxRetainedPayloadBytes,omitempty"`
	Version                 string                `json:"version"`
	ServerNow               int64                 `json:"serverNow"`
	State                   string                `json:"state"`
	ArtifactID              string                `json:"artifactId"`
	Package                 *msi.Selection        `json:"package"`
	NativeAcceptanceDigest  string                `json:"nativeAcceptanceDigest"`
	UploadOffset            int64                 `json:"uploadOffset"`
	UploadPendingDigest     string                `json:"uploadPendingDigest"`
	Targets                 []ArtifactTarget      `json:"targets"`
}

func (r *Registry) ArtifactView(ctx context.Context) (ArtifactView, error) {
	if r == nil || r.artifact == nil {
		return ArtifactView{}, msi.ErrUnavailable
	}
	record, e := r.artifact.read(ctx)
	if e != nil {
		return ArtifactView{}, e
	}
	out := ArtifactView{Version: "tracebolt.windows-managed-msi-artifact.v2", ServerNow: r.artifact.now().Unix(), State: "empty", Targets: []ArtifactTarget{}}
	if record.Version == msi.ReusableArtifactRecordVersion {
		out.Version = "tracebolt.windows-managed-msi-artifact.v3"
		out.Reusable = true
		out.RetiredCount = strconv.FormatUint(record.RetiredCount, 10)
		out.Recent = record.Recent
		out.MaxRetainedPayloadBytes = msi.MaxRetainedPayloadBytes
		eligible := record.Artifact != nil && record.Artifact.CompletedAt != 0 && !record.RetirementStarted && !record.Retired
		reason := "not_ready"
		if eligible {
			reason = ""
		}
		if record.RetirementStarted && !record.Retired {
			reason = "unconfirmed_custody"
		}
		out.CanRetire = &eligible
		out.RetirementBlocked = &reason
	}
	if out.ServerNow < record.ClockFloor {
		return ArtifactView{}, msi.ErrExpired
	}
	if a := record.Artifact; a != nil {
		p := a.Package
		out.Package = &p
		out.ArtifactID = msi.ArtifactIdentity(*a)
		out.NativeAcceptanceDigest = a.NativeAcceptanceDigest
		out.PublisherStatus = a.PublisherStatus
		out.PublisherEvidenceDigest = a.PublisherEvidenceDigest
		out.UploadOffset = a.Offset
		out.UploadPendingDigest = a.PendingDigest
		out.State = "upload_incomplete"
		if a.CompletedAt != 0 {
			out.State = "uploaded"
		}
	}
	if record.RetirementStarted {
		out.State = "intervention_required"
	}
	if record.Retired {
		out.State = "retired"
	}
	for _, m := range r.ordered {
		out.Targets = append(out.Targets, ArtifactTarget{m.binding.DeviceID, msi.BindingDigest(m.binding)})
		if out.Reusable && *out.CanRetire {
			saved, err := m.store.ReadRegisteredWindowsManagedMSI(msi.WithFinalCheck(ctx, m.configurationCheck), m.binding, m.key.Public().(ed25519.PublicKey))
			if err != nil || saved.Artifact != nil && msi.ArtifactIdentity(*saved.Artifact) == out.ArtifactID && len(saved.RetiredReport) == 0 {
				*out.CanRetire = false
				*out.RetirementBlocked = "awaiting_device_retirement"
			}
		}
	}
	sort.Slice(out.Targets, func(i, j int) bool { return out.Targets[i].DeviceID < out.Targets[j].DeviceID })
	return out, nil
}
