package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorauth"
	msi "localrmm/internal/windowsmanagedmsi"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const SetupPlanVersion = "tracebolt.windows-managed-msi-manager-setup.v1"

var ErrSetup = errors.New("windows_managed_msi_setup_blocked_preserve_existing_state")

type SetupRequest struct {
	Catalogue        bool   `json:"catalogue,omitempty"`
	Scheduled        bool   `json:"scheduled,omitempty"`
	Reusable         bool   `json:"reusable,omitempty"`
	Fleet            bool   `json:"fleet,omitempty"`
	AdditionalDevice bool   `json:"additionalDevice,omitempty"`
	Phase            string `json:"phase"`
	LANConfig        string `json:"lanConfig"`
	EnrollmentConfig string `json:"enrollmentConfig"`
	DeviceID         string `json:"deviceId"`
	ExpiresAt        int64  `json:"expiresAt"`
	RegistrationFile string `json:"registrationFile,omitempty"`
}
type SetupPlan struct {
	ScheduleOperators      []string               `json:"scheduleOperators,omitempty"`
	OriginalConfigDigests  []string               `json:"originalConfigDigests,omitempty"`
	OriginalConfigFiles    []string               `json:"originalConfigFiles,omitempty"`
	OriginalRegistryDigest string                 `json:"originalRegistryDigest,omitempty"`
	ManagerKeyID           string                 `json:"managerKeyId,omitempty"`
	Version                string                 `json:"version"`
	Request                SetupRequest           `json:"request"`
	ManagerID              string                 `json:"managerId"`
	ManagerOrigin          string                 `json:"managerOrigin"`
	StateDirectory         string                 `json:"stateDirectory"`
	IncarnationDigest      string                 `json:"incarnationDigest"`
	CurrentLeafDigest      string                 `json:"currentLeafDigest"`
	CurrentLeafNotAfter    int64                  `json:"currentLeafNotAfter"`
	ExpiresAt              int64                  `json:"expiresAt"`
	ConfigurationDigest    string                 `json:"configurationDigest"`
	OtherPurposeKeyIDs     []string               `json:"otherPurposeKeyIds"`
	DeliveryOperators      []string               `json:"deliveryOperators"`
	InstallOperators       []string               `json:"installOperators"`
	UID                    int                    `json:"uid"`
	GID                    int                    `json:"gid"`
	Offer                  *msi.SetupOffer        `json:"offer,omitempty"`
	Registration           *msi.SetupRegistration `json:"registration,omitempty"`
	RegistrationDigest     string                 `json:"registrationDigest,omitempty"`
	Digest                 string                 `json:"digest"`
}
type setupComplete struct {
	Version             string `json:"version"`
	PlanDigest          string `json:"planDigest"`
	RegistrationDigest  string `json:"registrationDigest"`
	ConfigurationDigest string `json:"configurationDigest"`
}
type setupPrepared struct {
	Plan        *SetupPlan `json:"plan,omitempty"`
	Version     string     `json:"version"`
	PlanDigest  string     `json:"planDigest"`
	OfferDigest string     `json:"offerDigest"`
}
type setupMaterial struct {
	plan       SetupPlan
	lan        lanconfig.Material
	enrollment enrollmentconfig.Material
	config     enrollmentstate.Config
	existing   []Config
}

func setupPath(state, name string) string {
	return filepath.Join(state, "windows-managed-msi-setup", name)
}
func SetupLANPath(state string) string   { return setupPath(state, "lan.json") }
func SetupOfferPath(state string) string { return setupPath(state, "offer.json") }
func (p SetupPlan) digest() string       { p.Digest = ""; b, _ := json.Marshal(p); return msi.Digest(b) }
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func canonicalRead(path string, v any) ([]byte, error) {
	raw, e := lanconfig.ReadProtected(path, true, 32768)
	if e != nil || msi.Canonical(raw, v, 32768) != nil {
		return nil, ErrSetup
	}
	return raw, nil
}
func absent(paths ...string) bool {
	for _, p := range paths {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return false
		}
	}
	return true
}
func publicFromPrivate(path string) (ed25519.PublicKey, error) {
	raw, e := lanconfig.ReadProtected(path, true, 64)
	defer clear(raw)
	if e != nil || len(raw) != 64 || !bytes.Equal(raw, ed25519.NewKeyFromSeed(raw[:32])) {
		return nil, ErrSetup
	}
	return bytes.Clone(raw[32:]), nil
}
func loadSetupInputs(ctx context.Context, q SetupRequest, now time.Time) (setupMaterial, error) {
	var out setupMaterial
	if ctx == nil || q.Phase != "prepare" && q.Phase != "finalize" || !absolute(q.LANConfig) || !absolute(q.EnrollmentConfig) {
		return out, ErrSetup
	}
	m, e := lanconfig.Load(q.LANConfig)
	if e != nil || m.Config.Profile != lanconfig.TLS || !m.Config.WindowsInventoryEnabled || q.Catalogue && (!q.Reusable || !q.Fleet) || q.Reusable && !q.Fleet || q.Scheduled && (!q.Fleet || !q.Reusable) || q.AdditionalDevice && !q.Fleet || (m.Config.WindowsManagedMSIConfigFile != "") != q.AdditionalDevice || q.Fleet && !enrollmentcrypto.ValidID(q.DeviceID, "agent_") {
		return out, ErrSetup
	}
	en, e := enrollmentconfig.Load(q.EnrollmentConfig, m, now)
	if e != nil {
		return out, ErrSetup
	}
	cfg, e := en.WindowsStoreConfig()
	if e != nil {
		return out, ErrSetup
	}
	p := SetupPlan{Version: SetupPlanVersion, Request: q, ManagerID: cfg.Binding.InstanceID, ManagerOrigin: m.Config.AgentOrigin, StateDirectory: m.Config.StateDirectory, ExpiresAt: q.ExpiresAt, OtherPurposeKeyIDs: []string{}, DeliveryOperators: []string{}, InstallOperators: []string{}, UID: os.Geteuid(), GID: os.Getegid()}
	if q.Fleet {
		p.Version = FleetSetupPlanVersion
		if q.Reusable {
			p.Version = ReusableSetupPlanVersion
		}
		if q.Scheduled {
			p.Version = ScheduledSetupPlanVersion
		}
	}
	if q.Catalogue {
		p.Version = CatalogueSetupPlanVersion
		if q.Scheduled {
			p.Version = ScheduledCatalogueSetupPlanVersion
		}
	}
	var existing []Config
	if q.AdditionalDevice {
		registry, configs, raw, e := readFleetRegistry(m.Config.WindowsManagedMSIConfigFile, p.StateDirectory, cfg.RecordLimit)
		if e != nil || registry.ManagerID != p.ManagerID || registry.Version != setupRegistryVersion(q) || len(configs) >= min(cfg.RecordLimit, msi.MaxDevices) {
			return out, ErrSetup
		}
		pub, e := publicFromPrivate(fleetPath(p.StateDirectory, "manager.key"))
		if e != nil {
			return out, ErrSetup
		}
		p.ManagerKeyID = msi.Digest(pub)
		p.OriginalRegistryDigest = msi.Digest(raw)
		p.OriginalConfigFiles = append([]string(nil), registry.ConfigFiles...)
		for _, c := range configs {
			raw, _ := json.Marshal(c)
			p.OriginalConfigDigests = append(p.OriginalConfigDigests, msi.Digest(raw))
			if c.Binding.DeviceID == q.DeviceID || c.Binding.KeyID != p.ManagerKeyID {
				return out, ErrSetup
			}
		}
		existing = configs
	}
	for _, op := range m.Operators {
		canInstall, canSchedule := false, false
		for _, cap := range op.Capabilities {
			if cap == operatorauth.WindowsManagedMSIDeliver {
				p.DeliveryOperators = append(p.DeliveryOperators, op.ID)
			}
			if cap == operatorauth.WindowsManagedMSISchedule {
				canSchedule = true
			}
			if cap == operatorauth.WindowsManagedMSIInstall {
				canInstall = true
				p.InstallOperators = append(p.InstallOperators, op.ID)
			}
		}
		if q.Scheduled && canInstall && canSchedule {
			p.ScheduleOperators = append(p.ScheduleOperators, op.ID)
		}
	}
	sort.Strings(p.ScheduleOperators)
	sort.Strings(p.DeliveryOperators)
	sort.Strings(p.InstallOperators)
	if len(p.DeliveryOperators) == 0 || len(p.InstallOperators) == 0 || q.Scheduled && len(p.ScheduleOperators) == 0 {
		return out, ErrSetup
	}
	var inputs [][]byte
	for _, path := range []string{q.LANConfig, q.EnrollmentConfig} {
		raw, e := lanconfig.ReadProtected(path, false, 16384)
		if e != nil {
			return out, ErrSetup
		}
		inputs = append(inputs, raw)
	}
	raw, _ := json.Marshal(inputs)
	p.ConfigurationDigest = msi.Digest(raw)
	for _, der := range append([][]byte{en.Issuer().IssuerDER(), en.Issuer().RootDER()}, m.Server.Certificate...) {
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return out, ErrSetup
		}
		if pub, ok := cert.PublicKey.(ed25519.PublicKey); ok {
			p.OtherPurposeKeyIDs = append(p.OtherPurposeKeyIDs, msi.Digest(pub))
		}
	}
	for _, path := range []string{m.Config.ServiceActionsConfigFile, m.Config.WindowsServiceActionsConfigFile, m.Config.WindowsUpdateJobsConfigFile, m.Config.WindowsSoftwareJobsConfigFile, m.Config.PackageActionsConfigFile} {
		ids, e := configuredKeyIDs(path, 0)
		if e != nil {
			return out, e
		}
		p.OtherPurposeKeyIDs = append(p.OtherPurposeKeyIDs, ids...)
	}
	sort.Strings(p.OtherPurposeKeyIDs)
	if q.Phase == "finalize" {
		if q.ExpiresAt != 0 || !absolute(q.RegistrationFile) {
			return out, ErrSetup
		}
		var offer msi.SetupOffer
		var prepared setupPrepared
		offerRaw, e := canonicalRead(setupPlanPath(p, "offer.json"), &offer)
		if e != nil || offer.Validate() != nil || offer.Reusable() != q.Reusable || offer.Scheduled() != q.Scheduled {
			return out, ErrSetup
		}
		if _, e = canonicalRead(setupPlanPath(p, "prepared.json"), &prepared); e != nil || prepared.Version != p.Version || !msi.ValidDigest(prepared.PlanDigest) || prepared.OfferDigest != msi.Digest(offerRaw) {
			return out, ErrSetup
		}
		if q.Fleet && (prepared.Plan == nil || prepared.Plan.Version != p.Version || prepared.Plan.Digest != prepared.Plan.digest() || prepared.Plan.Digest != prepared.PlanDigest || prepared.Plan.Request.Phase != "prepare" || prepared.Plan.Request.DeviceID != q.DeviceID || prepared.Plan.Request.LANConfig != q.LANConfig || prepared.Plan.Request.EnrollmentConfig != q.EnrollmentConfig || prepared.Plan.ConfigurationDigest != p.ConfigurationDigest || prepared.Plan.Request.Fleet != q.Fleet || prepared.Plan.Request.Reusable != q.Reusable || prepared.Plan.Request.Scheduled != q.Scheduled || prepared.Plan.Request.Catalogue != q.Catalogue || prepared.Plan.Request.AdditionalDevice != q.AdditionalDevice || !sameJSON(prepared.Plan.OriginalConfigFiles, p.OriginalConfigFiles) || !sameJSON(prepared.Plan.OriginalConfigDigests, p.OriginalConfigDigests) || prepared.Plan.OriginalRegistryDigest != p.OriginalRegistryDigest || prepared.Plan.ManagerKeyID != p.ManagerKeyID || !sameJSON(prepared.Plan.DeliveryOperators, p.DeliveryOperators) || !sameJSON(prepared.Plan.InstallOperators, p.InstallOperators) || !sameJSON(prepared.Plan.ScheduleOperators, p.ScheduleOperators) || !sameJSON(prepared.Plan.OtherPurposeKeyIDs, p.OtherPurposeKeyIDs)) {
			return out, ErrSetup
		}
		pub, e := publicFromPrivate(setupPlanKey(p))
		if e != nil || !bytes.Equal(pub, offer.ManagerPublicKey) {
			return out, ErrSetup
		}
		registrationRaw, e := lanconfig.ReadProtected(q.RegistrationFile, true, 32769)
		if e != nil {
			return out, ErrSetup
		}
		registrationRaw = bytes.TrimSuffix(registrationRaw, []byte("\n"))
		reg, e := msi.DecodeSetupRegistration(registrationRaw)
		if e != nil || !sameJSON(reg.Offer, offer) || reg.Grant.Reusable() != q.Reusable || reg.Grant.Scheduled() != q.Scheduled {
			return out, ErrSetup
		}
		for _, c := range existing {
			if bindingAlias(c.Binding, reg.Grant.Binding) {
				return out, ErrSetup
			}
		}
		p.Offer = &offer
		p.Registration = &reg
		p.ExpiresAt = offer.ExpiresAt
		p.RegistrationDigest = msi.Digest(registrationRaw)
		for _, key := range [][]byte{offer.ManagerPublicKey, reg.ExecutorPublicKey} {
			for _, other := range p.OtherPurposeKeyIDs {
				if msi.Digest(key) == other {
					return out, ErrSetup
				}
			}
		}
	}
	if !msi.ValidTime(now.Unix()) || !msi.ValidTime(p.ExpiresAt) || now.Unix() >= p.ExpiresAt {
		return out, ErrSetup
	}
	out = setupMaterial{plan: p, lan: m, enrollment: en, config: cfg, existing: existing}
	return out, nil
}

// Inspect only existing protected enrollment state. Planning creates no files,
// credentials, scopes or optional tables; partial state is never adopted.
func PlanSetup(ctx context.Context, q SetupRequest, now time.Time) (SetupPlan, error) {
	m, e := loadSetupInputs(ctx, q, now)
	if e != nil {
		return SetupPlan{}, e
	}
	p := m.plan
	in, e := enrollmentstore.InspectWindowsManagedMSISetup(ctx, filepath.Join(p.StateDirectory, enrollmentconfig.WindowsDatabaseFile), m.enrollment.Issuer().IssuerDER(), q.DeviceID, now)
	if e != nil || !setupInspectionMatches(m, in) {
		return SetupPlan{}, ErrSetup
	}
	p.IncarnationDigest = "sha256:" + in.Identity.Issuance.CertificateHash
	p.CurrentLeafDigest = in.CurrentLeafDigest
	p.CurrentLeafNotAfter = in.CurrentLeafNotAfter
	if p.ExpiresAt > in.CurrentLeafNotAfter {
		return SetupPlan{}, ErrSetup
	}
	if q.Phase == "prepare" {
		if q.RegistrationFile != "" || !absent(setupPlanIntent(p), setupPlanPath(p, "")) || !q.AdditionalDevice && (!setupSpoolAbsent(p.StateDirectory) || q.Fleet && !absent(fleetPath(p.StateDirectory, ""))) {
			return SetupPlan{}, ErrSetup
		}
	} else {
		if !absent(setupPlanPath(p, "finalize-started.json"), setupPlanPath(p, "registration.json"), setupPlanPath(p, "manager.json"), setupPlanPath(p, "complete.json"), SetupPlanLANPath(p)) || !q.AdditionalDevice && !setupSpoolAbsent(p.StateDirectory) || q.Fleet && !absent(setupPlanPath(p, "registry.json")) || p.Offer.ManagerID != p.ManagerID || p.Offer.DeviceID != q.DeviceID || p.Offer.ManagerOrigin != p.ManagerOrigin || p.Offer.IncarnationDigest != p.IncarnationDigest {
			return SetupPlan{}, ErrSetup
		}
	}
	p.Digest = p.digest()
	return p, nil
}
func ApplySetup(ctx context.Context, p SetupPlan, approval string, clock func() time.Time) (*msi.SetupOffer, error) {
	if ctx == nil || clock == nil || approval != p.Digest || p.Digest != p.digest() {
		return nil, ErrSetup
	}
	fresh, e := PlanSetup(ctx, p.Request, clock().UTC())
	if e != nil || !sameJSON(fresh, p) {
		return nil, ErrSetup
	}
	m, e := loadSetupInputs(ctx, p.Request, clock().UTC())
	if e != nil {
		return nil, e
	}
	start := clock().UTC()
	last := start
	inputs := func() error {
		n := clock().UTC()
		if n.Before(last) || n.Unix() >= p.ExpiresAt || n.Unix() >= p.CurrentLeafNotAfter {
			return ErrSetup
		}
		last = n
		next, e := loadSetupInputs(ctx, p.Request, n)
		if e != nil {
			return e
		}
		want := m.plan
		got := next.plan
		if !sameJSON(want, got) {
			return ErrSetup
		}
		return nil
	}
	live := func() error {
		if inputs() != nil {
			return ErrSetup
		}
		in, e := enrollmentstore.InspectWindowsManagedMSISetup(ctx, filepath.Join(p.StateDirectory, enrollmentconfig.WindowsDatabaseFile), m.enrollment.Issuer().IssuerDER(), p.Request.DeviceID, clock().UTC())
		if e != nil || !setupInspectionMatches(m, in) || in.CurrentLeafDigest != p.CurrentLeafDigest || in.CurrentLeafNotAfter != p.CurrentLeafNotAfter || "sha256:"+in.Identity.Issuance.CertificateHash != p.IncarnationDigest {
			return ErrSetup
		}
		return inputs()
	}
	create := func(path string, v any) error {
		raw, e := json.Marshal(v)
		if e != nil {
			return e
		}
		return createSetupFile(path, raw)
	}
	if live() != nil {
		return nil, ErrSetup
	}
	if p.Request.Phase == "prepare" {
		if create(setupPlanIntent(p), p) != nil || createSetupDirectory(setupPlanPath(p, "")) != nil {
			return nil, ErrSetup
		}
		if p.Request.Fleet && !p.Request.AdditionalDevice && createSetupDirectory(fleetPath(p.StateDirectory, "")) != nil {
			return nil, ErrSetup
		}
		var pub ed25519.PublicKey
		var key ed25519.PrivateKey
		if p.Request.AdditionalDevice {
			pub, e = publicFromPrivate(setupPlanKey(p))
		} else {
			pub, key, e = ed25519.GenerateKey(rand.Reader)
		}

		defer clear(key)
		if e != nil {
			return nil, ErrSetup
		}
		for _, other := range p.OtherPurposeKeyIDs {
			if msi.Digest(pub) == other {
				return nil, ErrSetup
			}
		}
		offer := msi.SetupOffer{Version: msi.SetupOfferVersion, ManagerID: p.ManagerID, DeviceID: p.Request.DeviceID, IncarnationDigest: p.IncarnationDigest, ManagerOrigin: p.ManagerOrigin, ManagerPublicKey: pub, ExpiresAt: p.ExpiresAt}
		if p.Request.Reusable {
			offer.Version = msi.ReusableOfferVersion
		}
		if p.Request.Scheduled {
			offer.Version = msi.ScheduledOfferVersion
		}
		if offer.Validate() != nil || !p.Request.AdditionalDevice && createSetupFile(setupPlanKey(p), key) != nil || live() != nil || create(setupPlanPath(p, "offer.json"), offer) != nil {
			return nil, ErrSetup
		}
		raw, _ := json.Marshal(offer)
		prepared := setupPrepared{Version: p.Version, PlanDigest: p.Digest, OfferDigest: msi.Digest(raw)}
		if p.Request.Fleet {
			copy := p
			prepared.Plan = &copy
		}
		if create(setupPlanPath(p, "prepared.json"), prepared) != nil || live() != nil {
			return nil, ErrSetup
		}
		return &offer, nil
	}
	if p.Registration == nil || p.Offer == nil {
		return nil, ErrSetup
	}
	if create(setupPlanPath(p, "finalize-started.json"), p) != nil || create(setupPlanPath(p, "registration.json"), p.Registration) != nil || !p.Request.AdditionalDevice && createSetupSpool(p) != nil || live() != nil {
		return nil, ErrSetup
	}
	store, e := enrollmentstore.Open(filepath.Join(p.StateDirectory, enrollmentconfig.WindowsDatabaseFile), m.config, m.enrollment.Issuer().IssuerDER())
	if e != nil {
		return nil, ErrSetup
	}
	defer store.Close()
	guarded := msi.WithFinalCheck(enrollmentstore.WithWindowsManagedMSISetupExpectedLeaf(enrollmentstore.WithOverviewClock(ctx, clock), p.CurrentLeafDigest, p.CurrentLeafNotAfter), func() error {
		if inputs() != nil {
			return ErrSetup
		}
		var saved SetupPlan
		var reg msi.SetupRegistration
		if _, e := canonicalRead(setupPlanPath(p, "finalize-started.json"), &saved); e != nil || !sameJSON(saved, p) {
			return ErrSetup
		}
		if _, e := canonicalRead(setupPlanPath(p, "registration.json"), &reg); e != nil || !sameJSON(reg, p.Registration) {
			return ErrSetup
		}
		return inputs()
	})
	if p.Request.Catalogue {
		e = store.SetupWindowsMSICatalogueCreateOnly(guarded, p.Offer.ManagerPublicKey, p.Registration.ExecutorPublicKey, p.Registration.Grant, clock().UTC(), p.Request.AdditionalDevice)
	} else if p.Request.Fleet {
		e = store.SetupWindowsManagedMSIFleetCreateOnly(guarded, p.Offer.ManagerPublicKey, p.Registration.ExecutorPublicKey, p.Registration.Grant, clock().UTC(), p.Request.AdditionalDevice)
	} else {
		e = store.SetupWindowsManagedMSICreateOnly(guarded, p.Offer.ManagerPublicKey, p.Registration.ExecutorPublicKey, p.Registration.Grant, clock().UTC())
	}
	if e != nil {
		return nil, e
	}
	c := Config{Version: ConfigVersion, Enabled: true, Binding: p.Registration.Grant.Binding, StateDirectory: p.StateDirectory, PrivateKeyFile: setupPlanKey(p), SetupReceiptFile: setupPlanPath(p, "complete.json"), SetupPlanDigest: p.Digest, SetupRegistrationDigest: p.RegistrationDigest}
	if p.Request.Fleet {
		c.Version = FleetConfigVersion
		if p.Request.Reusable {
			c.Version = ReusableConfigVersion
		}
		if p.Request.Scheduled {
			c.Version = ScheduledConfigVersion
		}
	}
	if p.Request.Catalogue {
		c.Version = CatalogueConfigVersion
		if p.Request.Scheduled {
			c.Version = ScheduledCatalogueConfigVersion
		}
	}
	lan := m.lan.Config
	lan.WindowsManagedMSIConfigFile = setupPlanPath(p, "manager.json")
	if p.Request.Fleet {
		registry := RegistryConfig{Version: RegistryVersion, Enabled: true, ManagerID: p.ManagerID, ConfigFiles: append(append([]string(nil), p.OriginalConfigFiles...), setupPlanPath(p, "manager.json"))}
		registry.Version = setupRegistryVersion(p.Request)
		if create(setupPlanPath(p, "registry.json"), registry) != nil {
			return nil, ErrSetup
		}
		lan.WindowsManagedMSIConfigFile = setupPlanPath(p, "registry.json")
	}
	raw, _ := json.Marshal(c)
	if inputs() != nil || create(setupPlanPath(p, "manager.json"), c) != nil || create(SetupPlanLANPath(p), lan) != nil || create(c.SetupReceiptFile, setupComplete{p.Version, p.Digest, p.RegistrationDigest, msi.Digest(raw)}) != nil || inputs() != nil {
		return nil, ErrSetup
	}
	return nil, nil
}

// Read only explicit supported configuration paths, at most one registry level.
// Key identities are public; no private byte digest appears in a plan.
func configuredKeyIDs(path string, depth int) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	if depth > 1 || !absolute(path) {
		return nil, ErrSetup
	}
	raw, e := lanconfig.ReadProtected(path, true, 65536)
	if e != nil {
		return nil, ErrSetup
	}
	var c struct {
		Version        string   `json:"version"`
		Enabled        bool     `json:"enabled"`
		PrivateKeyFile string   `json:"privateKeyFile"`
		ConfigFiles    []string `json:"configFiles"`
		Binding        struct {
			KeyID         string `json:"keyId"`
			ExecutorKeyID string `json:"executorKeyId"`
		} `json:"binding"`
	}
	if json.Unmarshal(raw, &c) != nil || !c.Enabled {
		return nil, ErrSetup
	}
	if len(c.ConfigFiles) > 0 {
		if depth != 0 || len(c.ConfigFiles) > 25 || c.Version != "tracebolt.windows-selected-update-manager-registry.v2" && c.Version != "tracebolt.windows-prepared-msi-manager-registry.v2" && c.Version != RegistryVersion && c.Version != ReusableRegistryVersion && c.Version != ScheduledRegistryVersion && c.Version != CatalogueRegistryVersion && c.Version != ScheduledCatalogueRegistryVersion {
			return nil, ErrSetup
		}
		var out []string
		for _, p := range c.ConfigFiles {
			ids, e := configuredKeyIDs(p, depth+1)
			if e != nil {
				return nil, e
			}
			out = append(out, ids...)
		}
		return out, nil
	}
	pub, e := publicFromPrivate(c.PrivateKeyFile)
	if e != nil || !keyvalidation.Ed25519(pub) {
		return nil, ErrSetup
	}
	ids := []string{msi.Digest(pub)}
	if c.Binding.KeyID != "" && c.Binding.KeyID != ids[0] {
		return nil, ErrSetup
	}
	if c.Binding.ExecutorKeyID != "" {
		if !msi.ValidDigest(c.Binding.ExecutorKeyID) {
			return nil, ErrSetup
		}
		ids = append(ids, c.Binding.ExecutorKeyID)
	}
	return ids, nil
}

func setupPlanPath(p SetupPlan, name string) string {
	if p.Request.Fleet {
		return fleetDevicePath(p.StateDirectory, p.Request.DeviceID, name)
	}
	return setupPath(p.StateDirectory, name)
}
func setupPlanIntent(p SetupPlan) string {
	if p.Request.Fleet {
		return filepath.Join(p.StateDirectory, "windows-managed-msi-fleet-"+p.Request.DeviceID+"-started.json")
	}
	return filepath.Join(p.StateDirectory, "windows-managed-msi-setup-started.json")
}
func setupPlanKey(p SetupPlan) string {
	if p.Request.Fleet {
		return fleetPath(p.StateDirectory, "manager.key")
	}
	return setupPath(p.StateDirectory, "manager.key")
}
func SetupPlanLANPath(p SetupPlan) string { return setupPlanPath(p, "lan.json") }
func setupInspectionMatches(m setupMaterial, in enrollmentstore.WindowsManagedMSISetupInspection) bool {
	if in.Config != m.config || in.OtherMutatorPresent || in.DeviceRegistered {
		return false
	}
	if !m.plan.Request.AdditionalDevice {
		return in.Status == "absent"
	}
	if !in.Fleet || in.Status != "fenced" || len(in.RegisteredBindings) != len(m.existing) || in.RegisteredDevices != len(m.existing) || msi.Digest(in.PublicKey) != m.plan.ManagerKeyID {
		return false
	}
	expected := map[string]msi.Binding{}
	for _, c := range m.existing {
		expected[c.Binding.DeviceID] = c.Binding
	}
	for _, b := range in.RegisteredBindings {
		if expected[b.DeviceID] != b {
			return false
		}
		delete(expected, b.DeviceID)
	}
	return len(expected) == 0
}

func setupRegistryVersion(q SetupRequest) string {
	if q.Catalogue {
		if q.Scheduled {
			return ScheduledCatalogueRegistryVersion
		}
		return CatalogueRegistryVersion
	}
	if q.Scheduled {
		return ScheduledRegistryVersion
	}
	if q.Reusable {
		return ReusableRegistryVersion
	}
	return RegistryVersion
}

func setupSpoolAbsent(state string) bool {
	if !absent(SpoolPath(state)) {
		return false
	}
	for i := 0; i < msi.MaxCatalogueEntries; i++ {
		if !absent(catalogueSpoolPath(state, i)) {
			return false
		}
	}
	return true
}
func createSetupSpool(p SetupPlan) error {
	if p.Request.Catalogue {
		return CreateCatalogueSpool(p.StateDirectory)
	}
	return CreateSpool(p.StateDirectory)
}
