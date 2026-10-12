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
	Phase            string `json:"phase"`
	LANConfig        string `json:"lanConfig"`
	EnrollmentConfig string `json:"enrollmentConfig"`
	DeviceID         string `json:"deviceId"`
	ExpiresAt        int64  `json:"expiresAt"`
	RegistrationFile string `json:"registrationFile,omitempty"`
}
type SetupPlan struct {
	Version             string                 `json:"version"`
	Request             SetupRequest           `json:"request"`
	ManagerID           string                 `json:"managerId"`
	ManagerOrigin       string                 `json:"managerOrigin"`
	StateDirectory      string                 `json:"stateDirectory"`
	IncarnationDigest   string                 `json:"incarnationDigest"`
	CurrentLeafDigest   string                 `json:"currentLeafDigest"`
	CurrentLeafNotAfter int64                  `json:"currentLeafNotAfter"`
	ExpiresAt           int64                  `json:"expiresAt"`
	ConfigurationDigest string                 `json:"configurationDigest"`
	OtherPurposeKeyIDs  []string               `json:"otherPurposeKeyIds"`
	DeliveryOperators   []string               `json:"deliveryOperators"`
	InstallOperators    []string               `json:"installOperators"`
	UID                 int                    `json:"uid"`
	GID                 int                    `json:"gid"`
	Offer               *msi.SetupOffer        `json:"offer,omitempty"`
	Registration        *msi.SetupRegistration `json:"registration,omitempty"`
	RegistrationDigest  string                 `json:"registrationDigest,omitempty"`
	Digest              string                 `json:"digest"`
}
type setupComplete struct {
	Version             string `json:"version"`
	PlanDigest          string `json:"planDigest"`
	RegistrationDigest  string `json:"registrationDigest"`
	ConfigurationDigest string `json:"configurationDigest"`
}
type setupPrepared struct {
	Version     string `json:"version"`
	PlanDigest  string `json:"planDigest"`
	OfferDigest string `json:"offerDigest"`
}
type setupMaterial struct {
	plan       SetupPlan
	lan        lanconfig.Material
	enrollment enrollmentconfig.Material
	config     enrollmentstate.Config
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
	if e != nil || m.Config.Profile != lanconfig.TLS || !m.Config.WindowsInventoryEnabled || m.Config.WindowsManagedMSIConfigFile != "" {
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
	for _, op := range m.Operators {
		for _, cap := range op.Capabilities {
			if cap == operatorauth.WindowsManagedMSIDeliver {
				p.DeliveryOperators = append(p.DeliveryOperators, op.ID)
			}
			if cap == operatorauth.WindowsManagedMSIInstall {
				p.InstallOperators = append(p.InstallOperators, op.ID)
			}
		}
	}
	sort.Strings(p.DeliveryOperators)
	sort.Strings(p.InstallOperators)
	if len(p.DeliveryOperators) == 0 || len(p.InstallOperators) == 0 {
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
		offerRaw, e := canonicalRead(SetupOfferPath(p.StateDirectory), &offer)
		if e != nil || offer.Validate() != nil {
			return out, ErrSetup
		}
		if _, e = canonicalRead(setupPath(p.StateDirectory, "prepared.json"), &prepared); e != nil || prepared.Version != SetupPlanVersion || !msi.ValidDigest(prepared.PlanDigest) || prepared.OfferDigest != msi.Digest(offerRaw) {
			return out, ErrSetup
		}
		pub, e := publicFromPrivate(setupPath(p.StateDirectory, "manager.key"))
		if e != nil || !bytes.Equal(pub, offer.ManagerPublicKey) {
			return out, ErrSetup
		}
		registrationRaw, e := lanconfig.ReadProtected(q.RegistrationFile, true, 32769)
		if e != nil {
			return out, ErrSetup
		}
		registrationRaw = bytes.TrimSuffix(registrationRaw, []byte("\n"))
		reg, e := msi.DecodeSetupRegistration(registrationRaw)
		if e != nil || !sameJSON(reg.Offer, offer) {
			return out, ErrSetup
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
	out = setupMaterial{p, m, en, cfg}
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
	if e != nil || in.Status != "absent" || in.OtherMutatorPresent || in.Config != m.config {
		return SetupPlan{}, ErrSetup
	}
	p.IncarnationDigest = "sha256:" + in.Identity.Issuance.CertificateHash
	p.CurrentLeafDigest = in.CurrentLeafDigest
	p.CurrentLeafNotAfter = in.CurrentLeafNotAfter
	if p.ExpiresAt > in.CurrentLeafNotAfter {
		return SetupPlan{}, ErrSetup
	}
	if q.Phase == "prepare" {
		if q.RegistrationFile != "" || !absent(filepath.Join(p.StateDirectory, "windows-managed-msi-setup-started.json"), setupPath(p.StateDirectory, ""), SpoolPath(p.StateDirectory)) {
			return SetupPlan{}, ErrSetup
		}
	} else {
		if !absent(setupPath(p.StateDirectory, "finalize-started.json"), setupPath(p.StateDirectory, "registration.json"), setupPath(p.StateDirectory, "manager.json"), setupPath(p.StateDirectory, "complete.json"), SetupLANPath(p.StateDirectory), SpoolPath(p.StateDirectory)) || p.Offer.ManagerID != p.ManagerID || p.Offer.DeviceID != q.DeviceID || p.Offer.ManagerOrigin != p.ManagerOrigin || p.Offer.IncarnationDigest != p.IncarnationDigest {
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
		if e != nil || in.Status != "absent" || in.OtherMutatorPresent || in.CurrentLeafDigest != p.CurrentLeafDigest || in.CurrentLeafNotAfter != p.CurrentLeafNotAfter || "sha256:"+in.Identity.Issuance.CertificateHash != p.IncarnationDigest {
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
		if create(filepath.Join(p.StateDirectory, "windows-managed-msi-setup-started.json"), p) != nil || createSetupDirectory(setupPath(p.StateDirectory, "")) != nil {
			return nil, ErrSetup
		}
		pub, key, e := ed25519.GenerateKey(rand.Reader)
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
		if offer.Validate() != nil || createSetupFile(setupPath(p.StateDirectory, "manager.key"), key) != nil || live() != nil || create(SetupOfferPath(p.StateDirectory), offer) != nil {
			return nil, ErrSetup
		}
		raw, _ := json.Marshal(offer)
		if create(setupPath(p.StateDirectory, "prepared.json"), setupPrepared{SetupPlanVersion, p.Digest, msi.Digest(raw)}) != nil || live() != nil {
			return nil, ErrSetup
		}
		return &offer, nil
	}
	if p.Registration == nil || p.Offer == nil {
		return nil, ErrSetup
	}
	if create(setupPath(p.StateDirectory, "finalize-started.json"), p) != nil || create(setupPath(p.StateDirectory, "registration.json"), p.Registration) != nil || CreateSpool(p.StateDirectory) != nil || live() != nil {
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
		if _, e := canonicalRead(setupPath(p.StateDirectory, "finalize-started.json"), &saved); e != nil || !sameJSON(saved, p) {
			return ErrSetup
		}
		if _, e := canonicalRead(setupPath(p.StateDirectory, "registration.json"), &reg); e != nil || !sameJSON(reg, p.Registration) {
			return ErrSetup
		}
		return inputs()
	})
	if e = store.SetupWindowsManagedMSICreateOnly(guarded, p.Offer.ManagerPublicKey, p.Registration.ExecutorPublicKey, p.Registration.Grant, clock().UTC()); e != nil {
		return nil, e
	}
	c := Config{Version: ConfigVersion, Enabled: true, Binding: p.Registration.Grant.Binding, StateDirectory: p.StateDirectory, PrivateKeyFile: setupPath(p.StateDirectory, "manager.key"), SetupReceiptFile: setupPath(p.StateDirectory, "complete.json"), SetupPlanDigest: p.Digest, SetupRegistrationDigest: p.RegistrationDigest}
	lan := m.lan.Config
	lan.WindowsManagedMSIConfigFile = setupPath(p.StateDirectory, "manager.json")
	raw, _ := json.Marshal(c)
	if inputs() != nil || create(setupPath(p.StateDirectory, "manager.json"), c) != nil || create(SetupLANPath(p.StateDirectory), lan) != nil || create(c.SetupReceiptFile, setupComplete{SetupPlanVersion, p.Digest, p.RegistrationDigest, msi.Digest(raw)}) != nil || inputs() != nil {
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
		if depth != 0 || len(c.ConfigFiles) > 25 || c.Version != "tracebolt.windows-selected-update-manager-registry.v2" && c.Version != "tracebolt.windows-prepared-msi-manager-registry.v2" {
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
