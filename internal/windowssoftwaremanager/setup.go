package windowssoftwaremanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"localrmm/internal/actionmanager"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorauth"
	"localrmm/internal/packagecontroller"
	"localrmm/internal/windowsactionmanager"
	"localrmm/internal/windowssoftwarejob"
)

const SetupPlanVersion = "tracebolt.windows-prepared-msi-manager-setup.v1"
const AdditionalSetupPlanVersion = "tracebolt.windows-prepared-msi-manager-setup.v2"

var ErrSetup = errors.New("windows_software_setup_blocked_preserve_all_existing_state")

type SetupRequest struct {
	Phase            string `json:"phase"`
	LANConfig        string `json:"lanConfig"`
	EnrollmentConfig string `json:"enrollmentConfig"`
	DeviceID         string `json:"deviceId"`
	ExpiresAt        int64  `json:"expiresAt"`
	RegistrationFile string `json:"registrationFile,omitempty"`
	AdditionalDevice bool   `json:"additionalDevice,omitempty"`
}
type SetupOperator struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// SetupPlan is public review material. No key, password, verifier, or private
// input hash is emitted. It authorizes only the selected create-only phase.
type SetupPlan struct {
	Version                string                                `json:"version"`
	Request                SetupRequest                          `json:"request"`
	Scope                  string                                `json:"scope"`
	ManagerID              string                                `json:"managerId"`
	ManagerOrigin          string                                `json:"managerOrigin"`
	IncarnationDigest      string                                `json:"incarnationDigest"`
	CurrentLeafDigest      string                                `json:"currentLeafDigest"`
	CurrentLeafNotAfter    int64                                 `json:"currentLeafNotAfter"`
	ExpiresAt              int64                                 `json:"expiresAt"`
	StateDirectory         string                                `json:"stateDirectory"`
	UID                    int                                   `json:"uid"`
	GID                    int                                   `json:"gid"`
	Operators              []SetupOperator                       `json:"operators"`
	ConfigurationDigest    string                                `json:"configurationDigest"`
	OtherPurposeKeyIDs     []string                              `json:"otherPurposeKeyIds"`
	Offer                  *windowssoftwarejob.SetupOffer        `json:"offer,omitempty"`
	Registration           *windowssoftwarejob.SetupRegistration `json:"registration,omitempty"`
	RegistrationDigest     string                                `json:"registrationDigest,omitempty"`
	OriginalRegistryFile   string                                `json:"originalRegistryFile,omitempty"`
	OriginalRegistryDigest string                                `json:"originalRegistryDigest,omitempty"`
	OriginalConfigFiles    []string                              `json:"originalConfigFiles,omitempty"`
	OriginalConfigDigests  []string                              `json:"originalConfigDigests,omitempty"`
	ManagerKeyFile         string                                `json:"managerKeyFile,omitempty"`
	ManagerKeyID           string                                `json:"managerKeyId,omitempty"`
	RegisteredDevices      int                                   `json:"registeredDevices,omitempty"`
	Digest                 string                                `json:"digest"`
}

func (p SetupPlan) digest() string {
	p.Digest = ""
	raw, _ := json.Marshal(p)
	return actionpermit.Digest(raw)
}
func setupPath(state, name string) string {
	return filepath.Join(state, "windows-software-setup", name)
}
func setupIntent(state string) string {
	return filepath.Join(state, "windows-software-setup-started.json")
}
func SetupLANPath(state string) string   { return setupPath(state, "lan.json") }
func SetupOfferPath(state string) string { return setupPath(state, "offer.json") }

// Additional outputs never use the first device's directory or key pathname.
// Device IDs are validated before these helpers are used by any read or write.
func setupPlanPath(p SetupPlan, name string) string {
	if p.Request.AdditionalDevice {
		return filepath.Join(p.StateDirectory, "windows-software-setup-"+p.Request.DeviceID, name)
	}
	return setupPath(p.StateDirectory, name)
}
func setupPlanIntent(p SetupPlan) string {
	if p.Request.AdditionalDevice {
		return filepath.Join(p.StateDirectory, "windows-software-setup-"+p.Request.DeviceID+"-started.json")
	}
	return setupIntent(p.StateDirectory)
}
func setupPlanKey(p SetupPlan) string {
	if p.Request.AdditionalDevice {
		return p.ManagerKeyFile
	}
	return setupPath(p.StateDirectory, "manager.key")
}

// SetupPlanLANPath returns only the staged output; activation is a separate step.
func SetupPlanLANPath(p SetupPlan) string { return setupPlanPath(p, "lan.json") }

type setupMaterial struct {
	lan             lanconfig.Material
	enrollment      enrollmentconfig.Material
	config          enrollmentstate.Config
	plan            SetupPlan
	forbidden       []ed25519.PublicKey
	managerPublic   ed25519.PublicKey
	existingConfigs []Config
}
type setupComplete struct {
	Version             string `json:"version"`
	PlanDigest          string `json:"planDigest"`
	RegistrationDigest  string `json:"registrationDigest"`
	ConfigurationDigest string `json:"configurationDigest"`
}
type setupPrepared struct {
	Version     string    `json:"version"`
	Plan        SetupPlan `json:"plan"`
	OfferDigest string    `json:"offerDigest"`
}

func canonicalRead(path string, target any) ([]byte, error) {
	raw, e := lanconfig.ReadProtected(path, true, 32768)
	if e != nil {
		return nil, ErrSetup
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return nil, ErrSetup
	}
	expected, e := json.Marshal(target)
	if e != nil || !bytes.Equal(raw, expected) {
		return nil, ErrSetup
	}
	return raw, nil
}
func absent(paths ...string) bool {
	for _, path := range paths {
		if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			return false
		}
	}
	return true
}
func publicFromPrivate(path string) (ed25519.PublicKey, error) {
	key, e := lanconfig.ReadProtected(path, true, ed25519.PrivateKeySize)
	defer clear(key)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrSetup
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	pub := derived.Public().(ed25519.PublicKey)
	if !bytes.Equal(key, derived) || !keyvalidation.Ed25519(pub) {
		return nil, ErrSetup
	}
	return bytes.Clone(pub), nil
}
func distinct(pub []byte, forbidden []ed25519.PublicKey) bool {
	if !keyvalidation.Ed25519(pub) {
		return false
	}
	for _, other := range forbidden {
		if bytes.Equal(pub, other) {
			return false
		}
	}
	return true
}

func loadSetupInputs(ctx context.Context, request SetupRequest, now time.Time) (setupMaterial, error) {
	fail := func() (setupMaterial, error) { return setupMaterial{}, ErrSetup }
	if ctx == nil || ctx.Err() != nil || now.IsZero() || now.Unix() <= 0 || now.Unix() > enrollmentstate.MaxTimestamp || (request.Phase != "prepare" && request.Phase != "finalize") || (request.Phase == "prepare" && (request.RegistrationFile != "" || request.ExpiresAt <= now.Unix())) || (request.Phase == "finalize" && (request.RegistrationFile == "" || request.ExpiresAt != 0)) {
		return fail()
	}
	m, e := lanconfig.Load(request.LANConfig)
	if e != nil || m.Config.Profile != lanconfig.TLS || !m.Config.WindowsInventoryEnabled || (m.Config.WindowsSoftwareJobsConfigFile != "") != request.AdditionalDevice || len(m.Operators) == 0 {
		return fail()
	}
	en, e := enrollmentconfig.Load(request.EnrollmentConfig, m, now)
	if e != nil {
		return fail()
	}
	cfg, e := en.WindowsStoreConfig()
	if e != nil {
		return fail()
	}
	p := SetupPlan{Version: SetupPlanVersion, Request: request, Scope: windowssoftwarejob.Scope, ManagerID: cfg.Binding.InstanceID, ManagerOrigin: m.Config.AgentOrigin, ExpiresAt: request.ExpiresAt, StateDirectory: m.Config.StateDirectory, UID: os.Geteuid(), GID: os.Getegid(), Operators: []SetupOperator{}, OtherPurposeKeyIDs: []string{}}
	if request.AdditionalDevice {
		if !enrollmentcrypto.ValidID(request.DeviceID, "agent_") {
			return fail()
		}
		p.Version = AdditionalSetupPlanVersion
	}
	for _, op := range m.Operators {
		for _, cap := range op.Capabilities {
			if cap == operatorauth.WindowsSoftwareInstall {
				p.Operators = append(p.Operators, SetupOperator{op.ID, op.Username})
			}
		}
	}
	if len(p.Operators) == 0 {
		return fail()
	}
	sort.Slice(p.Operators, func(i, j int) bool { return p.Operators[i].ID < p.Operators[j].ID })
	// Digest only nonsecret configuration and public key identifiers. Operator
	// password/verifier bytes and all private key bytes are deliberately excluded.
	var configInputs [][]byte
	for _, path := range []string{request.LANConfig, request.EnrollmentConfig} {
		raw, e := lanconfig.ReadProtected(path, false, 16384)
		if e != nil {
			return fail()
		}
		configInputs = append(configInputs, raw)
	}
	raw, _ := json.Marshal(configInputs)
	p.ConfigurationDigest = actionpermit.Digest(raw)
	forbidden := []ed25519.PublicKey{}
	for _, der := range append([][]byte{en.Issuer().IssuerDER(), en.Issuer().RootDER()}, m.Server.Certificate...) {
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return fail()
		}
		if key, ok := cert.PublicKey.(ed25519.PublicKey); ok {
			forbidden = append(forbidden, key)
		}
	}
	// Configured service/package keys are compared, never reused or opened as
	// runtime domains. This check neither initializes nor repairs their state.
	for _, entry := range []struct {
		path, version string
		packageKey    bool
	}{{m.Config.ServiceActionsConfigFile, actionmanager.ConfigVersion, false}, {m.Config.WindowsServiceActionsConfigFile, windowsactionmanager.ConfigVersion, false}, {m.Config.PackageActionsConfigFile, packagecontroller.ConfigVersion, true}} {
		if entry.path == "" {
			continue
		}
		raw, e := lanconfig.ReadProtected(entry.path, true, 8192)
		if e != nil {
			return fail()
		}
		var path string
		if entry.packageKey {
			var c packagecontroller.Config
			if lanconfig.StrictObject(raw, &c, "version", "enabled", "managerId", "endpointId", "incarnationDigest", "rootPolicyDigest", "transportProfile", "httpTestAcknowledged", "stateFile", "privateKeyFile", "localScopeAcknowledged") != nil || c.Version != entry.version || !c.Enabled || c.ManagerID != p.ManagerID {
				return fail()
			}
			path = c.PrivateKeyFile
		} else {
			var c actionmanager.Config
			if lanconfig.StrictObject(raw, &c, "version", "enabled", "managerId", "transportProfile", "httpTestAcknowledged", "privateKeyFile") != nil || c.Version != entry.version || !c.Enabled || c.ManagerID != p.ManagerID {
				return fail()
			}
			path = c.PrivateKeyFile
		}
		pub, e := publicFromPrivate(path)
		if e != nil {
			return fail()
		}
		forbidden = append(forbidden, pub)
	}
	for _, key := range forbidden {
		p.OtherPurposeKeyIDs = append(p.OtherPurposeKeyIDs, actionpermit.Digest(key))
	}
	updatePins, e := configuredUpdateKeyIDs(m.Config.WindowsUpdateJobsConfigFile, p.ManagerID)
	if e != nil {
		return fail()
	}
	p.OtherPurposeKeyIDs = append(p.OtherPurposeKeyIDs, updatePins...)
	sort.Strings(p.OtherPurposeKeyIDs)
	loaded := setupMaterial{lan: m, enrollment: en, config: cfg, plan: p, forbidden: forbidden}
	if request.AdditionalDevice && loadAdditionalSetupInputs(&loaded) != nil {
		return fail()
	}
	return loaded, nil
}
func loadSetup(ctx context.Context, request SetupRequest, now time.Time) (setupMaterial, error) {
	fail := func() (setupMaterial, error) { return setupMaterial{}, ErrSetup }
	loaded, e := loadSetupInputs(ctx, request, now)
	if e != nil {
		return fail()
	}
	m, en, p, forbidden := loaded.lan, loaded.enrollment, loaded.plan, loaded.forbidden
	inspection, e := enrollmentstore.InspectWindowsSoftwareJobSetup(ctx, filepath.Join(m.Config.StateDirectory, enrollmentconfig.WindowsDatabaseFile), en.Issuer().IssuerDER(), request.DeviceID, now)
	if e != nil || !setupInspectionMatches(loaded, inspection, false) {
		return fail()
	}
	p.IncarnationDigest = "sha256:" + inspection.Identity.Issuance.CertificateHash
	p.CurrentLeafDigest = inspection.CurrentLeafDigest
	p.CurrentLeafNotAfter = inspection.CurrentLeafNotAfter
	if checkSetupParent(setupPlanIntent(p)) != nil {
		return fail()
	}
	if request.Phase == "prepare" {
		if !absent(setupPlanIntent(p), setupPlanPath(p, "")) {
			return fail()
		}
	} else {
		var started SetupPlan
		if _, e = canonicalRead(setupPlanIntent(p), &started); e != nil || started.Version != p.Version || started.Request.AdditionalDevice != request.AdditionalDevice || started.Request.Phase != "prepare" || started.Digest != started.digest() {
			return fail()
		}
		var receipt setupPrepared
		if _, e = canonicalRead(setupPlanPath(p, "prepared.json"), &receipt); e != nil || receipt.Version != p.Version || !sameJSON(receipt.Plan, started) {
			return fail()
		}
		offerRaw, e := lanconfig.ReadProtected(setupPlanPath(p, "offer.json"), true, 16384)
		if e != nil {
			return fail()
		}
		offer, e := windowssoftwarejob.DecodeSetupOffer(offerRaw)
		if e != nil || receipt.OfferDigest != actionpermit.Digest(offerRaw) || !offerMatchesPlan(offer, started) || !offerMatchesPlan(offer, p) || started.Request.LANConfig != request.LANConfig || started.Request.EnrollmentConfig != request.EnrollmentConfig || started.ConfigurationDigest != p.ConfigurationDigest || !sameJSON(started.Operators, p.Operators) || !sameJSON(started.OtherPurposeKeyIDs, p.OtherPurposeKeyIDs) || started.UID != p.UID || started.GID != p.GID || started.StateDirectory != p.StateDirectory || !sameAdditionalSetupInputs(started, p) {
			return fail()
		}
		key, e := publicFromPrivate(setupPlanKey(p))
		if e != nil || !bytes.Equal(key, offer.ManagerPublicKey) || !distinct(key, forbidden) || !distinctFromPlan(key, p) {
			return fail()
		}
		// A CLI-captured public JSON document may contain one final newline only.
		registrationRaw, e := lanconfig.ReadProtected(request.RegistrationFile, true, 16385)
		if e != nil {
			return fail()
		}
		registrationRaw = bytes.TrimSuffix(registrationRaw, []byte("\n"))
		registration, e := windowssoftwarejob.DecodeSetupRegistration(registrationRaw)
		if e != nil || !sameJSON(registration.Offer, offer) || !distinct(registration.ExecutorPublicKey, append(forbidden, key)) || !distinctFromPlan(registration.ExecutorPublicKey, p) || !additionalRegistrationUnique(registration, loaded.existingConfigs) {
			return fail()
		}
		if !absent(setupPlanPath(p, "finalize-started.json"), setupPlanPath(p, "registration.json"), setupPlanPath(p, "manager.json"), SetupPlanLANPath(p), setupPlanPath(p, "complete.json")) || request.AdditionalDevice && !absent(setupPlanPath(p, "registry.json")) {
			return fail()
		}
		p.Offer = &offer
		p.Registration = &registration
		p.ExpiresAt = offer.ExpiresAt
		p.RegistrationDigest = actionpermit.Digest(registrationRaw)
	}
	issuer, e := x509.ParseCertificate(en.Issuer().IssuerDER())
	if e != nil || p.ExpiresAt <= now.Unix() || p.ExpiresAt > issuer.NotAfter.Unix() {
		return fail()
	}
	p.Digest = p.digest()
	if request.AdditionalDevice {
		raw, err := json.Marshal(p)
		prepared, preparedErr := json.Marshal(setupPrepared{p.Version, p, actionpermit.Digest(nil)})
		if err != nil || preparedErr != nil || len(raw) > 32768 || len(prepared) > 32768 {
			return fail()
		}
	}
	loaded.plan = p
	return loaded, nil
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func offerMatchesPlan(o windowssoftwarejob.SetupOffer, p SetupPlan) bool {
	return o.ManagerID == p.ManagerID && o.DeviceID == p.Request.DeviceID && o.IncarnationDigest == p.IncarnationDigest && o.ManagerOrigin == p.ManagerOrigin && (p.Request.Phase == "finalize" || o.ExpiresAt == p.ExpiresAt)
}
func PlanSetup(ctx context.Context, request SetupRequest, now time.Time) (SetupPlan, error) {
	m, e := loadSetup(ctx, request, now)
	return m.plan, e
}

type setupEffects interface {
	Create(string, []byte) error
	Mkdir(string) error
	Generate() (ed25519.PublicKey, ed25519.PrivateKey, error)
	Initialize(context.Context, setupMaterial, windowssoftwarejob.SetupRegistration, func() time.Time) error
	Recheck(context.Context, SetupPlan, time.Time) error
	RecheckRegistered(context.Context, SetupPlan, time.Time) error
}
type localSetupEffects struct{}

func (localSetupEffects) Create(path string, b []byte) error { return createSetupFile(path, b) }
func (localSetupEffects) Mkdir(path string) error            { return createSetupDirectory(path) }
func (localSetupEffects) Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
func (localSetupEffects) Initialize(ctx context.Context, m setupMaterial, r windowssoftwarejob.SetupRegistration, clock func() time.Time) error {
	s, e := enrollmentstore.Open(filepath.Join(m.plan.StateDirectory, enrollmentconfig.WindowsDatabaseFile), m.config, m.enrollment.Issuer().IssuerDER())
	if e != nil {
		return ErrSetup
	}
	defer s.Close()
	// Resample after Open/SQLite waits and at the store's final commit boundary.
	guarded := windowssoftwarejob.WithFinalCheck(enrollmentstore.WithWindowsSoftwareSetupExpectedLeaf(enrollmentstore.WithOverviewClock(ctx, clock), m.plan.CurrentLeafDigest, m.plan.CurrentLeafNotAfter), func() error {
		now := clock().UTC()
		if recheckSetupInputs(ctx, m.plan, now) != nil || now.Unix() >= m.plan.CurrentLeafNotAfter {
			return ErrSetup
		}
		var started SetupPlan
		if _, e := canonicalRead(setupPlanPath(m.plan, "finalize-started.json"), &started); e != nil || !sameJSON(started, m.plan) {
			return ErrSetup
		}
		var saved windowssoftwarejob.SetupRegistration
		if _, e := canonicalRead(setupPlanPath(m.plan, "registration.json"), &saved); e != nil || !sameJSON(saved, r) {
			return ErrSetup
		}
		return nil
	})
	if m.plan.Request.AdditionalDevice {
		return s.RegisterWindowsSoftwareDeviceCreateOnly(guarded, r.Offer.ManagerPublicKey, r.ExecutorPublicKey, r.Consent, clock().UTC())
	}
	return s.SetupWindowsSoftwareJobsCreateOnly(guarded, r.Offer.ManagerPublicKey, r.ExecutorPublicKey, r.Consent, clock().UTC())
}

// sameSetupInputs compares every reviewed nonsecret configuration/operator/key
// field without treating a read-only authority snapshot as present authority.
func sameSetupInputs(a, b SetupPlan) bool {
	clearSnapshot := func(p *SetupPlan) {
		p.IncarnationDigest = ""
		p.CurrentLeafDigest = ""
		p.CurrentLeafNotAfter = 0
		p.ExpiresAt = p.Request.ExpiresAt
		p.Offer = nil
		p.Registration = nil
		p.RegistrationDigest = ""
		p.Digest = ""
	}
	clearSnapshot(&a)
	clearSnapshot(&b)
	return sameJSON(a, b)
}
func recheckSetupInputs(ctx context.Context, p SetupPlan, now time.Time) error {
	fresh, e := loadSetupInputs(ctx, p.Request, now)
	if e != nil || !sameSetupInputs(p, fresh.plan) || now.Unix() >= p.ExpiresAt {
		return ErrSetup
	}
	if p.Request.Phase == "finalize" {
		var offer windowssoftwarejob.SetupOffer
		if _, e = canonicalRead(setupPlanPath(p, "offer.json"), &offer); e != nil || !sameJSON(offer, p.Offer) {
			return ErrSetup
		}
		pub, e := publicFromPrivate(setupPlanKey(p))
		if e != nil || !bytes.Equal(pub, offer.ManagerPublicKey) {
			return ErrSetup
		}
		raw, e := lanconfig.ReadProtected(p.Request.RegistrationFile, true, 16385)
		if e != nil {
			return ErrSetup
		}
		raw = bytes.TrimSuffix(raw, []byte("\n"))
		r, e := windowssoftwarejob.DecodeSetupRegistration(raw)
		if e != nil || !sameJSON(r, p.Registration) || actionpermit.Digest(raw) != p.RegistrationDigest {
			return ErrSetup
		}
	}
	return nil
}
func (localSetupEffects) Recheck(ctx context.Context, p SetupPlan, now time.Time) error {
	return recheckSetupAuthority(ctx, p, now, false)
}
func (localSetupEffects) RecheckRegistered(ctx context.Context, p SetupPlan, now time.Time) error {
	return recheckSetupAuthority(ctx, p, now, true)
}
func recheckSetupAuthority(ctx context.Context, p SetupPlan, now time.Time, registered bool) error {
	if recheckSetupInputs(ctx, p, now) != nil {
		return ErrSetup
	}
	fresh, e := loadSetupInputs(ctx, p.Request, now)
	if e != nil || !sameSetupInputs(p, fresh.plan) {
		return ErrSetup
	}
	inspect, e := enrollmentstore.InspectWindowsSoftwareJobSetup(ctx, filepath.Join(p.StateDirectory, enrollmentconfig.WindowsDatabaseFile), fresh.enrollment.Issuer().IssuerDER(), p.Request.DeviceID, now)
	if e != nil || !setupInspectionMatches(setupMaterial{config: fresh.config, plan: p, existingConfigs: fresh.existingConfigs, managerPublic: fresh.managerPublic}, inspect, registered) || inspect.Identity.Binding.InstanceID != p.ManagerID || "sha256:"+inspect.Identity.Issuance.CertificateHash != p.IncarnationDigest || inspect.CurrentLeafDigest != p.CurrentLeafDigest || inspect.CurrentLeafNotAfter != p.CurrentLeafNotAfter {
		return ErrSetup
	}
	return nil
}

// ApplySetup is reachable only from explicit local apply. First-device setup
// generates its purpose-specific key only after exact review; additional-device
// setup reads that same existing key without generating or rewriting it.
func ApplySetup(ctx context.Context, p SetupPlan, approval string, clock func() time.Time) (*windowssoftwarejob.SetupOffer, error) {
	if ctx == nil || clock == nil || approval == "" || approval != p.Digest || p.Digest != p.digest() {
		return nil, ErrSetup
	}
	ctx = enrollmentstore.WithOverviewClock(ctx, clock)
	m, e := loadSetup(ctx, p.Request, clock().UTC())
	if e != nil || !sameJSON(m.plan, p) {
		return nil, ErrSetup
	}
	return applySetup(ctx, m, localSetupEffects{}, clock)
}
func applySetup(ctx context.Context, m setupMaterial, fx setupEffects, clock func() time.Time) (*windowssoftwarejob.SetupOffer, error) {
	p := m.plan
	if p.Request.AdditionalDevice {
		// Keep one monotonic sample across file writes, transaction waits and output
		// reads. Once rollback is observed, every later sample remains invalid.
		sourceClock := clock
		var observed time.Time
		regressed := false
		clock = func() time.Time {
			fresh := sourceClock().UTC()
			if !observed.IsZero() && fresh.Before(observed) {
				regressed = true
			}
			if regressed {
				return time.Time{}
			}
			observed = fresh
			return fresh
		}
		ctx = enrollmentstore.WithOverviewClock(ctx, clock)
	}
	create := func(path string, value any) error {
		raw, e := json.Marshal(value)
		if e != nil {
			return ErrSetup
		}
		return fx.Create(path, raw)
	}
	started := clock().UTC()
	live := func() error {
		now := clock().UTC()
		if ctx.Err() != nil || now.Before(started) || now.Unix() >= p.ExpiresAt || now.Unix() >= p.CurrentLeafNotAfter {
			return ErrSetup
		}
		if fx.Recheck(ctx, p, now) != nil {
			return ErrSetup
		}
		fresh := clock().UTC()
		if ctx.Err() != nil || fresh.Before(now) || fresh.Unix() >= p.ExpiresAt || fresh.Unix() >= p.CurrentLeafNotAfter {
			return ErrSetup
		}
		return nil
	}
	if live() != nil {
		return nil, ErrSetup
	}
	if p.Request.AdditionalDevice {
		return applyAdditionalSetup(ctx, m, fx, clock, live)
	}
	if p.Request.Phase == "prepare" {
		if create(setupIntent(p.StateDirectory), p) != nil || fx.Mkdir(setupPath(p.StateDirectory, "")) != nil {
			return nil, ErrSetup
		}
		pub, key, e := fx.Generate()
		defer clear(key)
		if e != nil || len(key) != ed25519.PrivateKeySize {
			return nil, ErrSetup
		}
		derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		defer clear(derived)
		if !bytes.Equal(key, derived) || !bytes.Equal(pub, derived.Public().(ed25519.PublicKey)) || !distinct(pub, m.forbidden) || !distinctFromPlan(pub, m.plan) {
			return nil, ErrSetup
		}
		offer := windowssoftwarejob.SetupOffer{Version: windowssoftwarejob.SetupOfferVersion, ManagerID: p.ManagerID, DeviceID: p.Request.DeviceID, IncarnationDigest: p.IncarnationDigest, ManagerOrigin: p.ManagerOrigin, ManagerPublicKey: bytes.Clone(pub), ExpiresAt: p.ExpiresAt}
		if offer.Validate() != nil || fx.Create(setupPath(p.StateDirectory, "manager.key"), key) != nil || live() != nil || create(SetupOfferPath(p.StateDirectory), offer) != nil {
			return nil, ErrSetup
		}
		raw, _ := json.Marshal(offer)
		if live() != nil || create(setupPath(p.StateDirectory, "prepared.json"), setupPrepared{SetupPlanVersion, p, actionpermit.Digest(raw)}) != nil || live() != nil {
			return nil, ErrSetup
		}
		return &offer, nil
	}
	if p.Registration == nil || p.Offer == nil || p.Registration.Validate() != nil || !sameJSON(p.Offer, p.Registration.Offer) {
		return nil, ErrSetup
	}
	if create(setupPath(p.StateDirectory, "finalize-started.json"), p) != nil || create(setupPath(p.StateDirectory, "registration.json"), p.Registration) != nil || live() != nil {
		return nil, ErrSetup
	}
	if fx.Initialize(ctx, m, *p.Registration, clock) != nil {
		return nil, ErrSetup
	}
	// The configured manager is untouched. These are new protected output files;
	// using the staged LAN config/startup remains a separately approved host step.
	config := Config{Version: ConfigVersion, Enabled: true, Binding: p.Registration.Consent.Binding, PrivateKeyFile: setupPath(p.StateDirectory, "manager.key"), SetupReceiptFile: setupPath(p.StateDirectory, "complete.json"), SetupPlanDigest: p.Digest, SetupRegistrationDigest: p.RegistrationDigest}
	lan := m.lan.Config
	lan.WindowsSoftwareJobsConfigFile = setupPath(p.StateDirectory, "manager.json")
	configRaw, _ := json.Marshal(config)
	if create(setupPath(p.StateDirectory, "manager.json"), config) != nil || create(SetupLANPath(p.StateDirectory), lan) != nil || create(config.SetupReceiptFile, setupComplete{SetupPlanVersion, p.Digest, p.RegistrationDigest, actionpermit.Digest(configRaw)}) != nil {
		return nil, ErrSetup
	}

	return nil, nil
}

// loadAdditionalSetupInputs admits only a complete explicitly activated prior
// setup. It never discovers files, opens writable state, repairs receipts, or
// replaces the existing purpose-specific key. These public references and exact
// input digests become part of both the review and the final commit fence.
func loadAdditionalSetupInputs(m *setupMaterial) error {
	p := &m.plan
	path := m.lan.Config.WindowsSoftwareJobsConfigFile
	files, raw, err := registryConfigFilesSnapshot(path, m.config.RecordLimit)
	if err != nil || len(files) == 0 || len(files) >= windowssoftwarejob.MaxDevices || len(files) >= m.config.RecordLimit {
		return ErrSetup
	}
	devices, executors, pins, grants := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	p.OriginalRegistryFile, p.OriginalRegistryDigest = path, actionpermit.Digest(raw)
	p.OriginalConfigFiles = append([]string(nil), files...)
	p.OriginalConfigDigests = make([]string, 0, len(files))
	p.RegisteredDevices = len(files)
	for _, file := range files {
		var c Config
		body, err := canonicalRead(file, &c)
		if err != nil || !validConfig(c) || !hasSetupReceipt(c) || checkSetupReceipt(c) != nil || c.Binding.ManagerID != p.ManagerID {
			return ErrSetup
		}
		b := c.Binding
		if devices[b.DeviceID] || executors[b.ExecutorID] || pins[b.ExecutorKeyID] || grants[b.GrantID] || b.DeviceID == p.Request.DeviceID {
			return ErrSetup
		}
		devices[b.DeviceID], executors[b.ExecutorID], pins[b.ExecutorKeyID], grants[b.GrantID] = true, true, true, true
		pub, err := publicFromPrivate(c.PrivateKeyFile)
		if err != nil || actionpermit.Digest(pub) != b.KeyID || !distinct(pub, m.forbidden) || !distinctFromPlan(pub, m.plan) {
			return ErrSetup
		}
		if m.managerPublic == nil {
			m.managerPublic = pub
			p.ManagerKeyFile, p.ManagerKeyID = c.PrivateKeyFile, b.KeyID
		} else if !bytes.Equal(pub, m.managerPublic) || c.PrivateKeyFile != p.ManagerKeyFile || b.KeyID != p.ManagerKeyID {
			return ErrSetup
		}
		p.OriginalConfigDigests = append(p.OriginalConfigDigests, actionpermit.Digest(body))
		m.existingConfigs = append(m.existingConfigs, c)
	}
	// The manifest may have blocked while its entries/receipts were read.
	again, err := lanconfig.ReadProtected(path, true, maxRegistryBytes)
	if err != nil || !bytes.Equal(raw, again) {
		return ErrSetup
	}
	return nil
}

func sameAdditionalSetupInputs(a, b SetupPlan) bool {
	type inputs struct {
		RegistryFile, RegistryDigest, KeyFile, KeyID string
		ConfigFiles, ConfigDigests                   []string
		RegisteredDevices                            int
	}
	take := func(p SetupPlan) inputs {
		return inputs{p.OriginalRegistryFile, p.OriginalRegistryDigest, p.ManagerKeyFile, p.ManagerKeyID, p.OriginalConfigFiles, p.OriginalConfigDigests, p.RegisteredDevices}
	}
	return sameJSON(take(a), take(b))
}

func additionalRegistrationUnique(r windowssoftwarejob.SetupRegistration, configs []Config) bool {
	b := r.Consent.Binding
	for _, c := range configs {
		old := c.Binding
		if old.DeviceID == b.DeviceID || old.ExecutorID == b.ExecutorID || old.ExecutorKeyID == b.ExecutorKeyID || old.GrantID == b.GrantID {
			return false
		}
	}
	return true
}

func setupInspectionMatches(m setupMaterial, in enrollmentstore.WindowsSoftwareSetupInspection, registered bool) bool {
	if in.Config != m.config {
		return false
	}
	if !m.plan.Request.AdditionalDevice {
		return !registered && in.Status == "absent"
	}
	count := len(m.existingConfigs)
	if registered {
		count++
	}
	if in.Status != "fenced" || in.DeviceRegistered != registered || in.RegisteredDevices != count || !bytes.Equal(in.PublicKey, m.managerPublic) || len(in.RegisteredBindings) != count {
		return false
	}
	expected := make(map[string]windowssoftwarejob.Binding, count)
	for _, c := range m.existingConfigs {
		expected[c.Binding.DeviceID] = c.Binding
	}
	if registered {
		if m.plan.Registration == nil {
			return false
		}
		expected[m.plan.Request.DeviceID] = m.plan.Registration.Consent.Binding
	}
	for _, b := range in.RegisteredBindings {
		if old, ok := expected[b.DeviceID]; !ok || old != b {
			return false
		}
		delete(expected, b.DeviceID)
	}
	return len(expected) == 0
}

func applyAdditionalSetup(ctx context.Context, m setupMaterial, fx setupEffects, clock func() time.Time, live func() error) (*windowssoftwarejob.SetupOffer, error) {
	p := m.plan
	create := func(name string, value any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return ErrSetup
		}
		return fx.Create(setupPlanPath(p, name), raw)
	}
	if p.Request.Phase == "prepare" {
		raw, err := json.Marshal(p)
		if err != nil || fx.Create(setupPlanIntent(p), raw) != nil || live() != nil || fx.Mkdir(setupPlanPath(p, "")) != nil || live() != nil {
			return nil, ErrSetup
		}
		// Existing key is only read/compared. No Generate or key Create is reachable.
		offer := windowssoftwarejob.SetupOffer{Version: windowssoftwarejob.SetupOfferVersion, ManagerID: p.ManagerID, DeviceID: p.Request.DeviceID, IncarnationDigest: p.IncarnationDigest, ManagerOrigin: p.ManagerOrigin, ManagerPublicKey: bytes.Clone(m.managerPublic), ExpiresAt: p.ExpiresAt}
		if offer.Validate() != nil || create("offer.json", offer) != nil || live() != nil {
			return nil, ErrSetup
		}
		raw, _ = json.Marshal(offer)
		if create("prepared.json", setupPrepared{p.Version, p, actionpermit.Digest(raw)}) != nil || live() != nil {
			return nil, ErrSetup
		}
		return &offer, nil
	}
	if p.Registration == nil || p.Offer == nil || p.Registration.Validate() != nil || !sameJSON(p.Offer, p.Registration.Offer) || !bytes.Equal(p.Offer.ManagerPublicKey, m.managerPublic) || !additionalRegistrationUnique(*p.Registration, m.existingConfigs) {
		return nil, ErrSetup
	}
	last := clock().UTC()
	if create("finalize-started.json", p) != nil || live() != nil || create("registration.json", p.Registration) != nil || live() != nil || fx.Initialize(ctx, m, *p.Registration, clock) != nil {
		return nil, ErrSetup
	}
	// Registration is now permanent, so output fences require that exact new
	// record alongside every original binding. A delayed write cannot refresh
	// expiry, change the current leaf, or turn a partial result into success.
	registeredLive := func() error {
		now := clock().UTC()
		if ctx.Err() != nil || now.Before(last) || now.Unix() >= p.ExpiresAt || now.Unix() >= p.CurrentLeafNotAfter || fx.RecheckRegistered(ctx, p, now) != nil {
			return ErrSetup
		}
		fresh := clock().UTC()
		if ctx.Err() != nil || fresh.Before(now) || fresh.Unix() >= p.ExpiresAt || fresh.Unix() >= p.CurrentLeafNotAfter {
			return ErrSetup
		}
		last = fresh
		return nil
	}
	config := Config{Version: ConfigVersion, Enabled: true, Binding: p.Registration.Consent.Binding, PrivateKeyFile: p.ManagerKeyFile, SetupReceiptFile: setupPlanPath(p, "complete.json"), SetupPlanDigest: p.Digest, SetupRegistrationDigest: p.RegistrationDigest}
	registry := RegistryConfig{Version: RegistryVersion, Enabled: true, ManagerID: p.ManagerID, ConfigFiles: append(append([]string(nil), p.OriginalConfigFiles...), setupPlanPath(p, "manager.json"))}
	if !validRegistry(registry, m.config.RecordLimit) {
		return nil, ErrSetup
	}
	lan := m.lan.Config
	lan.WindowsSoftwareJobsConfigFile = setupPlanPath(p, "registry.json")
	configRaw, _ := json.Marshal(config)
	for _, output := range []struct {
		name  string
		value any
	}{
		{"manager.json", config}, {"registry.json", registry}, {"lan.json", lan},
		// Config remains v1, so its existing completion-receipt contract is unchanged.
		{"complete.json", setupComplete{SetupPlanVersion, p.Digest, p.RegistrationDigest, actionpermit.Digest(configRaw)}},
	} {
		if registeredLive() != nil || create(output.name, output.value) != nil || registeredLive() != nil {
			return nil, ErrSetup
		}
	}
	return nil, nil
}
