package windowsupdatemanager

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
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorauth"
	"localrmm/internal/packagecontroller"
	"localrmm/internal/windowsactionmanager"
	"localrmm/internal/windowsupdatejob"
)

const SetupPlanVersion = "tracebolt.windows-selected-update-manager-setup.v1"

var ErrSetup = errors.New("windows_update_setup_blocked_preserve_all_existing_state")

type SetupRequest struct {
	Phase            string `json:"phase"`
	LANConfig        string `json:"lanConfig"`
	EnrollmentConfig string `json:"enrollmentConfig"`
	DeviceID         string `json:"deviceId"`
	ExpiresAt        int64  `json:"expiresAt"`
	RegistrationFile string `json:"registrationFile,omitempty"`
}
type SetupOperator struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// SetupPlan is public review material. No key, password, verifier, or private
// input hash is emitted. It authorizes only the selected create-only phase.
type SetupPlan struct {
	Version             string                              `json:"version"`
	Request             SetupRequest                        `json:"request"`
	Scope               string                              `json:"scope"`
	ManagerID           string                              `json:"managerId"`
	ManagerOrigin       string                              `json:"managerOrigin"`
	IncarnationDigest   string                              `json:"incarnationDigest"`
	CurrentLeafDigest   string                              `json:"currentLeafDigest"`
	CurrentLeafNotAfter int64                               `json:"currentLeafNotAfter"`
	ExpiresAt           int64                               `json:"expiresAt"`
	StateDirectory      string                              `json:"stateDirectory"`
	UID                 int                                 `json:"uid"`
	GID                 int                                 `json:"gid"`
	Operators           []SetupOperator                     `json:"operators"`
	ConfigurationDigest string                              `json:"configurationDigest"`
	OtherPurposeKeyIDs  []string                            `json:"otherPurposeKeyIds"`
	Offer               *windowsupdatejob.SetupOffer        `json:"offer,omitempty"`
	Registration        *windowsupdatejob.SetupRegistration `json:"registration,omitempty"`
	RegistrationDigest  string                              `json:"registrationDigest,omitempty"`
	Digest              string                              `json:"digest"`
}

func (p SetupPlan) digest() string {
	p.Digest = ""
	raw, _ := json.Marshal(p)
	return actionpermit.Digest(raw)
}
func setupPath(state, name string) string { return filepath.Join(state, "windows-update-setup", name) }
func setupIntent(state string) string {
	return filepath.Join(state, "windows-update-setup-started.json")
}
func SetupLANPath(state string) string   { return setupPath(state, "lan.json") }
func SetupOfferPath(state string) string { return setupPath(state, "offer.json") }

type setupMaterial struct {
	lan        lanconfig.Material
	enrollment enrollmentconfig.Material
	config     enrollmentstate.Config
	plan       SetupPlan
	forbidden  []ed25519.PublicKey
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
	if e != nil || m.Config.Profile != lanconfig.TLS || !m.Config.WindowsInventoryEnabled || m.Config.WindowsUpdateJobsConfigFile != "" || len(m.Operators) == 0 {
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
	p := SetupPlan{Version: SetupPlanVersion, Request: request, Scope: windowsupdatejob.Scope, ManagerID: cfg.Binding.InstanceID, ManagerOrigin: m.Config.AgentOrigin, ExpiresAt: request.ExpiresAt, StateDirectory: m.Config.StateDirectory, UID: os.Geteuid(), GID: os.Getegid(), Operators: []SetupOperator{}, OtherPurposeKeyIDs: []string{}}
	for _, op := range m.Operators {
		for _, cap := range op.Capabilities {
			if cap == operatorauth.WindowsUpdateInstall {
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
	sort.Strings(p.OtherPurposeKeyIDs)
	return setupMaterial{m, en, cfg, p, forbidden}, nil
}
func loadSetup(ctx context.Context, request SetupRequest, now time.Time) (setupMaterial, error) {
	fail := func() (setupMaterial, error) { return setupMaterial{}, ErrSetup }
	loaded, e := loadSetupInputs(ctx, request, now)
	if e != nil {
		return fail()
	}
	m, en, cfg, p, forbidden := loaded.lan, loaded.enrollment, loaded.config, loaded.plan, loaded.forbidden
	inspection, e := enrollmentstore.InspectWindowsUpdateJobSetup(ctx, filepath.Join(m.Config.StateDirectory, enrollmentconfig.WindowsDatabaseFile), en.Issuer().IssuerDER(), request.DeviceID, now)
	if e != nil || inspection.Status != "absent" || inspection.Config != cfg {
		return fail()
	}
	p.IncarnationDigest = "sha256:" + inspection.Identity.Issuance.CertificateHash
	p.CurrentLeafDigest = inspection.CurrentLeafDigest
	p.CurrentLeafNotAfter = inspection.CurrentLeafNotAfter
	if checkSetupParent(setupIntent(p.StateDirectory)) != nil {
		return fail()
	}
	if request.Phase == "prepare" {
		if !absent(setupIntent(p.StateDirectory), setupPath(p.StateDirectory, "")) {
			return fail()
		}
	} else {
		var started SetupPlan
		if _, e = canonicalRead(setupIntent(p.StateDirectory), &started); e != nil || started.Version != SetupPlanVersion || started.Request.Phase != "prepare" || started.Digest != started.digest() {
			return fail()
		}
		var receipt setupPrepared
		if _, e = canonicalRead(setupPath(p.StateDirectory, "prepared.json"), &receipt); e != nil || receipt.Version != SetupPlanVersion || !sameJSON(receipt.Plan, started) {
			return fail()
		}
		offerRaw, e := lanconfig.ReadProtected(SetupOfferPath(p.StateDirectory), true, 16384)
		if e != nil {
			return fail()
		}
		offer, e := windowsupdatejob.DecodeSetupOffer(offerRaw)
		if e != nil || receipt.OfferDigest != actionpermit.Digest(offerRaw) || !offerMatchesPlan(offer, started) || !offerMatchesPlan(offer, p) || started.Request.LANConfig != request.LANConfig || started.Request.EnrollmentConfig != request.EnrollmentConfig || started.ConfigurationDigest != p.ConfigurationDigest || !sameJSON(started.Operators, p.Operators) || !sameJSON(started.OtherPurposeKeyIDs, p.OtherPurposeKeyIDs) || started.UID != p.UID || started.GID != p.GID || started.StateDirectory != p.StateDirectory {
			return fail()
		}
		key, e := publicFromPrivate(setupPath(p.StateDirectory, "manager.key"))
		if e != nil || !bytes.Equal(key, offer.ManagerPublicKey) || !distinct(key, forbidden) {
			return fail()
		}
		// A CLI-captured public JSON document may contain one final newline only.
		registrationRaw, e := lanconfig.ReadProtected(request.RegistrationFile, true, 16385)
		if e != nil {
			return fail()
		}
		registrationRaw = bytes.TrimSuffix(registrationRaw, []byte("\n"))
		registration, e := windowsupdatejob.DecodeSetupRegistration(registrationRaw)
		if e != nil || !sameJSON(registration.Offer, offer) || !distinct(registration.ExecutorPublicKey, append(forbidden, key)) {
			return fail()
		}
		if !absent(setupPath(p.StateDirectory, "finalize-started.json"), setupPath(p.StateDirectory, "registration.json"), setupPath(p.StateDirectory, "manager.json"), SetupLANPath(p.StateDirectory), setupPath(p.StateDirectory, "complete.json")) {
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
	return setupMaterial{m, en, cfg, p, forbidden}, nil
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func offerMatchesPlan(o windowsupdatejob.SetupOffer, p SetupPlan) bool {
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
	Initialize(context.Context, setupMaterial, windowsupdatejob.SetupRegistration, func() time.Time) error
	Recheck(context.Context, SetupPlan, time.Time) error
}
type localSetupEffects struct{}

func (localSetupEffects) Create(path string, b []byte) error { return createSetupFile(path, b) }
func (localSetupEffects) Mkdir(path string) error            { return createSetupDirectory(path) }
func (localSetupEffects) Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
func (localSetupEffects) Initialize(ctx context.Context, m setupMaterial, r windowsupdatejob.SetupRegistration, clock func() time.Time) error {
	s, e := enrollmentstore.Open(filepath.Join(m.plan.StateDirectory, enrollmentconfig.WindowsDatabaseFile), m.config, m.enrollment.Issuer().IssuerDER())
	if e != nil {
		return ErrSetup
	}
	defer s.Close()
	// Resample after Open/SQLite waits and at the store's final commit boundary.
	guarded := windowsupdatejob.WithFinalCheck(enrollmentstore.WithWindowsUpdateSetupExpectedLeaf(enrollmentstore.WithOverviewClock(ctx, clock), m.plan.CurrentLeafDigest, m.plan.CurrentLeafNotAfter), func() error {
		now := clock().UTC()
		if recheckSetupInputs(ctx, m.plan, now) != nil || now.Unix() >= m.plan.CurrentLeafNotAfter {
			return ErrSetup
		}
		var started SetupPlan
		if _, e := canonicalRead(setupPath(m.plan.StateDirectory, "finalize-started.json"), &started); e != nil || !sameJSON(started, m.plan) {
			return ErrSetup
		}
		var saved windowsupdatejob.SetupRegistration
		if _, e := canonicalRead(setupPath(m.plan.StateDirectory, "registration.json"), &saved); e != nil || !sameJSON(saved, r) {
			return ErrSetup
		}
		return nil
	})
	return s.SetupWindowsUpdateJobsCreateOnly(guarded, r.Offer.ManagerPublicKey, r.ExecutorPublicKey, r.Consent, clock().UTC())
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
		var offer windowsupdatejob.SetupOffer
		if _, e = canonicalRead(SetupOfferPath(p.StateDirectory), &offer); e != nil || !sameJSON(offer, p.Offer) {
			return ErrSetup
		}
		pub, e := publicFromPrivate(setupPath(p.StateDirectory, "manager.key"))
		if e != nil || !bytes.Equal(pub, offer.ManagerPublicKey) {
			return ErrSetup
		}
		raw, e := lanconfig.ReadProtected(p.Request.RegistrationFile, true, 16385)
		if e != nil {
			return ErrSetup
		}
		raw = bytes.TrimSuffix(raw, []byte("\n"))
		r, e := windowsupdatejob.DecodeSetupRegistration(raw)
		if e != nil || !sameJSON(r, p.Registration) || actionpermit.Digest(raw) != p.RegistrationDigest {
			return ErrSetup
		}
	}
	return nil
}
func (localSetupEffects) Recheck(ctx context.Context, p SetupPlan, now time.Time) error {
	if recheckSetupInputs(ctx, p, now) != nil {
		return ErrSetup
	}
	fresh, e := loadSetupInputs(ctx, p.Request, now)
	if e != nil {
		return ErrSetup
	}
	inspect, e := enrollmentstore.InspectWindowsUpdateJobSetup(ctx, filepath.Join(p.StateDirectory, enrollmentconfig.WindowsDatabaseFile), fresh.enrollment.Issuer().IssuerDER(), p.Request.DeviceID, now)
	if e != nil || inspect.Config != fresh.config || inspect.Status != "absent" || inspect.Identity.Binding.InstanceID != p.ManagerID || "sha256:"+inspect.Identity.Issuance.CertificateHash != p.IncarnationDigest || inspect.CurrentLeafDigest != p.CurrentLeafDigest || inspect.CurrentLeafNotAfter != p.CurrentLeafNotAfter {
		return ErrSetup
	}
	return nil
}

// ApplySetup is reachable only from explicit local apply. It generates the one
// purpose-specific manager key only after a fresh exact plan digest approval.
func ApplySetup(ctx context.Context, p SetupPlan, approval string, clock func() time.Time) (*windowsupdatejob.SetupOffer, error) {
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
func applySetup(ctx context.Context, m setupMaterial, fx setupEffects, clock func() time.Time) (*windowsupdatejob.SetupOffer, error) {
	p := m.plan
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
		if !bytes.Equal(key, derived) || !bytes.Equal(pub, derived.Public().(ed25519.PublicKey)) || !distinct(pub, m.forbidden) {
			return nil, ErrSetup
		}
		offer := windowsupdatejob.SetupOffer{Version: windowsupdatejob.SetupOfferVersion, ManagerID: p.ManagerID, DeviceID: p.Request.DeviceID, IncarnationDigest: p.IncarnationDigest, ManagerOrigin: p.ManagerOrigin, ManagerPublicKey: bytes.Clone(pub), ExpiresAt: p.ExpiresAt}
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
	lan.WindowsUpdateJobsConfigFile = setupPath(p.StateDirectory, "manager.json")
	configRaw, _ := json.Marshal(config)
	if create(setupPath(p.StateDirectory, "manager.json"), config) != nil || create(SetupLANPath(p.StateDirectory), lan) != nil || create(config.SetupReceiptFile, setupComplete{SetupPlanVersion, p.Digest, p.RegistrationDigest, actionpermit.Digest(configRaw)}) != nil {
		return nil, ErrSetup
	}

	return nil, nil
}
