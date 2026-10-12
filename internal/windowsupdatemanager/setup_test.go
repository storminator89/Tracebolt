package windowsupdatemanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/windowsupdatejob"
)

type setupFixtureEffects struct {
	files           map[string][]byte
	events          []string
	fail            string
	key             ed25519.PrivateKey
	generated       int
	initialized     int
	checks          int
	recheck         func()
	afterCreate     func(string)
	afterInitialize func()
}

func (f *setupFixtureEffects) Create(path string, raw []byte) error {
	f.events = append(f.events, "create:"+path)
	if strings.HasSuffix(path, f.fail) && f.fail != "" {
		return ErrSetup
	}
	if _, exists := f.files[path]; exists {
		return ErrSetup
	}
	f.files[path] = bytes.Clone(raw)
	if f.afterCreate != nil {
		f.afterCreate(path)
	}
	return nil
}
func (f *setupFixtureEffects) Mkdir(path string) error {
	f.events = append(f.events, "mkdir:"+path)
	if f.fail == "mkdir" {
		return ErrSetup
	}
	return nil
}
func (f *setupFixtureEffects) Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	f.generated++
	f.events = append(f.events, "generate")
	return f.key.Public().(ed25519.PublicKey), bytes.Clone(f.key), nil
}
func (f *setupFixtureEffects) Initialize(_ context.Context, _ setupMaterial, _ windowsupdatejob.SetupRegistration, _ func() time.Time) error {
	f.initialized++
	f.events = append(f.events, "initialize")
	if f.afterInitialize != nil {
		f.afterInitialize()
	}
	if f.fail == "initialize" {
		return ErrSetup
	}
	return nil
}
func (f *setupFixtureEffects) Recheck(context.Context, SetupPlan, time.Time) error {
	f.checks++
	if f.recheck != nil {
		f.recheck()
	}
	if f.fail == "recheck" {
		return ErrSetup
	}
	return nil
}
func (f *setupFixtureEffects) RecheckRegistered(ctx context.Context, p SetupPlan, now time.Time) error {
	return f.Recheck(ctx, p, now)
}
func setupFixture(t *testing.T) (setupMaterial, *setupFixtureEffects, time.Time) {
	t.Helper()
	now := time.Unix(1800000000, 0).UTC()
	m := setupMaterial{plan: SetupPlan{Version: SetupPlanVersion, Request: SetupRequest{Phase: "prepare", DeviceID: "agent_" + strings.Repeat("2", 32), ExpiresAt: now.Unix() + 3600}, Scope: windowsupdatejob.Scope, ManagerID: "manager_" + strings.Repeat("1", 32), ManagerOrigin: "https://manager.example", IncarnationDigest: "sha256:" + strings.Repeat("3", 64), CurrentLeafDigest: "sha256:" + strings.Repeat("4", 64), CurrentLeafNotAfter: now.Unix() + 7200, ExpiresAt: now.Unix() + 3600, StateDirectory: "/protected/state", Operators: []SetupOperator{{"operator-fixture", "Fixture"}}}}
	m.plan.Digest = m.plan.digest()
	fx := &setupFixtureEffects{files: map[string][]byte{}, key: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32))}
	return m, fx, now
}
func finalSetupFixture(t *testing.T) (setupMaterial, *setupFixtureEffects, time.Time) {
	m, fx, now := setupFixture(t)
	offer, e := applySetup(context.Background(), m, fx, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{82}, 32)).Public().(ed25519.PublicKey)
	binding := windowsupdatejob.Binding{ManagerID: offer.ManagerID, DeviceID: offer.DeviceID, IncarnationDigest: offer.IncarnationDigest, ExecutorID: "executor_" + strings.Repeat("5", 32), ExecutorKeyID: actionpermit.Digest(executor), GrantID: "grant_" + strings.Repeat("6", 32), KeyID: actionpermit.Digest(offer.ManagerPublicKey)}
	reg := windowsupdatejob.SetupRegistration{Version: windowsupdatejob.SetupRegistrationVersion, Offer: *offer, Consent: windowsupdatejob.Consent{Version: windowsupdatejob.ConsentVersion, Scope: windowsupdatejob.Scope, Binding: binding, Enabled: true, Acknowledged: true, ExpiresAt: offer.ExpiresAt}, ExecutorPublicKey: executor}
	if reg.Validate() != nil {
		t.Fatal("fixture registration")
	}
	m.plan.Request.Phase = "finalize"
	m.plan.Request.ExpiresAt = 0
	m.plan.Request.RegistrationFile = "/protected/registration.json"
	m.plan.Offer = offer
	m.plan.Registration = &reg
	raw, _ := json.Marshal(reg)
	m.plan.RegistrationDigest = actionpermit.Digest(raw)
	m.plan.Digest = m.plan.digest()
	fx.events = nil
	return m, fx, now
}
func TestUpdateSetupPreparationIsPurposeSeparateAndPublicOnly(t *testing.T) {
	m, fx, now := setupFixture(t)
	offer, e := applySetup(context.Background(), m, fx, func() time.Time { return now })
	if e != nil || offer == nil || offer.Validate() != nil || fx.generated != 1 || fx.initialized != 0 {
		t.Fatal("preparation", e)
	}
	if len(fx.events) < 3 || !strings.HasPrefix(fx.events[0], "create:"+setupIntent(m.plan.StateDirectory)) || fx.events[2] != "generate" {
		t.Fatal("generation before durable started fence", fx.events)
	}
	raw, _ := json.Marshal(offer)
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(fx.key))) || offer.ExpiresAt != m.plan.ExpiresAt {
		t.Fatal("private material or refreshed expiry")
	}
	if _, e = applySetup(context.Background(), m, fx, func() time.Time { return now }); e == nil || fx.generated != 1 {
		t.Fatal("existing setup adopted")
	}
}
func TestUpdateSetupPartialPreparationRetainsEvidenceAndNeverInitializes(t *testing.T) {
	for _, fail := range []string{"mkdir", "manager.key", "offer.json", "prepared.json"} {
		t.Run(fail, func(t *testing.T) {
			m, fx, now := setupFixture(t)
			fx.fail = fail
			if offer, e := applySetup(context.Background(), m, fx, func() time.Time { return now }); e == nil || offer != nil || fx.initialized != 0 {
				t.Fatal("partial setup escaped", e)
			}
			if len(fx.files[setupIntent(m.plan.StateDirectory)]) == 0 {
				t.Fatal("lost started evidence")
			}
		})
	}
	m, fx, now := setupFixture(t)
	m.forbidden = []ed25519.PublicKey{fx.key.Public().(ed25519.PublicKey)}
	if _, e := applySetup(context.Background(), m, fx, func() time.Time { return now }); e == nil || len(fx.files[setupPath(m.plan.StateDirectory, "manager.key")]) != 0 {
		t.Fatal("borrowed key accepted")
	}
}
func TestUpdateSetupFinalizeOrderAndRetainedUncertainty(t *testing.T) {
	m, fx, now := finalSetupFixture(t)
	if offer, e := applySetup(context.Background(), m, fx, func() time.Time { return now }); e != nil || offer != nil || fx.initialized != 1 || fx.generated != 1 {
		t.Fatal("finalize", e)
	}
	if len(fx.events) != 6 || !strings.HasSuffix(fx.events[0], "finalize-started.json") || !strings.HasSuffix(fx.events[1], "registration.json") || fx.events[2] != "initialize" || !strings.HasSuffix(fx.events[5], "complete.json") {
		t.Fatal("wrong transaction sequence", fx.events)
	}
	var config Config
	if json.Unmarshal(fx.files[setupPath(m.plan.StateDirectory, "manager.json")], &config) != nil || config.Binding != m.plan.Registration.Consent.Binding {
		t.Fatal("wrong exact config")
	}
	for _, fail := range []string{"initialize", "manager.json", "lan.json", "complete.json"} {
		t.Run(fail, func(t *testing.T) {
			m, fx, now := finalSetupFixture(t)
			fx.fail = fail
			if _, e := applySetup(context.Background(), m, fx, func() time.Time { return now }); e == nil {
				t.Fatal("partial finalize succeeded")
			}
			if len(fx.files[setupPath(m.plan.StateDirectory, "finalize-started.json")]) == 0 || len(fx.files[setupPath(m.plan.StateDirectory, "complete.json")]) != 0 {
				t.Fatal("failure evidence erased or success manufactured")
			}
			n := fx.initialized
			fx.fail = ""
			if _, e := applySetup(context.Background(), m, fx, func() time.Time { return now }); e == nil || fx.initialized != n {
				t.Fatal("uncertainty retried")
			}
		})
	}
}
func TestUpdateSetupExpiryAfterBlockingReadRetainsFence(t *testing.T) {
	m, fx, now := setupFixture(t)
	at := now
	fx.recheck = func() { at = time.Unix(m.plan.ExpiresAt, 0).UTC() }
	if _, e := applySetup(context.Background(), m, fx, func() time.Time { return at }); e == nil || fx.generated != 0 {
		t.Fatal("expiry across blocking read accepted")
	}
}
func TestUpdateSetupReviewDigestBindsIdentityScopePathsOperatorsAndPins(t *testing.T) {
	m, _, _ := finalSetupFixture(t)
	p := m.plan
	for _, change := range []func(*SetupPlan){func(p *SetupPlan) { p.Request.DeviceID = "other" }, func(p *SetupPlan) { p.ExpiresAt++ }, func(p *SetupPlan) { p.CurrentLeafDigest = "other" }, func(p *SetupPlan) { p.CurrentLeafNotAfter++ }, func(p *SetupPlan) { p.Scope = "observation" }, func(p *SetupPlan) { p.StateDirectory = "/elsewhere" }, func(p *SetupPlan) { p.Operators = []SetupOperator{{"different", "name"}} }, func(p *SetupPlan) { p.RegistrationDigest = "different" }} {
		other := p
		change(&other)
		if p.digest() == other.digest() {
			t.Fatal("review digest omitted input")
		}
	}
	if _, e := ApplySetup(context.Background(), p, "", time.Now); !errors.Is(e, ErrSetup) {
		t.Fatal("missing approval accepted")
	}
	if _, e := ApplySetup(context.Background(), p, p.Digest, nil); !errors.Is(e, ErrSetup) {
		t.Fatal("missing live clock accepted")
	}
}

func TestGeneratedSetupConfigRequiresExactCompletionAfterFinalWrite(t *testing.T) {
	m, fx, now := finalSetupFixture(t)
	fx.fail = "complete.json"
	if _, e := applySetup(context.Background(), m, fx, func() time.Time { return now }); e == nil {
		t.Fatal("partial finalize succeeded")
	}
	var c Config
	if json.Unmarshal(fx.files[setupPath(m.plan.StateDirectory, "manager.json")], &c) != nil || !validConfig(c) || !hasSetupReceipt(c) {
		t.Fatal("generated config omitted completion binding")
	}
	// Public-only inert receipt fixture: no key generation or host setup occurs.
	c.SetupReceiptFile = filepath.Join(t.TempDir(), "complete.json")
	if checkSetupReceipt(c) == nil {
		t.Fatal("missing final receipt admitted")
	}
	if e := os.WriteFile(c.SetupReceiptFile, []byte(`{"version":`), 0600); e != nil {
		t.Fatal(e)
	}
	if checkSetupReceipt(c) == nil {
		t.Fatal("partial receipt admitted")
	}
	raw, _ := json.Marshal(c)
	receipt := setupComplete{SetupPlanVersion, c.SetupPlanDigest, c.SetupRegistrationDigest, actionpermit.Digest(raw)}
	saved, _ := json.Marshal(receipt)
	if e := os.WriteFile(c.SetupReceiptFile, saved, 0600); e != nil {
		t.Fatal(e)
	}
	if checkSetupReceipt(c) != nil {
		t.Fatal("exact complete receipt rejected")
	}
	other := c
	other.PrivateKeyFile = "/protected/different.key"
	if checkSetupReceipt(other) == nil {
		t.Fatal("receipt admitted different configuration")
	}
	receipt.PlanDigest = "sha256:" + strings.Repeat("f", 64)
	saved, _ = json.Marshal(receipt)
	if e := os.WriteFile(c.SetupReceiptFile, saved, 0600); e != nil {
		t.Fatal(e)
	}
	if checkSetupReceipt(c) == nil {
		t.Fatal("replaced mismatched receipt admitted")
	}
	other = c
	other.SetupReceiptFile = ""
	if validConfig(other) {
		t.Fatal("partial completion fields accepted")
	}
}

func additionalSetupFixture(t *testing.T) (setupMaterial, *setupFixtureEffects, time.Time) {
	t.Helper()
	first, fx, now := finalSetupFixture(t)
	if _, err := applySetup(context.Background(), first, fx, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	var old Config
	oldPath := setupPath(first.plan.StateDirectory, "manager.json")
	if json.Unmarshal(fx.files[oldPath], &old) != nil {
		t.Fatal("first config")
	}
	m, _, _ := setupFixture(t)
	m.config.RecordLimit = windowsupdatejob.MaxDevices
	m.plan.Version = AdditionalSetupPlanVersion
	m.plan.Request.AdditionalDevice = true
	m.plan.Request.DeviceID = "agent_" + strings.Repeat("8", 32)
	m.plan.IncarnationDigest = actionpermit.Digest([]byte("second-original-anchor"))
	m.plan.CurrentLeafDigest = actionpermit.Digest([]byte("second-current-leaf"))
	m.plan.OriginalRegistryFile = oldPath
	m.plan.OriginalRegistryDigest = actionpermit.Digest(fx.files[oldPath])
	m.plan.OriginalConfigFiles = []string{oldPath}
	m.plan.OriginalConfigDigests = []string{m.plan.OriginalRegistryDigest}
	m.plan.ManagerKeyFile, m.plan.ManagerKeyID = old.PrivateKeyFile, old.Binding.KeyID
	m.plan.RegisteredDevices = 1
	m.managerPublic = bytes.Clone(first.plan.Offer.ManagerPublicKey)
	m.existingConfigs = []Config{old}
	m.plan.Digest = m.plan.digest()
	fx.events, fx.generated, fx.initialized, fx.checks = nil, 0, 0, 0
	return m, fx, now
}

func finalAdditionalSetupFixture(t *testing.T) (setupMaterial, *setupFixtureEffects, time.Time) {
	t.Helper()
	m, fx, now := additionalSetupFixture(t)
	offer, err := applySetup(context.Background(), m, fx, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{83}, 32)).Public().(ed25519.PublicKey)
	binding := windowsupdatejob.Binding{ManagerID: offer.ManagerID, DeviceID: offer.DeviceID, IncarnationDigest: offer.IncarnationDigest, ExecutorID: "executor_" + strings.Repeat("7", 32), ExecutorKeyID: actionpermit.Digest(executor), GrantID: "grant_" + strings.Repeat("8", 32), KeyID: actionpermit.Digest(offer.ManagerPublicKey)}
	registration := windowsupdatejob.SetupRegistration{Version: windowsupdatejob.SetupRegistrationVersion, Offer: *offer, Consent: windowsupdatejob.Consent{Version: windowsupdatejob.ConsentVersion, Scope: windowsupdatejob.Scope, Binding: binding, Enabled: true, Acknowledged: true, ExpiresAt: offer.ExpiresAt}, ExecutorPublicKey: executor}
	if registration.Validate() != nil {
		t.Fatal("registration fixture")
	}
	m.plan.Request.Phase, m.plan.Request.ExpiresAt = "finalize", 0
	m.plan.Request.RegistrationFile = "/protected/second-registration.json"
	m.plan.Offer, m.plan.Registration = offer, &registration
	raw, _ := json.Marshal(registration)
	m.plan.RegistrationDigest = actionpermit.Digest(raw)
	m.plan.Digest = m.plan.digest()
	fx.events = nil
	return m, fx, now
}

func cloneSetupFiles(files map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for path, raw := range files {
		out[path] = bytes.Clone(raw)
	}
	return out
}
func unchangedSetupFiles(t *testing.T, before, after map[string][]byte) {
	t.Helper()
	for path, raw := range before {
		if !bytes.Equal(raw, after[path]) {
			t.Fatalf("old bytes changed: %s", path)
		}
	}
}

func TestAdditionalSetupPreparationReusesOnlyExistingManagerKey(t *testing.T) {
	m, fx, now := additionalSetupFixture(t)
	before := cloneSetupFiles(fx.files)
	offer, err := applySetup(context.Background(), m, fx, func() time.Time { return now })
	if err != nil || offer == nil || fx.generated != 0 || fx.initialized != 0 || !bytes.Equal(offer.ManagerPublicKey, m.managerPublic) || offer.DeviceID != m.plan.Request.DeviceID || offer.IncarnationDigest != m.plan.IncarnationDigest || offer.ExpiresAt != m.plan.ExpiresAt {
		t.Fatal("additional preparation", err)
	}
	unchangedSetupFiles(t, before, fx.files)
	if len(fx.events) != 4 || fx.events[0] != "create:"+setupPlanIntent(m.plan) || fx.events[1] != "mkdir:"+setupPlanPath(m.plan, "") {
		t.Fatal("wrong create-only sequence", fx.events)
	}
	if _, exists := fx.files[setupPlanPath(m.plan, "manager.key")]; exists {
		t.Fatal("copied or generated another manager key")
	}
	next := m.plan
	next.Request.DeviceID = "agent_" + strings.Repeat("9", 32)
	if setupPlanIntent(next) == setupPlanIntent(m.plan) || setupPlanPath(next, "offer.json") == setupPlanPath(m.plan, "offer.json") || SetupPlanLANPath(m.plan) == SetupLANPath(m.plan.StateDirectory) {
		t.Fatal("per-device paths collided")
	}
	if _, err = applySetup(context.Background(), m, fx, func() time.Time { return now }); err == nil || fx.generated != 0 {
		t.Fatal("reused additional setup adopted")
	}
}

func TestAdditionalSetupFinalizeStagesExplicitRegistryWithoutChangingOldBytes(t *testing.T) {
	m, fx, now := finalAdditionalSetupFixture(t)
	before := cloneSetupFiles(fx.files)
	if offer, err := applySetup(context.Background(), m, fx, func() time.Time { return now }); err != nil || offer != nil || fx.initialized != 1 || fx.generated != 0 {
		t.Fatal("finalize", err)
	}
	unchangedSetupFiles(t, before, fx.files)
	var c Config
	var registry RegistryConfig
	var lan lanconfig.Config
	if json.Unmarshal(fx.files[setupPlanPath(m.plan, "manager.json")], &c) != nil || !validConfig(c) || c.PrivateKeyFile != m.plan.ManagerKeyFile || c.Binding != m.plan.Registration.Consent.Binding {
		t.Fatal("new exact config")
	}
	if json.Unmarshal(fx.files[setupPlanPath(m.plan, "registry.json")], &registry) != nil || !validRegistry(registry, m.config.RecordLimit) || registry.ManagerID != m.plan.ManagerID || !sameJSON(registry.ConfigFiles, []string{m.plan.OriginalRegistryFile, setupPlanPath(m.plan, "manager.json")}) {
		t.Fatal("registry expanded or lost original entries")
	}
	if json.Unmarshal(fx.files[SetupPlanLANPath(m.plan)], &lan) != nil || lan.WindowsUpdateJobsConfigFile != setupPlanPath(m.plan, "registry.json") {
		t.Fatal("LAN did not stage explicit registry")
	}
	if len(fx.events) != 7 || fx.events[2] != "initialize" || !strings.HasSuffix(fx.events[6], "complete.json") {
		t.Fatal("wrong order", fx.events)
	}
}

func TestAdditionalSetupFailurePreservesFencesAndNeverRetries(t *testing.T) {
	for _, fail := range []string{"initialize", "manager.json", "registry.json", "lan.json", "complete.json"} {
		t.Run(fail, func(t *testing.T) {
			m, fx, now := finalAdditionalSetupFixture(t)
			before := cloneSetupFiles(fx.files)
			fx.fail = fail
			if _, err := applySetup(context.Background(), m, fx, func() time.Time { return now }); err == nil {
				t.Fatal("partial additional setup succeeded")
			}
			unchangedSetupFiles(t, before, fx.files)
			if len(fx.files[setupPlanPath(m.plan, "finalize-started.json")]) == 0 || len(fx.files[setupPlanPath(m.plan, "complete.json")]) != 0 {
				t.Fatal("lost failure fence or false completion")
			}
			n := fx.initialized
			fx.fail = ""
			if _, err := applySetup(context.Background(), m, fx, func() time.Time { return now }); err == nil || fx.initialized != n {
				t.Fatal("partial additional setup retried")
			}
		})
	}
}

func TestAdditionalSetupExpiryAcrossEachBlockingWriteFails(t *testing.T) {
	for _, phase := range []string{"prepare", "finalize"} {
		names := []string{"-started.json", "offer.json", "prepared.json"}
		if phase == "finalize" {
			names = []string{"finalize-started.json", "registration.json", "manager.json", "registry.json", "lan.json", "complete.json"}
		}
		for _, name := range names {
			t.Run(phase+"/"+name, func(t *testing.T) {
				var m setupMaterial
				var fx *setupFixtureEffects
				var now time.Time
				if phase == "prepare" {
					m, fx, now = additionalSetupFixture(t)
				} else {
					m, fx, now = finalAdditionalSetupFixture(t)
				}
				at := now
				fx.afterCreate = func(path string) {
					if strings.HasSuffix(path, name) {
						at = time.Unix(m.plan.ExpiresAt, 0).UTC()
					}
				}
				if _, err := applySetup(context.Background(), m, fx, func() time.Time { return at }); err == nil {
					t.Fatal("blocking write refreshed expired authority")
				}
				if fx.generated != 0 {
					t.Fatal("generated key")
				}
			})
		}
	}
	m, fx, now := finalAdditionalSetupFixture(t)
	at := now
	fx.afterInitialize = func() { at = time.Unix(m.plan.CurrentLeafNotAfter, 0).UTC() }
	if _, err := applySetup(context.Background(), m, fx, func() time.Time { return at }); err == nil || len(fx.files[setupPlanPath(m.plan, "manager.json")]) != 0 {
		t.Fatal("expired post-transaction leaf produced staged config")
	}
}

func TestAdditionalSetupRejectsDuplicateIndependentExecutorAndGrant(t *testing.T) {
	m, _, _ := finalAdditionalSetupFixture(t)
	for _, change := range []func(*windowsupdatejob.Binding){
		func(b *windowsupdatejob.Binding) { b.DeviceID = m.existingConfigs[0].Binding.DeviceID },
		func(b *windowsupdatejob.Binding) { b.ExecutorID = m.existingConfigs[0].Binding.ExecutorID },
		func(b *windowsupdatejob.Binding) { b.ExecutorKeyID = m.existingConfigs[0].Binding.ExecutorKeyID },
		func(b *windowsupdatejob.Binding) { b.GrantID = m.existingConfigs[0].Binding.GrantID },
	} {
		r := *m.plan.Registration
		change(&r.Consent.Binding)
		if additionalRegistrationUnique(r, m.existingConfigs) {
			t.Fatal("duplicate device/executor/grant admitted")
		}
	}
	if !additionalRegistrationUnique(*m.plan.Registration, m.existingConfigs) {
		t.Fatal("fresh exact registration rejected")
	}
}

func TestAdditionalSetupInspectionRequiresExactCompleteBindings(t *testing.T) {
	m, _, _ := finalAdditionalSetupFixture(t)
	good := enrollmentstore.WindowsUpdateSetupInspection{Config: m.config, Status: "fenced", PublicKey: m.managerPublic, RegisteredDevices: 1, RegisteredBindings: []windowsupdatejob.Binding{m.existingConfigs[0].Binding}}
	if !setupInspectionMatches(m, good, false) {
		t.Fatal("existing complete registry rejected")
	}
	for _, change := range []func(*enrollmentstore.WindowsUpdateSetupInspection){
		func(p *enrollmentstore.WindowsUpdateSetupInspection) { p.Status = "absent" },
		func(p *enrollmentstore.WindowsUpdateSetupInspection) { p.DeviceRegistered = true },
		func(p *enrollmentstore.WindowsUpdateSetupInspection) { p.RegisteredDevices = 2 },
		func(p *enrollmentstore.WindowsUpdateSetupInspection) { p.RegisteredBindings = nil },
		func(p *enrollmentstore.WindowsUpdateSetupInspection) {
			b := p.RegisteredBindings[0]
			b.GrantID = "grant_" + strings.Repeat("f", 32)
			p.RegisteredBindings = []windowsupdatejob.Binding{b}
		},
		func(p *enrollmentstore.WindowsUpdateSetupInspection) { p.PublicKey = bytes.Repeat([]byte{1}, 32) },
	} {
		bad := good
		change(&bad)
		if setupInspectionMatches(m, bad, false) {
			t.Fatal("partial/mismatched registry admitted")
		}
	}
	registered := good
	registered.DeviceRegistered = true
	registered.RegisteredDevices = 2
	registered.RegisteredBindings = append(append([]windowsupdatejob.Binding(nil), good.RegisteredBindings...), m.plan.Registration.Consent.Binding)
	if !setupInspectionMatches(m, registered, true) || setupInspectionMatches(m, registered, false) {
		t.Fatal("post-registration fence lost its exact phase")
	}
}

func TestAdditionalSetupReviewBindsOriginalAuthorityReferences(t *testing.T) {
	m, _, _ := additionalSetupFixture(t)
	for _, change := range []func(*SetupPlan){
		func(p *SetupPlan) { p.Request.AdditionalDevice = false },
		func(p *SetupPlan) { p.OriginalRegistryFile = "/protected/other.json" },
		func(p *SetupPlan) { p.OriginalRegistryDigest = actionpermit.Digest([]byte("other")) },
		func(p *SetupPlan) { p.OriginalConfigFiles = []string{"/protected/other.json"} },
		func(p *SetupPlan) { p.OriginalConfigDigests = []string{actionpermit.Digest([]byte("other"))} },
		func(p *SetupPlan) { p.ManagerKeyFile = "/protected/other.key" },
		func(p *SetupPlan) { p.ManagerKeyID = actionpermit.Digest([]byte("other")) },
		func(p *SetupPlan) { p.RegisteredDevices++ },
	} {
		p := m.plan
		change(&p)
		if p.digest() == m.plan.digest() || sameSetupInputs(p, m.plan) {
			t.Fatal("review omitted original authority")
		}
	}
	first, _, _ := setupFixture(t)
	raw, _ := json.Marshal(first.plan)
	for _, key := range []string{"additionalDevice", "originalRegistry", "originalConfig", "managerKeyFile", "managerKeyId", "registeredDevices"} {
		if bytes.Contains(raw, []byte(key)) {
			t.Fatal("legacy plan acquired extra JSON fields", key)
		}
	}
	request, _ := json.Marshal(SetupRequest{Phase: "prepare", LANConfig: "lan", EnrollmentConfig: "enrollment", DeviceID: "device", ExpiresAt: 1})
	if string(request) != `{"phase":"prepare","lanConfig":"lan","enrollmentConfig":"enrollment","deviceId":"device","expiresAt":1}` {
		t.Fatal("legacy request bytes changed", string(request))
	}
}

// These are inert protected-file fixtures, not a manager setup or grant. They
// exercise existing-only reads with deterministic synthetic key material.
func protectedAdditionalInputs(t *testing.T, count int) setupMaterial {
	t.Helper()
	m, _, _ := additionalSetupFixture(t)
	root := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32))
	keyPath := filepath.Join(root, "manager.key")
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	files := make([]string, 0, count)
	for i := 0; i < count; i++ {
		c := m.existingConfigs[0]
		// Decimal formatting is deliberately avoided; IDs remain exact lowercase hex.
		id := strings.Repeat("0", 30) + string("0123456789abcdef"[(i+1)/16]) + string("0123456789abcdef"[(i+1)%16])
		c.Binding.DeviceID = "agent_" + id
		c.Binding.ExecutorID = "executor_" + id
		c.Binding.GrantID = "grant_" + id
		c.Binding.ExecutorKeyID = actionpermit.Digest([]byte("executor-" + id))
		c.PrivateKeyFile = keyPath
		dir := filepath.Join(root, id)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		c.SetupReceiptFile = filepath.Join(dir, "complete.json")
		path := filepath.Join(dir, "manager.json")
		raw, _ := json.Marshal(c)
		receipt, _ := json.Marshal(setupComplete{SetupPlanVersion, c.SetupPlanDigest, c.SetupRegistrationDigest, actionpermit.Digest(raw)})
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.SetupReceiptFile, receipt, 0600); err != nil {
			t.Fatal(err)
		}
		files = append(files, path)
	}
	registry := RegistryConfig{Version: RegistryVersion, Enabled: true, ManagerID: m.plan.ManagerID, ConfigFiles: files}
	raw, _ := json.Marshal(registry)
	path := filepath.Join(root, "registry.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m.lan.Config.WindowsUpdateJobsConfigFile = path
	m.managerPublic = nil
	m.existingConfigs = nil
	m.plan.OriginalRegistryFile = ""
	m.plan.OriginalRegistryDigest = ""
	m.plan.OriginalConfigFiles = nil
	m.plan.OriginalConfigDigests = nil
	m.plan.ManagerKeyFile = ""
	m.plan.ManagerKeyID = ""
	m.plan.RegisteredDevices = 0
	return m
}

func rewriteSetupFixtureConfig(t *testing.T, path string, change func(*Config)) {
	t.Helper()
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &c) != nil {
		t.Fatal("read fixture", err)
	}
	change(&c)
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Recompute the inert receipt so checks must inspect the changed config too.
	receipt, _ := json.Marshal(setupComplete{SetupPlanVersion, c.SetupPlanDigest, c.SetupRegistrationDigest, actionpermit.Digest(raw)})
	if c.SetupReceiptFile != "" {
		if err := os.WriteFile(c.SetupReceiptFile, receipt, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAdditionalSetupProtectedInputsRequireCompleteBoundedUniqueRegistry(t *testing.T) {
	m := protectedAdditionalInputs(t, 2)
	if err := loadAdditionalSetupInputs(&m); err != nil || len(m.existingConfigs) != 2 || m.plan.RegisteredDevices != 2 || len(m.plan.OriginalConfigDigests) != 2 || actionpermit.Digest(m.managerPublic) != m.plan.ManagerKeyID {
		t.Fatal("complete registry", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*setupMaterial)
	}{
		{"enrollment capacity", func(m *setupMaterial) { m.config.RecordLimit = 2 }},
		{"missing receipt", func(m *setupMaterial) {
			var c Config
			raw, _ := os.ReadFile(m.plan.OriginalConfigFiles[0])
			json.Unmarshal(raw, &c)
			if err := os.Remove(c.SetupReceiptFile); err != nil {
				t.Fatal(err)
			}
		}},
		{"unreceipted configuration", func(m *setupMaterial) {
			rewriteSetupFixtureConfig(t, m.plan.OriginalConfigFiles[0], func(c *Config) { c.SetupReceiptFile = ""; c.SetupPlanDigest = ""; c.SetupRegistrationDigest = "" })
		}},
		{"duplicate device", func(m *setupMaterial) {
			rewriteSetupFixtureConfig(t, m.plan.OriginalConfigFiles[1], func(c *Config) { c.Binding.DeviceID = m.existingConfigs[0].Binding.DeviceID })
		}},
		{"duplicate executor", func(m *setupMaterial) {
			rewriteSetupFixtureConfig(t, m.plan.OriginalConfigFiles[1], func(c *Config) { c.Binding.ExecutorID = m.existingConfigs[0].Binding.ExecutorID })
		}},
		{"duplicate executor pin", func(m *setupMaterial) {
			rewriteSetupFixtureConfig(t, m.plan.OriginalConfigFiles[1], func(c *Config) { c.Binding.ExecutorKeyID = m.existingConfigs[0].Binding.ExecutorKeyID })
		}},
		{"duplicate grant", func(m *setupMaterial) {
			rewriteSetupFixtureConfig(t, m.plan.OriginalConfigFiles[1], func(c *Config) { c.Binding.GrantID = m.existingConfigs[0].Binding.GrantID })
		}},
		{"already configured target", func(m *setupMaterial) { m.plan.Request.DeviceID = m.existingConfigs[0].Binding.DeviceID }},
		{"foreign manager", func(m *setupMaterial) { m.plan.ManagerID = "manager_" + strings.Repeat("f", 32) }},
		{"other purpose key", func(m *setupMaterial) { m.forbidden = []ed25519.PublicKey{m.managerPublic} }},
		{"key reference changed", func(m *setupMaterial) {
			rewriteSetupFixtureConfig(t, m.plan.OriginalConfigFiles[1], func(c *Config) {
				raw, err := os.ReadFile(c.PrivateKeyFile)
				if err != nil {
					t.Fatal(err)
				}
				c.PrivateKeyFile = filepath.Join(filepath.Dir(c.PrivateKeyFile), "copied.key")
				if err := os.WriteFile(c.PrivateKeyFile, raw, 0600); err != nil {
					t.Fatal(err)
				}
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := protectedAdditionalInputs(t, 2)
			if loadAdditionalSetupInputs(&m) != nil {
				t.Fatal("fixture")
			}
			tc.change(&m)
			m.managerPublic = nil
			m.existingConfigs = nil
			if loadAdditionalSetupInputs(&m) == nil {
				t.Fatal("unsafe existing registry admitted")
			}
		})
	}
	m = protectedAdditionalInputs(t, windowsupdatejob.MaxDevices)
	m.config.RecordLimit = windowsupdatejob.MaxDevices + 1
	if loadAdditionalSetupInputs(&m) == nil {
		t.Fatal("fleet bound exceeded")
	}
	m = protectedAdditionalInputs(t, 1)
	if loadAdditionalSetupInputs(&m) != nil {
		t.Fatal("fixture")
	}
	// The first completed v1 file can seed an explicit v2 registry; it is not
	// rewritten or silently converted by the read-only plan.
	m.lan.Config.WindowsUpdateJobsConfigFile = m.plan.OriginalConfigFiles[0]
	m.managerPublic = nil
	m.existingConfigs = nil
	if loadAdditionalSetupInputs(&m) != nil || m.plan.OriginalRegistryFile != m.lan.Config.WindowsUpdateJobsConfigFile {
		t.Fatal("completed v1 seed rejected")
	}
}

func TestAdditionalSetupRejectsRollbackBetweenBlockingOutputs(t *testing.T) {
	m, fx, now := finalAdditionalSetupFixture(t)
	at := now
	fx.afterCreate = func(path string) {
		if strings.HasSuffix(path, "finalize-started.json") {
			at = now.Add(10 * time.Second)
		}
		if strings.HasSuffix(path, "registration.json") {
			at = now.Add(5 * time.Second)
		}
	}
	if _, err := applySetup(context.Background(), m, fx, func() time.Time { return at }); err == nil || fx.initialized != 0 {
		t.Fatal("clock rollback between writes admitted")
	}
	m, fx, now = finalAdditionalSetupFixture(t)
	at = now
	fx.afterInitialize = func() { at = now.Add(-time.Second) }
	if _, err := applySetup(context.Background(), m, fx, func() time.Time { return at }); err == nil || len(fx.files[setupPlanPath(m.plan, "manager.json")]) != 0 {
		t.Fatal("post-transaction clock rollback admitted")
	}
}
