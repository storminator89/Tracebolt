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
	"localrmm/internal/windowsupdatejob"
)

type setupFixtureEffects struct {
	files       map[string][]byte
	events      []string
	fail        string
	key         ed25519.PrivateKey
	generated   int
	initialized int
	checks      int
	recheck     func()
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
