package actionsetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/actionpermit"
	"strings"
	"testing"
	"time"
)

type fixtureEffects struct {
	calls       []string
	fail        int
	files       map[string][]byte
	keys        int
	initialized bool
}

func (f *fixtureEffects) step(name string) error {
	f.calls = append(f.calls, name)
	if len(f.calls) == f.fail {
		return errors.New("fixture-fault")
	}
	return nil
}
func (f *fixtureEffects) Create(p string, b []byte) error {
	if _, ok := f.files[p]; ok {
		return errors.New("exists")
	}
	if e := f.step("create:" + p); e != nil {
		return e
	}
	f.files[p] = bytes.Clone(b)
	return nil
}
func (f *fixtureEffects) Mkdir(p string) error { return f.step("mkdir:" + p) }
func (f *fixtureEffects) Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if e := f.step("generate"); e != nil {
		return nil, nil, e
	}
	f.keys++
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	return key.Public().(ed25519.PublicKey), key, nil
}
func (f *fixtureEffects) Initialize(context.Context, material, ed25519.PublicKey, time.Time) error {
	if e := f.step("atomic-domain"); e != nil {
		return e
	}
	f.initialized = true
	return nil
}
func fixturePlan() ManagerPlan {
	p := ManagerPlan{Version: Version, ManagerID: "manager_" + strings.Repeat("a", 32), ManagerOrigin: "https://manager.test:8444", EndpointID: "device_" + strings.Repeat("b", 32), IncarnationDigest: actionpermit.Digest([]byte("leaf")), TransportProfile: "production-tls", UID: 65532, GID: 65532, LANConfig: "/run/tracebolt/lan.json", EnrollmentConfig: "/run/tracebolt/enrollment.json", StateDirectory: "/data/state", InputDigest: actionpermit.Digest([]byte("inputs")), Operators: []Operator{{"operator_" + strings.Repeat("c", 32), "maintenance"}}}
	p.Digest = p.calculatedDigest()
	return p
}
func TestFaultBeforeEveryEffectPreservesIntentAndNeverRetries(t *testing.T) {
	for fail := 1; fail <= 9; fail++ {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			p := fixturePlan()
			fx := &fixtureEffects{fail: fail, files: map[string][]byte{}}
			_, e := apply(context.Background(), material{}, p, fx, time.Unix(1000, 0))
			if e == nil {
				t.Fatal("fault accepted")
			}
			if len(fx.calls) != fail {
				t.Fatalf("continued after fault: %v", fx.calls)
			}
			if fail > 1 {
				if _, ok := fx.files[IntentPath(p.StateDirectory)]; !ok {
					t.Fatal("lost intent")
				}
			}
			old := fx.keys
			fx.fail = 0
			_, e = apply(context.Background(), material{}, p, fx, time.Unix(1000, 0))
			if fail > 1 && (e == nil || fx.keys != old) {
				t.Fatal("partial setup reinitialized")
			}
		})
	}
}
func TestSuccessfulApplyOneKeyNoPrivateBundleAndRepeatBlocked(t *testing.T) {
	p := fixturePlan()
	fx := &fixtureEffects{files: map[string][]byte{}}
	b, e := apply(context.Background(), material{}, p, fx, time.Unix(1000, 0))
	if e != nil || fx.keys != 1 || !fx.initialized {
		t.Fatal(e)
	}
	if fx.calls[0] != "create:"+IntentPath(p.StateDirectory) || fx.calls[2] != "generate" {
		t.Fatal(fx.calls)
	}
	raw, _ := json.Marshal(b)
	secret := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	if bytes.Contains(raw, secret) || strings.Contains(string(raw), "private") {
		t.Fatal("private material leaked")
	}
	if _, e = apply(context.Background(), material{}, p, fx, time.Unix(1000, 0)); e == nil || fx.keys != 1 {
		t.Fatal("repeat generated key")
	}
}
func TestPlanDigestBindsEveryField(t *testing.T) {
	p := fixturePlan()
	before := p.Digest
	mutations := []func(*ManagerPlan){func(p *ManagerPlan) { p.UID++ }, func(p *ManagerPlan) { p.GID++ }, func(p *ManagerPlan) { p.EndpointID += "x" }, func(p *ManagerPlan) { p.IncarnationDigest = actionpermit.Digest([]byte("other")) }, func(p *ManagerPlan) { p.HTTPTestAcknowledged = true }, func(p *ManagerPlan) { p.InputDigest = actionpermit.Digest(nil) }, func(p *ManagerPlan) { p.Operators = nil }, func(p *ManagerPlan) { p.LANConfig += ".new" }}
	for _, change := range mutations {
		q := p
		change(&q)
		if q.calculatedDigest() == before {
			t.Fatal("unbound field")
		}
	}
}
func TestMissingOrChangedApprovalBeforeProductionReads(t *testing.T) {
	p := fixturePlan()
	for _, token := range []string{"", actionpermit.Digest(nil)} {
		if _, e := ApplyManager(context.Background(), p, token, time.Now()); e == nil {
			t.Fatal("unapproved apply")
		}
	}
	p.UID++
	if _, e := ApplyManager(context.Background(), p, p.Digest, time.Now()); e == nil {
		t.Fatal("changed plan")
	}
}
func TestForbiddenKeyCannotReachPrivateWrite(t *testing.T) {
	p := fixturePlan()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	fx := &fixtureEffects{files: map[string][]byte{}}
	if _, e := apply(context.Background(), material{forbidden: []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}}, p, fx, time.Now()); e == nil {
		t.Fatal("reused credential")
	}
	if len(fx.calls) != 3 {
		t.Fatal(fx.calls)
	}
}
