package enrollmenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionmanager"
)

// These exercise real SQLite-backed manager claims, not a simulated Claim.
// The admission callback models the account epoch/lease contract independently
// of operatorauth's own concurrency and journal tests.
type serviceClaimHarness struct {
	configure func(operatorauth.ActorAdmission) error
	approve   func(context.Context, string) (func() (int, func(), error), uint64)
}

func serviceAccountHarness(t *testing.T, windows bool) serviceClaimHarness {
	t.Helper()
	ctx := context.Background()
	if !windows {
		f := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfileComplete, true)
		h, err := New(f.store, f.issuer.IssuerDER(), "https://localhost")
		if err != nil {
			t.Fatal(err)
		}
		manager, helper, _, peer := prepareActions(t, f, h)
		caps, err := helper.Capabilities(ctx, peer)
		if err != nil {
			t.Fatal(err)
		}
		if err = manager.Report(ctx, f.snapshot.InvitationID, f.cert.CertificateHash(), caps); err != nil {
			t.Fatal(err)
		}
		return serviceClaimHarness{manager.ConfigureAccountAuthority, func(c context.Context, actor string) (func() (int, func(), error), uint64) {
			r, e := manager.Preview(c, f.snapshot.Approval.DeviceID, actor, "fixture.service")
			if e != nil {
				t.Fatal(e)
			}
			r, e = manager.Approve(c, f.snapshot.Approval.DeviceID, r.Preview.ID, r.Preview.Digest, actor)
			if e != nil {
				t.Fatal(e)
			}
			identity := r.Jobs[len(r.Jobs)-1].Identity()
			persisted, e := manager.View(ctx, f.snapshot.Approval.DeviceID)
			if e != nil {
				t.Fatal(e)
			}
			return func() (int, func(), error) {
				g, release, err := manager.ClaimWithAdmission(ctx, f.snapshot.InvitationID, f.cert.CertificateHash(), identity)
				return len(g.Envelope), release, err
			}, persisted.Jobs[len(persisted.Jobs)-1].AuthorityEpoch
		}}
	}
	f := newCollectionFixture(t, "tls", enrollmentcrypto.CollectionProfileWindowsInventory, true)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{94}, 32))
	pub := key.Public().(ed25519.PublicKey)
	b := windowsaction.Binding{ManagerID: f.config.Binding.InstanceID, EndpointID: f.snapshot.Approval.DeviceID, KeyID: windowsaction.Digest(pub), IncarnationDigest: "sha256:" + f.cert.CertificateHash(), InstallationID: "broker_" + strings.Repeat("5", 32), Target: "FixtureService", TargetDigest: windowsaction.Digest([]byte("fixture target")), GrantDigest: windowsaction.Digest([]byte("fixture grant"))}
	if err := f.store.SetupWindowsServiceActionsCreateOnly(ctx, pub, b, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	kp := filepath.Join(dir, "command.key")
	cp := filepath.Join(dir, "actions.json")
	if err := os.WriteFile(kp, key, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(windowsactionmanager.Config{Version: windowsactionmanager.ConfigVersion, Enabled: true, ManagerID: b.ManagerID, TransportProfile: windowsactionmanager.Profile("tls"), PrivateKeyFile: kp})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cp, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := windowsactionmanager.Load(ctx, f.store, cp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	if err = m.Report(ctx, f.snapshot.InvitationID, f.cert.CertificateHash(), windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: time.Now().Unix(), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return serviceClaimHarness{m.ConfigureAccountAuthority, func(c context.Context, actor string) (func() (int, func(), error), uint64) {
		r, e := m.Preview(c, f.snapshot.Approval.DeviceID, actor, b.Target, "start")
		if e != nil {
			t.Fatal(e)
		}
		r, e = m.Approve(c, f.snapshot.Approval.DeviceID, r.Preview.ID, r.Preview.Digest, actor)
		if e != nil {
			t.Fatal(e)
		}
		identity := r.Jobs[len(r.Jobs)-1].Identity()
		// Reload the manager and read durable metadata before claim.
		reopened, e := windowsactionmanager.Load(ctx, f.store, cp)
		if e != nil {
			t.Fatal(e)
		}
		defer reopened.Close()
		persisted, e := reopened.View(ctx, f.snapshot.Approval.DeviceID)
		if e != nil {
			t.Fatal(e)
		}
		return func() (int, func(), error) {
			g, release, err := m.ClaimWithAdmission(ctx, f.snapshot.InvitationID, f.cert.CertificateHash(), identity)
			return len(g.Envelope), release, err
		}, persisted.Jobs[len(persisted.Jobs)-1].AuthorityEpoch
	}}
}

func TestServiceAccountClaimEpochAndLease(t *testing.T) {
	for _, windows := range []bool{false, true} {
		name := "linux"
		if windows {
			name = "windows"
		}
		t.Run(name, func(t *testing.T) {
			for _, scenario := range []string{"regrant-denies-old", "legacy-zero-denied", "other-actor-continues"} {
				t.Run(scenario, func(t *testing.T) {
					h := serviceAccountHarness(t, windows)
					actor := "operator_" + strings.Repeat("1", 32)
					other := "operator_" + strings.Repeat("2", 32)
					var mu sync.RWMutex
					epochs := map[string]uint64{actor: 7, other: 7}
					denied := errors.New("account epoch retired")
					admission := func(ctx context.Context, a string, epoch uint64, _ ...operatorauth.Capability) (context.Context, func(), error) {
						mu.RLock()
						if epoch == 0 || epochs[a] != epoch {
							mu.RUnlock()
							return ctx, nil, denied
						}
						return ctx, mu.RUnlock, nil
					}
					epoch := uint64(7)
					if scenario == "legacy-zero-denied" {
						epoch = 0
					} else {
						if err := h.configure(admission); err != nil {
							t.Fatal(err)
						}
					}
					approvedActor := actor
					if scenario == "other-actor-continues" {
						approvedActor = other
					}
					claim, persisted := h.approve(operatorauth.WithApprovalEpoch(context.Background(), epoch), approvedActor)
					if persisted != epoch {
						t.Fatal("durable epoch missing", persisted)
					}
					if scenario == "legacy-zero-denied" {
						if err := h.configure(admission); err != nil {
							t.Fatal(err)
						}
					}
					mu.Lock()
					epochs[actor] = 8
					mu.Unlock() // revoke/regrant one actor only
					n, release, err := claim()
					if scenario != "other-actor-continues" {
						if !errors.Is(err, denied) || release != nil || n != 0 {
							t.Fatal("retired approval released permit", err)
						}
						n, release, err = claim()
						if !errors.Is(err, denied) || release != nil || n != 0 {
							t.Fatal("repeat revived approval", err)
						}
						return
					}
					if err != nil || n == 0 || release == nil {
						t.Fatal("other actor blocked", err)
					}
					if mu.TryLock() {
						mu.Unlock()
						t.Fatal("lease released before transport handoff")
					}
					release()
					if !mu.TryLock() {
						t.Fatal("lease leaked")
					}
					mu.Unlock()
					n, release, err = claim()
					if release != nil {
						release()
					}
					if err == nil || n != 0 {
						t.Fatal("consumed permit replayed", err)
					}
				})
			}
		})
	}
}
