package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"localrmm/internal/enrollmentstate"
	msi "localrmm/internal/windowsmanagedmsi"
	"testing"
	"time"
)

func TestManagedFleetArtifactIndependentOfRevokedOrExpiredTarget(t *testing.T) {
	for _, kind := range []string{"revoked", "expired"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsSoftwareStoreFixture(t, false)
			ctx := context.Background()
			pub := f.key.Public().(ed25519.PublicKey)
			second := additionalSoftwareIdentity(t, fullSoftwareFixture{f: f.fixture, s: f.store, path: f.path, at: f.at}, 2)
			a := managedStoreGrant(f)
			a.ExpiresAt = f.at.Unix() + 10
			b := a
			b.ExpiresAt = f.at.Unix() + 1000
			b.Binding.DeviceID = second.snap.Approval.DeviceID
			b.Binding.IncarnationDigest = "sha256:" + second.cert.CertificateHash()
			b.Binding.ExecutorID = id("executor", 14)
			b.Binding.DeliveryGrantID = id("grant", 16)
			b.Binding.InstallGrantID = id("grant", 17)
			executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{119}, 32)).Public().(ed25519.PublicKey)
			b.Binding.ExecutorKeyID = msi.Digest(executor)
			if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, pub, f.executor.Public().(ed25519.PublicKey), a, f.at, false); e != nil {
				t.Fatal("first", e)
			}
			if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, pub, executor, b, f.at, true); e != nil {
				t.Fatal("second", e)
			}
			if kind == "revoked" {
				control := f.fixture.control(f.snapshot, 210)
				control.Now = f.at.Unix() + 1
				if _, e := f.store.Terminate(ctx, enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked}); e != nil {
					t.Fatal(e)
				}
			}
			at := f.at.Add(11 * time.Second)
			if _, _, e := f.store.WindowsManagedMSITransaction(ctx, a.Binding, pub, at, func(*msi.Record, msi.Current, time.Time) error { return nil }); e == nil {
				t.Fatal("A unexpectedly admitted")
			}
			r, e := f.store.WindowsManagedMSIArtifactTransaction(ctx, pub, at, func(r *msi.ArtifactRecord, at time.Time) error {
				r.Artifact = &msi.Artifact{Package: preparedMSITestSelection(), NativeAcceptanceDigest: msi.Digest([]byte("review")), IntentAt: at.Unix(), PrefixDigest: msi.Digest(nil)}
				return nil
			})
			if e != nil || r.Artifact == nil {
				t.Fatal("A poisoned central reserve", e)
			}
			before, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, a.Binding, pub)
			if e != nil {
				t.Fatal(e)
			}
			rawBefore, _ := json.Marshal(before)
			if _, _, e = f.store.WindowsManagedMSITransaction(ctx, b.Binding, pub, at, func(*msi.Record, msi.Current, time.Time) error { return nil }); e != nil {
				t.Fatal("B blocked", e)
			}
			after, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, a.Binding, pub)
			rawAfter, _ := json.Marshal(after)
			if e != nil || !bytes.Equal(rawBefore, rawAfter) {
				t.Fatal("B wrote A", e)
			}
			if e = f.store.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(f.path, f.fixture.config, f.fixture.issuerDER)
			if e != nil {
				t.Fatal("expired A blocked restart", e)
			}
			defer reopened.Close()
			bindings, e := reopened.WindowsManagedMSIFleetBindings(ctx, pub)
			if e != nil || len(bindings) != 2 {
				t.Fatal("registry reopen", e)
			}
			if _, e = reopened.ReadWindowsManagedMSIArtifact(ctx, pub); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestManagedFleetRejectsAliasedBindingsAndSingletonAdoption(t *testing.T) {
	for _, kind := range []string{"device", "executor-id", "executor-key", "delivery", "install", "cross-role", "singleton"} {
		t.Run(kind, func(t *testing.T) {
			f := newWindowsSoftwareStoreFixture(t, false)
			ctx := context.Background()
			pub := f.key.Public().(ed25519.PublicKey)
			second := additionalSoftwareIdentity(t, fullSoftwareFixture{f: f.fixture, s: f.store, path: f.path, at: f.at}, 2)
			a := managedStoreGrant(f)
			if kind == "singleton" {
				if e := f.store.SetupWindowsManagedMSICreateOnly(ctx, pub, f.executor.Public().(ed25519.PublicKey), a, f.at); e != nil {
					t.Fatal(e)
				}
			} else if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, pub, f.executor.Public().(ed25519.PublicKey), a, f.at, false); e != nil {
				t.Fatal(e)
			}
			b := a
			b.Binding.DeviceID = second.snap.Approval.DeviceID
			b.Binding.IncarnationDigest = "sha256:" + second.cert.CertificateHash()
			b.Binding.ExecutorID = id("executor", 14)
			b.Binding.DeliveryGrantID = id("grant", 16)
			b.Binding.InstallGrantID = id("grant", 17)
			executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{119}, 32)).Public().(ed25519.PublicKey)
			b.Binding.ExecutorKeyID = msi.Digest(executor)
			switch kind {
			case "device":
				b.Binding.DeviceID = a.Binding.DeviceID
			case "executor-id":
				b.Binding.ExecutorID = a.Binding.ExecutorID
			case "executor-key":
				executor = f.executor.Public().(ed25519.PublicKey)
				b.Binding.ExecutorKeyID = a.Binding.ExecutorKeyID
			case "delivery":
				b.Binding.DeliveryGrantID = a.Binding.DeliveryGrantID
			case "install":
				b.Binding.InstallGrantID = a.Binding.InstallGrantID
			case "cross-role":
				b.Binding.DeliveryGrantID = a.Binding.InstallGrantID
			}
			if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, pub, executor, b, f.at, true); e == nil {
				t.Fatal("aliased/adopted grant")
			}
			if _, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, a.Binding, pub); e != nil {
				t.Fatal("rejection poisoned A", e)
			}
		})
	}
}
