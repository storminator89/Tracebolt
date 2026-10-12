package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	"testing"
	"time"
)

func managedStoreGrant(f windowsSoftwareStoreFixture) msi.Grant {
	b := f.consent.Binding
	return msi.Grant{Version: msi.GrantVersion, Binding: msi.Binding{ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest, ExecutorID: b.ExecutorID, ExecutorKeyID: b.ExecutorKeyID, KeyID: b.KeyID, DeliveryGrantID: id("grant", 6), InstallGrantID: id("grant", 7)}, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: f.consent.ExpiresAt}
}
func TestManagedMSISetupFreshPreservesPreparedBytes(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, false)
	g := managedStoreGrant(f)
	ctx := context.Background()
	key, executor := f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey)
	var before, after []byte
	if e := f.store.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snapshot.InvitationID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if e := f.store.OpenWindowsManagedMSI(ctx, key); !errors.Is(e, msi.ErrUnavailable) {
		t.Fatal(e)
	}
	if e := f.store.SetupWindowsManagedMSICreateOnly(ctx, key, executor, g, f.at); e != nil {
		t.Fatal(e)
	}
	if e := f.store.SetupWindowsManagedMSICreateOnly(ctx, key, executor, g, f.at); !errors.Is(e, msi.ErrConflict) {
		t.Fatal(e)
	}
	if e := f.store.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, f.snapshot.InvitationID).Scan(&after); e != nil {
		t.Fatal(e)
	}
	var c credential
	if json.Unmarshal(after, &c) != nil || c.WindowsManagedMSISetup == nil {
		t.Fatal("missing immutable managed marker")
	}
	c.WindowsManagedMSISetup = nil
	legacy, _ := json.Marshal(c)
	if !bytes.Equal(before, legacy) {
		t.Fatal("changed legacy credential bytes")
	}
	r, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, key)
	if e != nil || r.Grant != g || r.Artifact != nil {
		t.Fatal(e)
	}
	if e = f.store.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(f.path, f.fixture.config, f.fixture.issuerDER)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if e = reopened.OpenWindowsManagedMSI(ctx, key); e != nil {
		t.Fatal(e)
	}
}
func TestManagedMSIRejectsPreparedKeyReuse(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, true)
	g := managedStoreGrant(f)
	if e := f.store.SetupWindowsManagedMSICreateOnly(context.Background(), f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey), g, f.at); !errors.Is(e, msi.ErrAuthority) {
		t.Fatal("prepared key promoted", e)
	}
}
func TestManagedMSIUploadIntentImmutableAndFinalClock(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, false)
	g := managedStoreGrant(f)
	ctx := context.Background()
	key := f.key.Public().(ed25519.PublicKey)
	if e := f.store.SetupWindowsManagedMSICreateOnly(ctx, key, f.executor.Public().(ed25519.PublicKey), g, f.at); e != nil {
		t.Fatal(e)
	}
	_, _, e := f.store.WindowsManagedMSITransaction(ctx, g.Binding, key, f.at, func(r *msi.Record, _ msi.Current, at time.Time) error {
		r.Artifact = &msi.Artifact{Package: preparedMSITestSelection(), NativeAcceptanceDigest: msi.Digest([]byte("synthetic acceptance")), IntentAt: at.Unix(), PrefixDigest: msi.Digest(nil)}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	_, _, e = f.store.WindowsManagedMSITransaction(ctx, g.Binding, key, f.at, func(r *msi.Record, _ msi.Current, _ time.Time) error { r.Artifact = nil; return nil })
	if !errors.Is(e, msi.ErrConsumed) {
		t.Fatal("intent reset", e)
	}
	clock := f.at
	guarded := msi.WithFinalCheck(WithOverviewClock(ctx, func() time.Time { return clock }), func() error { clock = time.Unix(g.ExpiresAt, 0); return nil })
	_, _, e = f.store.WindowsManagedMSITransaction(guarded, g.Binding, key, f.at, func(r *msi.Record, _ msi.Current, at time.Time) error {
		r.Artifact.PendingDigest = msi.Digest([]byte("synthetic chunk"))
		r.Artifact.PendingSize = int(r.Artifact.Package.Size)
		return nil
	})
	if !errors.Is(e, msi.ErrExpired) {
		t.Fatal("clock crossed expiry during final wait", e)
	}
	r, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, key)
	if e != nil || r.Artifact.PendingDigest != "" {
		t.Fatal("expired mutation escaped", e)
	}
}
