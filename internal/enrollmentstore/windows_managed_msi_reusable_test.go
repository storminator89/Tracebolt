package enrollmentstore

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"testing"
	"time"
)

func TestManagedReusableFreshStoreAndArtifactRetirement(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, false)
	ctx := context.Background()
	g := managedStoreGrant(f)
	g.Version = msi.ReusableGrantVersion
	g.ReusableAcknowledged = true
	g.MutationPlanDigest = msi.Digest([]byte("fresh reviewed plan"))
	g.PeerBindingDigest = msi.Digest([]byte("independent peer"))
	pub := f.key.Public().(ed25519.PublicKey)
	if e := f.store.SetupWindowsManagedMSICreateOnly(ctx, pub, f.executor.Public().(ed25519.PublicKey), g, f.at); e == nil {
		t.Fatal("reusable singleton accepted")
	}
	if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, pub, f.executor.Public().(ed25519.PublicKey), g, f.at, false); e != nil {
		t.Fatal("fresh reusable", e)
	}
	a, e := f.store.ReadWindowsManagedMSIArtifact(ctx, pub)
	if e != nil || a.Version != msi.ReusableArtifactRecordVersion {
		t.Fatal(e)
	}
	selection := preparedMSITestSelection()
	selection.Size = 1024
	// Ordinary bounded synthetic metadata, no MSI bytes enter this database.
	_, e = f.store.WindowsManagedMSIArtifactTransaction(ctx, pub, f.at, func(r *msi.ArtifactRecord, at time.Time) error {
		r.Artifact = &msi.Artifact{Package: selection, PublisherStatus: "unverified", PublisherEvidenceDigest: msi.Digest([]byte("publisher")), NativeAcceptanceDigest: msi.Digest([]byte("native")), IntentAt: at.Unix(), PrefixDigest: msi.Digest(nil)}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	// Intent cannot be replaced without a completed reviewed retirement.
	_, e = f.store.WindowsManagedMSIArtifactTransaction(ctx, pub, f.at, func(r *msi.ArtifactRecord, _ time.Time) error { r.Artifact = nil; return nil })
	if e == nil {
		t.Fatal("uncompleted intent reset")
	}
	r, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, pub)
	if e != nil || r.Version != msi.ReusableRecordVersion || r.Jobs.Sequence != 0 {
		t.Fatal(e)
	}
	if e = f.store.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(f.path, f.fixture.config, f.fixture.issuerDER)
	if e != nil {
		t.Fatal("reopen", e)
	}
	defer reopened.Close()
	after, e := reopened.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, pub)
	raw, _ := json.Marshal(r)
	next, _ := json.Marshal(after)
	if e != nil || string(raw) != string(next) {
		t.Fatal("fresh grant changed", e)
	}
	if maxDatabaseBytes != 192<<20 {
		t.Fatal("enrollment DB cap expanded")
	}
}
