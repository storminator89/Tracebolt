package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	msi "localrmm/internal/windowsmanagedmsi"
	"testing"
	"time"
)

func catalogueStoreFixture(t *testing.T, scheduled bool) (windowsSoftwareStoreFixture, msi.Grant) {
	t.Helper()
	f := newWindowsSoftwareStoreFixture(t, false)
	g := scheduledManagedStoreGrant(f)
	if !scheduled {
		g.Version = msi.ReusableGrantVersion
		g.ScheduledEnabled = false
		g.ScheduledAcknowledged = false
	}
	if e := f.store.SetupWindowsMSICatalogueCreateOnly(context.Background(), f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey), g, f.at, false); e != nil {
		t.Fatal("catalogue setup", e)
	}
	return f, g
}
func catalogueReserve(t *testing.T, f windowsSoftwareStoreFixture, size int64, tag string) msi.ArtifactRecord {
	t.Helper()
	ctx := context.Background()
	key := f.key.Public().(ed25519.PublicKey)
	r, e := f.store.ReadWindowsMSICatalogue(ctx, key)
	if e != nil {
		t.Fatal(e)
	}
	sel := preparedMSITestSelection()
	sel.Size = size
	sel.Name = "Reviewed " + tag
	sel.SHA256 = msi.Digest([]byte(tag))
	r, e = f.store.ReserveWindowsMSICatalogue(ctx, key, f.at, r.Revision, msi.Artifact{Package: sel, NativeAcceptanceDigest: msi.Digest([]byte("native")), PublisherStatus: "unverified", PublisherEvidenceDigest: msi.Digest([]byte("publisher"))})
	if e != nil {
		t.Fatal("reserve", e)
	}
	return r.Entries[len(r.Entries)-1]
}
func catalogueComplete(t *testing.T, f windowsSoftwareStoreFixture, a msi.ArtifactRecord) msi.ArtifactRecord {
	t.Helper()
	ctx := msi.WithCatalogueOccurrence(context.Background(), a.RetiredCount)
	key := f.key.Public().(ed25519.PublicKey)
	for step := 0; step < 4; step++ {
		var e error
		a, e = f.store.WindowsManagedMSIArtifactTransaction(ctx, key, f.at, func(r *msi.ArtifactRecord, at time.Time) error {
			switch step {
			case 0:
				r.Artifact.PendingDigest = r.Artifact.Package.SHA256
				r.Artifact.PendingSize = int(r.Artifact.Package.Size)
			case 1:
				r.Artifact.CustodyDigest = msi.Digest([]byte(fmt.Sprintf("custody %d", r.RetiredCount)))
			case 2:
				r.Artifact.Offset = r.Artifact.Package.Size
				r.Artifact.PrefixDigest = r.Artifact.Package.SHA256
				r.Artifact.LastChunkDigest = r.Artifact.Package.SHA256
				r.Artifact.PendingDigest = ""
				r.Artifact.PendingSize = 0
			case 3:
				r.Artifact.CompletedAt = at.Unix()
			}
			return nil
		})
		if e != nil {
			t.Fatal("complete step", step, e)
		}
	}
	return a
}
func catalogueDeliver(f windowsSoftwareStoreFixture, g msi.Grant, a msi.ArtifactRecord, transfer string) error {
	_, _, e := f.store.WindowsManagedMSITransaction(context.Background(), g.Binding, f.key.Public().(ed25519.PublicKey), f.at, func(r *msi.Record, c msi.Current, at time.Time) error {
		if r.TransferID != "" {
			next, e := msi.NextManagerJob(*r)
			if e != nil {
				return e
			}
			*r = next
		}
		r.Artifact = a.Artifact
		r.ArtifactRetiredCount = a.RetiredCount
		if r.Jobs.Sequence == 0 {
			r.Jobs.Sequence = 1
		}
		r.TransferID = transfer
		p := msi.PermitForGrant(msi.Permit{Version: msi.Version, Kind: "deliver", TransferID: transfer, Binding: g.Binding, LeafDigest: c.LeafDigest, Package: a.Artifact.Package, NativeAcceptanceDigest: a.Artifact.NativeAcceptanceDigest, ActorID: id("operator", 21), IssuedAt: at.Unix(), ExpiresAt: at.Unix() + 600}, g, r.Jobs.Sequence, *a.Artifact)
		var e error
		r.DeliveryPermit, e = msi.SignPermit(p, f.key)
		return e
	})
	return e
}
func catalogueFinishJob(t *testing.T, f windowsSoftwareStoreFixture, g msi.Grant) {
	t.Helper()
	_, _, e := f.store.WindowsManagedMSITransaction(context.Background(), g.Binding, f.key.Public().(ed25519.PublicKey), f.at, func(r *msi.Record, c msi.Current, at time.Time) error {
		var e error
		r.DeliveryClaimedAt = at.Unix()
		r.DeliveryReport, e = savedMSIStoreReport(f, r.DeliveryPermit, "delivery", at.Unix())
		if e != nil {
			return e
		}
		p := msi.PermitForGrant(msi.Permit{Version: msi.Version, Kind: "readiness", TransferID: r.TransferID, Binding: g.Binding, LeafDigest: c.LeafDigest, Package: r.Artifact.Package, NativeAcceptanceDigest: r.Artifact.NativeAcceptanceDigest, ActorID: id("operator", 21), IssuedAt: at.Unix(), ExpiresAt: at.Unix() + 60, Sequence: 1, MaintenanceUntil: at.Unix() + 600, PackageReviewAccepted: true, TermsAccepted: true, SynchronousReviewDigest: msi.SynchronousReviewDigest(r.Artifact.Package, r.Artifact.NativeAcceptanceDigest)}, g, r.Jobs.Sequence, *r.Artifact)
		r.ReadinessPermit, e = msi.SignPermit(p, f.key)
		if e != nil {
			return e
		}
		r.ReadinessClaimedAt = at.Unix()
		r.ReadinessReport, e = savedMSIStoreReport(f, r.ReadinessPermit, "readiness", at.Unix())
		if e != nil {
			return e
		}
		p.Kind = "install"
		p.ReadinessDigest = msi.Digest(r.ReadinessReport)
		r.InstallPermit, e = msi.SignPermit(p, f.key)
		if e != nil {
			return e
		}
		r.InstallClaimedAt = at.Unix()
		r.ResultReport, e = savedMSIStoreReport(f, r.InstallPermit, "result", at.Unix())
		if e != nil {
			return e
		}
		p.Kind = "retire"
		p.Sequence = 0
		p.ReadinessDigest = ""
		p.MaintenanceUntil = 0
		p.RetireResultDigest = msi.Digest(r.ResultReport)
		r.RetirePermit, e = msi.SignPermit(p, f.key)
		if e != nil {
			return e
		}
		r.RetireClaimedAt = at.Unix()
		r.RetiredReport, e = savedMSIStoreReport(f, r.RetirePermit, "retired", at.Unix())
		return e
	})
	if e != nil {
		t.Fatal("signed settled retirement", e)
	}
}
func catalogueRetireMetadata(f windowsSoftwareStoreFixture, a msi.ArtifactRecord, finish bool) error {
	_, e := f.store.WindowsManagedMSIArtifactTransaction(msi.WithCatalogueOccurrence(context.Background(), a.RetiredCount), f.key.Public().(ed25519.PublicKey), f.at, func(r *msi.ArtifactRecord, _ time.Time) error {
		if finish {
			r.Retired = true
			return nil
		}
		proof, e := r.CatalogueRetirementEvidence()
		if e != nil {
			return e
		}
		r.RetirementStarted = true
		r.RetirementEvidenceDigest = proof
		r.RetiredBy = id("operator", 21)
		return nil
	})
	return e
}
func TestManagedMSICatalogueFreshQuotaAndRestart(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		t.Run(fmt.Sprint(scheduled), func(t *testing.T) {
			f, g := catalogueStoreFixture(t, scheduled)
			key := f.key.Public().(ed25519.PublicKey)
			ctx := context.Background()
			for i := 0; i < 4; i++ {
				catalogueReserve(t, f, 32<<20, fmt.Sprint(i))
			}
			c, e := f.store.ReadWindowsMSICatalogue(ctx, key)
			if e != nil || c.ReservedBytes() != 128<<20 || len(c.Entries) != 4 {
				t.Fatal("declared-byte quota", c, e)
			}
			if _, e = f.store.ReserveWindowsMSICatalogue(ctx, key, f.at, c.Revision, *c.Entries[0].Artifact); e == nil {
				t.Fatal("fifth payload accepted")
			}
			if _, e = f.store.ReadWindowsManagedMSIArtifact(ctx, key); e == nil {
				t.Fatal("unselected singleton read accepted")
			}
			j, e := f.store.ReadWindowsMSIWorklists(ctx, key)
			if e != nil || j.Version != msi.CatalogueWorklistVersion {
				t.Fatal("fresh worklist", e)
			}
			r, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, key)
			if e != nil || !r.Catalogue() {
				t.Fatal(e)
			}
			if e = f.store.Close(); e != nil {
				t.Fatal(e)
			}
			s, e := Open(f.path, f.fixture.config, f.fixture.issuerDER)
			if e != nil {
				t.Fatal("reopen", e)
			}
			defer s.Close()
			after, e := s.ReadWindowsMSICatalogue(ctx, key)
			a, _ := json.Marshal(c)
			b, _ := json.Marshal(after)
			if e != nil || string(a) != string(b) {
				t.Fatal("restart changed custody", e)
			}
		})
	}
}
func TestManagedMSICatalogueScopedRetirementAndReplay(t *testing.T) {
	f, g := catalogueStoreFixture(t, false)
	key := f.key.Public().(ed25519.PublicKey)
	ctx := context.Background()
	a := catalogueComplete(t, f, catalogueReserve(t, f, 1024, "A"))
	b := catalogueComplete(t, f, catalogueReserve(t, f, 1024, "B"))
	if e := catalogueDeliver(f, g, a, id("transfer", 22)); e != nil {
		t.Fatal("A deliver", e)
	}
	if e := catalogueRetireMetadata(f, a, false); e == nil {
		t.Fatal("unresolved A retired")
	}
	if e := catalogueRetireMetadata(f, b, false); e != nil {
		t.Fatal("A starved unrelated B", e)
	}
	if e := catalogueDeliver(f, g, b, id("transfer", 23)); e == nil {
		t.Fatal("retirement race admitted B")
	}
	if e := catalogueRetireMetadata(f, b, true); e != nil {
		t.Fatal(e)
	}
	c := catalogueComplete(t, f, catalogueReserve(t, f, 1024, "C"))
	if c.RetiredCount <= b.RetiredCount || *c.CatalogueSlot != *b.CatalogueSlot {
		t.Fatal("slot reuse lost unique occurrence")
	}
	catalogueFinishJob(t, f, g)
	if e := catalogueDeliver(f, g, c, id("transfer", 24)); e != nil {
		t.Fatal("C after A", e)
	}
	catalogueFinishJob(t, f, g)
	if e := catalogueDeliver(f, g, a, id("transfer", 25)); e == nil {
		t.Fatal("A B A old occurrence reused")
	}
	if e := catalogueRetireMetadata(f, a, false); e != nil {
		t.Fatal("retained A assignment evidence lost", e)
	}
	if e := catalogueRetireMetadata(f, a, true); e != nil {
		t.Fatal(e)
	}
	fresh := catalogueComplete(t, f, catalogueReserve(t, f, 1024, "A"))
	if msi.ArtifactIdentity(*a.Artifact) != msi.ArtifactIdentity(*fresh.Artifact) || a.RetiredCount == fresh.RetiredCount {
		t.Fatal("content/occurrence identity")
	}
	if e := catalogueDeliver(f, g, fresh, id("transfer", 26)); e != nil {
		t.Fatal("fresh A", e)
	}
	saved, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, key)
	if e != nil || saved.Jobs.Sequence != 3 || saved.ArtifactRetiredCount != fresh.RetiredCount {
		t.Fatal("job sequence", e)
	}
	if _, e = f.store.ReadWindowsManagedMSIArtifact(msi.WithCatalogueOccurrence(ctx, a.RetiredCount), key); e == nil {
		t.Fatal("pruned custody alias")
	}
}
func TestManagedMSICatalogueDoesNotPromoteLegacy(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, false)
	g := scheduledManagedStoreGrant(f)
	key := f.key.Public().(ed25519.PublicKey)
	ctx := context.Background()
	if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, key, f.executor.Public().(ed25519.PublicKey), g, f.at, false); e != nil {
		t.Fatal(e)
	}
	if e := f.store.SetupWindowsMSICatalogueCreateOnly(ctx, key, f.executor.Public().(ed25519.PublicKey), g, f.at, false); e == nil {
		t.Fatal("old singleton promoted")
	}
	if _, e := f.store.ReadWindowsMSICatalogue(ctx, key); e == nil {
		t.Fatal("old singleton exposed catalogue")
	}
}

func TestManagedMSICatalogueEntryAndByteLimitsAreIndependent(t *testing.T) {
	for _, kind := range []string{"entries", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := catalogueStoreFixture(t, false)
			size, count := int64(1024), 4
			if kind == "bytes" {
				size, count = 65<<20, 1
			}
			for i := 0; i < count; i++ {
				catalogueReserve(t, f, size, fmt.Sprint(i))
			}
			key := f.key.Public().(ed25519.PublicKey)
			c, e := f.store.ReadWindowsMSICatalogue(context.Background(), key)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.store.ReserveWindowsMSICatalogue(context.Background(), key, f.at, c.Revision, *c.Entries[0].Artifact); e == nil {
				t.Fatal("limit escaped", kind)
			}
			if _, e = f.store.ReserveWindowsMSICatalogue(context.Background(), key, f.at, 1, *c.Entries[0].Artifact); e == nil {
				t.Fatal("stale revision")
			}
		})
	}
}
func TestManagedMSICatalogueActiveWorklistsPinRetiredSlots(t *testing.T) {
	f, g := catalogueStoreFixture(t, false)
	key := f.key.Public().(ed25519.PublicKey)
	ctx := context.Background()
	var entries []msi.ArtifactRecord
	for i := 0; i < 4; i++ {
		a := catalogueComplete(t, f, catalogueReserve(t, f, 1024, fmt.Sprint(i)))
		entries = append(entries, a)
		w := msi.Worklist{ID: id("worklist", 30+i), Revision: 1, Name: fmt.Sprintf("Saved %d", i), CreatedBy: id("operator", 21), CreatedAt: f.at.Unix(), ArtifactID: msi.ArtifactIdentity(*a.Artifact), ArtifactRetiredCount: a.RetiredCount, Package: a.Artifact.Package, NativeAcceptanceDigest: a.Artifact.NativeAcceptanceDigest, PublisherStatus: a.Artifact.PublisherStatus, PublisherEvidenceDigest: a.Artifact.PublisherEvidenceDigest, Targets: []msi.WorklistTarget{{Name: "Original device", Binding: g.Binding}}, Batches: []msi.WorklistBatch{}}
		if _, e := f.store.WindowsMSIWorklistTransaction(msi.WithCatalogueOccurrence(ctx, a.RetiredCount), key, f.at, nil, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, _ time.Time) error {
			j.Worklists = append(j.Worklists, w)
			return nil
		}); e != nil {
			t.Fatal("independent active worklist", i, e)
		}
	}
	a := entries[0]
	if e := catalogueRetireMetadata(f, a, false); e != nil {
		t.Fatal(e)
	}
	if e := catalogueRetireMetadata(f, a, true); e != nil {
		t.Fatal(e)
	}
	c, _ := f.store.ReadWindowsMSICatalogue(ctx, key)
	if _, e := f.store.ReserveWindowsMSICatalogue(ctx, key, f.at, c.Revision, *a.Artifact); e == nil {
		t.Fatal("active worklist orphaned by slot reuse")
	}
	if _, e := f.store.WindowsMSIWorklistTransaction(ctx, key, f.at, nil, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, _ time.Time) error {
		j.Worklists[0].ArchivedAt = f.at.Unix()
		j.Worklists[0].Revision++
		return nil
	}); e != nil {
		t.Fatal("archive", e)
	}
	fresh := catalogueReserve(t, f, 1024, "new")
	if *fresh.CatalogueSlot != *a.CatalogueSlot {
		t.Fatal("retired archived slot not reusable")
	}
	j, e := f.store.ReadWindowsMSIWorklists(ctx, key)
	if e != nil || len(j.Worklists) != 4 || j.Worklists[0].ArchivedAt == 0 {
		t.Fatal("archived outcome lost", e)
	}
}

func TestManagedMSICatalogueIndependentDevicesAndOlderUnusedEntry(t *testing.T) {
	f, g := catalogueStoreFixture(t, false)
	second := additionalSoftwareIdentity(t, fullSoftwareFixture{f: f.fixture, s: f.store, path: f.path, at: f.at}, 2)
	other := f
	other.executor = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{119}, 32))
	g2 := g
	g2.Binding.DeviceID = second.snap.Approval.DeviceID
	g2.Binding.IncarnationDigest = "sha256:" + second.cert.CertificateHash()
	g2.Binding.ExecutorID = id("executor", 14)
	g2.Binding.ExecutorKeyID = msi.Digest(other.executor.Public().(ed25519.PublicKey))
	g2.Binding.DeliveryGrantID = id("grant", 16)
	g2.Binding.InstallGrantID = id("grant", 17)
	key := f.key.Public().(ed25519.PublicKey)
	ctx := context.Background()
	if e := f.store.SetupWindowsMSICatalogueCreateOnly(ctx, key, other.executor.Public().(ed25519.PublicKey), g2, f.at, true); e != nil {
		t.Fatal("additional exact device", e)
	}
	a := catalogueComplete(t, f, catalogueReserve(t, f, 1024, "A"))
	b := catalogueComplete(t, f, catalogueReserve(t, f, 1024, "B"))
	if e := catalogueDeliver(f, g, a, id("transfer", 61)); e != nil {
		t.Fatal(e)
	}
	if e := catalogueDeliver(other, g2, b, id("transfer", 62)); e != nil {
		t.Fatal("unresolved A blocked different device B", e)
	}
	catalogueFinishJob(t, other, g2)
	if e := catalogueDeliver(other, g2, a, id("transfer", 63)); e != nil {
		t.Fatal("unused older A rejected", e)
	}
	r, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, g2.Binding, key)
	if e != nil || r.ArtifactRetiredCount != a.RetiredCount || r.Jobs.Sequence != 2 {
		t.Fatal("older custody lost monotonic job sequence", e)
	}
	ar, e := f.store.ReadWindowsManagedMSIArtifact(msi.WithCatalogueOccurrence(ctx, a.RetiredCount), key)
	if e != nil || len(ar.Assignments) != 2 {
		t.Fatal("original independent assignments", e)
	}
}
