package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	msi "localrmm/internal/windowsmanagedmsi"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// In-memory canonical adapter for protected inert spool fixtures. Real SQLite
// quota/assignment/retirement transactions are tested in enrollmentstore.
type catalogueMemoryStore struct {
	*fleetMemoryStore
	catalogue msi.CatalogueRecord
}

func (s *catalogueMemoryStore) ReadWindowsMSICatalogue(ctx context.Context, _ ed25519.PublicKey) (msi.CatalogueRecord, error) {
	if e := msi.CheckFinal(ctx); e != nil {
		return msi.CatalogueRecord{}, e
	}
	raw, _ := json.Marshal(s.catalogue)
	return msi.DecodeCatalogueRecord(raw)
}
func (s *catalogueMemoryStore) ReadWindowsManagedMSIArtifact(ctx context.Context, key ed25519.PublicKey) (msi.ArtifactRecord, error) {
	c, e := s.ReadWindowsMSICatalogue(ctx, key)
	if e != nil {
		return msi.ArtifactRecord{}, e
	}
	id, ok := msi.CatalogueOccurrence(ctx)
	a := c.Find(id)
	if !ok || a == nil {
		return msi.ArtifactRecord{}, msi.ErrUnavailable
	}
	return *a, nil
}
func (s *catalogueMemoryStore) ReserveWindowsMSICatalogue(ctx context.Context, key ed25519.PublicKey, at time.Time, revision uint64, a msi.Artifact) (msi.CatalogueRecord, error) {
	c, e := s.ReadWindowsMSICatalogue(ctx, key)
	if e != nil {
		return c, e
	}
	if c.Revision != revision || len(c.Entries) >= 4 || c.ReservedBytes()+a.Package.Size > msi.MaxRetainedPayloadBytes {
		return c, msi.ErrConflict
	}
	slot := uint32(len(c.Entries))
	c.Sequence++
	c.Revision++
	a.IntentAt = at.Unix()
	a.PrefixDigest = msi.Digest(nil)
	c.Entries = append(c.Entries, msi.ArtifactRecord{Version: msi.CatalogueArtifactRecordVersion, CatalogueSlot: &slot, RetiredCount: c.Sequence, ClockFloor: at.Unix(), Artifact: &a})
	if c.Validate() != nil {
		return c, msi.ErrIntegrity
	}
	s.catalogue = c
	return c, nil
}
func (s *catalogueMemoryStore) WindowsManagedMSIArtifactTransaction(ctx context.Context, key ed25519.PublicKey, at time.Time, fn func(*msi.ArtifactRecord, time.Time) error) (msi.ArtifactRecord, error) {
	before, e := s.ReadWindowsManagedMSIArtifact(ctx, key)
	if e != nil {
		return before, e
	}
	raw, _ := json.Marshal(before)
	after, _ := msi.DecodeArtifactRecord(raw)
	after.ClockFloor = at.Unix()
	if e = fn(&after, at); e != nil {
		return after, e
	}
	if e = msi.CheckFinal(ctx); e != nil {
		return after, e
	}
	if msi.ArtifactRecordTransition(before, after) != nil {
		return after, msi.ErrIntegrity
	}
	*s.catalogue.Find(after.RetiredCount) = after
	s.catalogue.Revision++
	return after, nil
}
func catalogueManagerFixture(t *testing.T) (*Registry, *catalogueMemoryStore, string, string) {
	t.Helper()
	dir, _ := protectedSpoolFixture(t)
	if e := CreateCatalogueSpool(dir); e != nil {
		t.Fatal(e)
	}
	spool, e := OpenCatalogueSpool(dir)
	if e != nil {
		t.Fatal(e)
	}
	m, store, _, actor, at := managerFixture(t)
	g := store.r.Grant
	g.Version = msi.ReusableGrantVersion
	g.ReusableAcknowledged = true
	g.MutationPlanDigest = msi.Digest([]byte("fresh"))
	g.PeerBindingDigest = msi.Digest([]byte("peer"))
	store.r, e = msi.NewRecord(g, store.r.PublicKey, store.r.ExecutorPublicKey, *at)
	if e != nil {
		t.Fatal(e)
	}
	store.r.Version = msi.CatalogueManagerRecordVersion
	s := &catalogueMemoryStore{fleetMemoryStore: &fleetMemoryStore{members: map[string]*memoryStore{m.binding.DeviceID: store}, now: at}, catalogue: msi.CatalogueRecord{Version: msi.CatalogueRecordVersion, Revision: 1, ClockFloor: *at, Entries: []msi.ArtifactRecord{}}}
	a, e := newArtifactManager(context.Background(), s, store.r.PublicKey, spool, m.now, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	a.deliveryAllowed = func(v string) bool { return v == actor }
	m.store = s
	m.spool = spool
	m.artifact = a
	r, e := NewRegistry([]*Manager{m})
	if e != nil {
		t.Fatal(e)
	}
	return r, s, actor, dir
}
func TestCatalogueProtectedSpoolsKeepIndependentIncompleteCustody(t *testing.T) {
	r, s, actor, dir := catalogueManagerFixture(t)
	ctx := context.Background()
	reserve := func(tag byte, data []byte) context.Context {
		t.Helper()
		sel := managerSelection()
		sel.Name = fmt.Sprintf("Package %c", tag)
		sel.SHA256 = msi.Digest(data)
		if e := r.artifact.ReserveCatalogueUpload(ctx, actor, strconv.FormatUint(s.catalogue.Revision, 10), sel, msi.Digest([]byte("native")), "unverified", msi.Digest([]byte("publisher"))); e != nil {
			t.Fatal(e)
		}
		pin, e := WithArtifactRetiredCount(ctx, strconv.FormatUint(s.catalogue.Sequence, 10))
		if e != nil {
			t.Fatal(e)
		}
		return pin
	}
	broken := inertArtifact()
	broken[0] = 0
	ac := reserve('A', broken)
	if e := r.artifact.Upload(ac, actor, UploadChunk{PackageDigest: msi.Digest(broken), Data: broken, Digest: msi.Digest(broken)}); e == nil {
		t.Fatal("invalid MSI fixture accepted")
	}
	data := inertArtifact()
	data[len(data)-1] = 'B'
	bc := reserve('B', data)
	if e := r.artifact.Upload(bc, actor, UploadChunk{PackageDigest: msi.Digest(data), Data: data, Digest: msi.Digest(data)}); e != nil {
		t.Fatal("A blocked B upload", e)
	}
	if e := r.artifact.CompleteUpload(bc, actor); e != nil {
		t.Fatal("A blocked B complete", e)
	}
	view, e := r.CatalogueView(ctx)
	if e != nil || len(view.Entries) != 2 || view.ReservedBytes != 2048 || view.Entries[0].State != "upload_incomplete" || view.Entries[1].State != "uploaded" {
		t.Fatal("catalogue view", view, e)
	}
	if e = r.artifact.RetireArtifact(bc, actor, view.Entries[1].ArtifactID, true); e != nil {
		t.Fatal("independent B cleanup", e)
	}
	if _, e = os.Stat(filepath.Join(catalogueSpoolPath(dir, 1), artifactName)); !os.IsNotExist(e) {
		t.Fatal("B retained", e)
	}
	if _, e = os.Stat(filepath.Join(catalogueSpoolPath(dir, 0), artifactName)); e != nil {
		t.Fatal("A uncertain custody removed", e)
	}
	view, e = r.CatalogueView(ctx)
	if e != nil || view.ReservedBytes != 1024 || view.Entries[1].State != "retired" {
		t.Fatal("quota after cleanup", e)
	}
	if e = r.artifact.RetireArtifact(ac, actor, view.Entries[1].ArtifactID, true); e == nil {
		t.Fatal("cross-entry retirement accepted")
	}
	spool, e := OpenCatalogueSpool(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = newArtifactManager(ctx, s, r.artifact.key, spool, r.artifact.now, func() error { return nil }); e != nil {
		t.Fatal("restart", e)
	}
}
func TestCatalogueSetupWrappersAndOriginalConsentBytes(t *testing.T) {
	q := SetupRequest{Fleet: true, Reusable: true}
	raw, _ := json.Marshal(q)
	q.Catalogue = true
	if setupRegistryVersion(q) != CatalogueRegistryVersion {
		t.Fatal("catalogue mode")
	}
	q.Scheduled = true
	if setupRegistryVersion(q) != ScheduledCatalogueRegistryVersion || fleetSetupVersion(ScheduledCatalogueConfigVersion) != ScheduledCatalogueSetupPlanVersion {
		t.Fatal("scheduled catalogue mode")
	}
	old, _ := json.Marshal(SetupRequest{Fleet: true, Reusable: true})
	if string(raw) != string(old) {
		t.Fatal("legacy request drift")
	}
	if fleetGrantProfile(CatalogueConfigVersion, msi.Grant{Version: msi.ScheduledGrantVersion}) {
		t.Fatal("scheduled grant silently admitted as manual")
	}
}

func (s *catalogueMemoryStore) WindowsManagedMSITransaction(ctx context.Context, b msi.Binding, key ed25519.PublicKey, at time.Time, fn func(*msi.Record, msi.Current, time.Time) error) (msi.Record, time.Time, error) {
	before := s.members[b.DeviceID].r
	after, when, e := s.fleetMemoryStore.WindowsManagedMSITransaction(ctx, b, key, at, fn)
	if e != nil {
		return after, when, e
	}
	if after.Artifact == nil {
		return after, when, nil
	}
	a := s.catalogue.Find(after.ArtifactRetiredCount)
	if a == nil {
		return after, when, msi.ErrIntegrity
	}
	if after.TransferID != before.TransferID {
		a.Assignments = append(a.Assignments, msi.CatalogueAssignment{Binding: b, TransferID: after.TransferID, JobSequence: after.Jobs.Sequence})
		sort.Slice(a.Assignments, func(i, j int) bool { return a.Assignments[i].Binding.DeviceID < a.Assignments[j].Binding.DeviceID })
	}
	if len(after.RetiredReport) > 0 && len(before.RetiredReport) == 0 {
		assignment := a.Assignment(b)
		assignment.ResultDigest = msi.Digest(after.ResultReport)
		assignment.RetirementDigest = msi.Digest(after.RetiredReport)
	}
	return after, when, nil
}
func TestCatalogueIndependentDeliveryAndOlderUnusedOccurrence(t *testing.T) {
	registry, store, actor, _ := catalogueManagerFixture(t)
	x := registry.ordered[0]
	y := addReusableManagerTarget(t, x, store.fleetMemoryStore)
	y.store = store
	store.members[y.binding.DeviceID].r.Version = msi.CatalogueManagerRecordVersion
	defer y.Close()
	ctx := context.Background()
	contexts := []context.Context{}
	ids := []string{}
	payloads := [][]byte{}
	for _, tag := range []byte{'A', 'B'} {
		data := inertArtifact()
		data[len(data)-1] = tag
		sel := managerSelection()
		sel.Name = string(tag)
		sel.SHA256 = msi.Digest(data)
		if e := registry.artifact.ReserveCatalogueUpload(ctx, actor, strconv.FormatUint(store.catalogue.Revision, 10), sel, msi.Digest([]byte("native")), "unverified", msi.Digest([]byte("publisher"))); e != nil {
			t.Fatal(e)
		}
		pin, _ := WithArtifactRetiredCount(ctx, strconv.FormatUint(store.catalogue.Sequence, 10))
		if e := registry.artifact.Upload(pin, actor, UploadChunk{PackageDigest: sel.SHA256, Data: data, Digest: msi.Digest(data)}); e != nil {
			t.Fatal(e)
		}
		if e := registry.artifact.CompleteUpload(pin, actor); e != nil {
			t.Fatal(e)
		}
		a, _ := registry.artifact.read(pin)
		contexts = append(contexts, pin)
		ids = append(ids, msi.ArtifactIdentity(*a.Artifact))
		payloads = append(payloads, data)
	}
	for i, m := range []*Manager{x, y} {
		if e := m.DeliverArtifact(contexts[i], actor, "transfer_"+strings.Repeat(strconv.Itoa(i+7), 32), true, ids[i], msi.BindingDigest(m.binding)); e != nil {
			t.Fatal("independent delivery", i, e)
		}
		poll, e := m.Poll(ctx)
		if e != nil {
			t.Fatal(e)
		}
		p, _ := msi.VerifyPermit(poll.Permit, m.key.Public().(ed25519.PublicKey))
		chunk, e := m.Chunk(ctx, msi.ChunkRequest{TransferID: p.TransferID, PermitDigest: msi.Digest(poll.Permit), Index: 0})
		if e != nil || !bytes.Equal(chunk.Data, payloads[i]) {
			t.Fatal("wrong selected payload", i, e)
		}
	}
	if e := registry.artifact.RetireArtifact(contexts[0], actor, ids[0], true); e == nil {
		t.Fatal("A unresolved deletion")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	record := store.members[y.binding.DeviceID].r
	delivery := record.DeliveryPermit
	reusableManagerReport(t, y, key, delivery, "delivery", *store.now)
	if e := y.Review(contexts[1], actor, true, true, true, true); e != nil {
		t.Fatal(e)
	}
	poll, e := y.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ready := reusableManagerReport(t, y, key, poll.Permit, "readiness", *store.now)
	reusableManagerReport(t, y, key, delivery, "mutation", *store.now)
	if e = y.Approve(contexts[1], actor, msi.Digest(ready), true); e != nil {
		t.Fatal(e)
	}
	poll, e = y.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	result := reusableManagerReport(t, y, key, poll.Permit, "result", *store.now)
	if e = y.Retire(contexts[1], actor, msi.Digest(result), true); e != nil {
		t.Fatal(e)
	}
	poll, e = y.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	reusableManagerReport(t, y, key, poll.Permit, "retired", *store.now)
	v, e := y.View(contexts[0])
	if e != nil || v.TransferID != "" || v.ArtifactRetiredCount != "1" {
		t.Fatal("older unused A projection", e)
	}
	if e = y.DeliverArtifact(contexts[0], actor, "transfer_"+strings.Repeat("e", 32), true, ids[0], msi.BindingDigest(y.binding)); e != nil {
		t.Fatal("older unused A deliver", e)
	}
	if store.members[y.binding.DeviceID].r.Jobs.Sequence != 2 || store.members[y.binding.DeviceID].r.ArtifactRetiredCount != 1 {
		t.Fatal("grant sequence conflated with custody order")
	}
}
