package windowsmanagedmsimanager

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"testing"
	"time"
)

type worklistMemoryStore struct {
	*fleetMemoryStore
	journal msi.WorklistJournal
}

func (s *worklistMemoryStore) ReadWindowsMSIWorklists(ctx context.Context, _ ed25519.PublicKey) (msi.WorklistJournal, error) {
	if e := msi.CheckFinal(ctx); e != nil {
		return msi.WorklistJournal{}, e
	}
	raw, _ := json.Marshal(s.journal)
	return msi.DecodeWorklistJournal(raw)
}
func (s *worklistMemoryStore) WindowsMSIWorklistTransaction(ctx context.Context, key ed25519.PublicKey, at time.Time, bindings []msi.Binding, fn func(*msi.WorklistJournal, msi.ArtifactRecord, map[string]msi.Record, time.Time) error) (msi.WorklistJournal, error) {
	j, e := s.ReadWindowsMSIWorklists(ctx, key)
	if e != nil {
		return j, e
	}
	records := map[string]msi.Record{}
	for id, member := range s.members {
		records[id] = member.r
	}
	for _, b := range bindings {
		m := s.members[b.DeviceID]
		if m == nil || m.r.Grant.Binding != b || m.current.Revoked {
			return j, msi.ErrAuthority
		}
		records[b.DeviceID] = m.r
	}
	if e = fn(&j, s.artifact, records, at); e != nil {
		return j, e
	}
	j.Revision++
	j.ClockFloor = at.Unix()
	if e = msi.WorklistJournalTransition(s.journal, j, records); e != nil {
		return j, e
	}
	if e = msi.CheckFinal(ctx); e != nil {
		return j, e
	}
	s.journal = j
	return j, nil
}
func (s *worklistMemoryStore) WindowsManagedMSITransaction(ctx context.Context, b msi.Binding, key ed25519.PublicKey, at time.Time, fn func(*msi.Record, msi.Current, time.Time) error) (msi.Record, time.Time, error) {
	d, batched := msi.WorklistDispatchFrom(ctx)
	if !batched {
		return s.fleetMemoryStore.WindowsManagedMSITransaction(ctx, b, key, at, fn)
	}
	j, e := s.ReadWindowsMSIWorklists(ctx, key)
	if e != nil {
		return msi.Record{}, at, e
	}
	if _, _, _, e = j.Dispatch(d, b, *s.now); e != nil {
		return msi.Record{}, at, e
	}
	before := s.members[b.DeviceID].r
	r, now, e := s.fleetMemoryStore.WindowsManagedMSITransaction(ctx, b, key, at, fn)
	if e != nil {
		return r, now, e
	}
	if e = j.FinishDispatch(d, before, r, *s.now, false); e != nil {
		s.members[b.DeviceID].r = before
		return msi.Record{}, now, e
	}
	s.journal = j
	return r, now, nil
}
func savedManagerFixture(t *testing.T) (*Registry, *Manager, *worklistMemoryStore, ed25519.PrivateKey, string, *int64) {
	t.Helper()
	m, base, key, actor, now, _ := reusableManagerFixture(t)
	s := &worklistMemoryStore{fleetMemoryStore: base, journal: msi.WorklistJournal{Version: msi.WorklistVersion, ManagerID: m.binding.ManagerID, KeyID: m.binding.KeyID, Revision: 1, ClockFloor: *now, Worklists: []msi.Worklist{}}}
	m.store = s
	m.artifact.store = s
	r, e := NewRegistry([]*Manager{m})
	if e != nil {
		t.Fatal(e)
	}
	return r, m, s, key, actor, now
}
func TestManagedMSIWorklistDeliberateStagesAndExactReopen(t *testing.T) {
	r, m, s, key, actor, now := savedManagerFixture(t)
	ctx := context.Background()
	artifact := reusableManagerUpload(t, m, actor, 'A')
	v, e := r.SaveWorklist(ctx, actor, SaveWorklistRequest{Name: "Reviewed fleet", ArtifactID: artifact, ArtifactRetiredCount: "0", Targets: []SaveWorklistTarget{{DeviceID: m.binding.DeviceID, BindingDigest: msi.BindingDigest(m.binding), Name: "Pinned device"}}, Group: msi.WorklistGroup{ID: "group-original", Name: "Original group", Revision: 7}})
	if e != nil {
		t.Fatal("save", e)
	}
	sess := WorklistSession{ActorID: actor, Digest: msi.Digest([]byte("session")), ExpiresAt: *now + 600}
	for _, kind := range []string{"deliver", "review", "approve"} {
		before := s.members[m.binding.DeviceID].r
		preview, e := r.PreviewWorklist(ctx, actor, v.ID, v.Revision, kind)
		if e != nil || len(preview.Items) != 1 {
			t.Fatal("preview", kind, e, preview)
		}
		acks := msi.WorklistAcknowledgements{Acknowledged: true}
		if kind == "review" {
			acks = msi.WorklistAcknowledgements{PackageReviewAccepted: true, TermsAccepted: true, MaintenanceAcknowledged: true, SynchronousReviewAccepted: true}
		}
		v, e = r.ConfirmWorklist(ctx, sess, v.ID, ConfirmWorklistBatch{Revision: v.Revision, Kind: kind, Items: preview.Items, Acknowledgements: acks})
		if e != nil {
			t.Fatal("confirm", kind, e)
		}
		after := s.members[m.binding.DeviceID].r
		if msi.Digest(before.DeliveryPermit) != msi.Digest(after.DeliveryPermit) || msi.Digest(before.ReadinessPermit) != msi.Digest(after.ReadinessPermit) || msi.Digest(before.InstallPermit) != msi.Digest(after.InstallPermit) {
			t.Fatal("confirmation dispatched")
		}
		batch := v.Batches[len(v.Batches)-1]
		q := batch.Items[0].Request
		ref := &msi.WorklistDispatchReference{WorklistID: v.ID, BatchID: batch.ID, Item: 0}
		bad := sess
		bad.Digest = msi.Digest([]byte("new session"))
		if _, e = r.BatchDispatchContext(ctx, bad, ref, q, acks); e == nil {
			t.Fatal("session revived confirmation")
		}
		exact, e := r.BatchDispatchContext(ctx, sess, ref, q, acks)
		if e != nil {
			t.Fatal(e)
		}
		switch kind {
		case "deliver":
			exact, e = WithArtifactRetiredCount(exact, "0")
			if e == nil {
				e = m.DeliverArtifact(exact, actor, q.TransferID, true, artifact, q.BindingDigest)
			}
		case "review":
			exact, e = WithJobOccurrence(exact, "0", q.TransferID, q.JobSequence)
			if e == nil {
				e = m.Review(exact, actor, true, true, true, true)
			}
		case "approve":
			exact, e = WithJobOccurrence(exact, "0", q.TransferID, q.JobSequence)
			if e == nil {
				e = m.Approve(exact, actor, q.ReadinessDigest, true)
			}
		}
		if e != nil {
			t.Fatal("dispatch", kind, e)
		}
		if _, e = r.BatchDispatchContext(ctx, sess, ref, q, acks); e == nil {
			t.Fatal("duplicate dispatch admitted")
		}
		if kind != "approve" {
			poll, e := m.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			report := "delivery"
			if kind == "review" {
				report = "readiness"
			}
			reusableManagerReport(t, m, key, poll.Permit, report, *now)
			if kind == "review" {
				reusableManagerReport(t, m, key, s.members[m.binding.DeviceID].r.DeliveryPermit, "mutation", *now)
			}
		}
		v, e = r.Worklist(ctx, actor, v.ID)
		if e != nil {
			t.Fatal(e)
		}
	}
	if v.Targets[0].TransferID == "" || v.Targets[0].JobSequence != 1 || v.Group.Revision != 7 || v.Rows[0].View == nil || v.Rows[0].View.State != "approved" {
		t.Fatal("lost exact saved state", v)
	}
	// Same content in a new custody occurrence cannot reuse an old worklist.
	s.artifact.RetiredCount = 1 // Only the read projection is exercised here.
	s.artifact.RetiredChain = msi.Digest([]byte("chain"))
	s.artifact.Recent = []msi.RetiredArtifact{{Sequence: 1, ArtifactID: artifact, Package: v.Package, NativeAcceptanceDigest: v.NativeAcceptanceDigest, PublisherStatus: v.PublisherStatus, PublisherEvidenceDigest: v.PublisherEvidenceDigest, EvidenceDigest: msi.Digest([]byte("retired")), ActorID: actor}}
	old, e := r.Worklist(ctx, actor, v.ID)
	if e != nil {
		t.Fatal(e)
	}
	if old.Rows[0].Available {
		t.Fatal("A to B to A rebound old assignment")
	}
}

func TestManagedMSIWorklistCompactionKeepsUnresolvedAndRejectsOldReferences(t *testing.T) {
	r, m, s, _, actor, now := savedManagerFixture(t)
	ctx := context.Background()
	artifact := reusableManagerUpload(t, m, actor, 'A')
	sess := WorklistSession{ActorID: actor, Digest: msi.Digest([]byte("session")), ExpiresAt: *now + 600}
	save := func() WorklistView {
		v, e := r.SaveWorklist(ctx, actor, SaveWorklistRequest{Name: "Exact list", ArtifactID: artifact, ArtifactRetiredCount: "0", Targets: []SaveWorklistTarget{{DeviceID: m.binding.DeviceID, BindingDigest: msi.BindingDigest(m.binding), Name: "Original target"}}})
		if e != nil {
			t.Fatal("save at capacity", e)
		}
		return v
	}
	v := save()
	originalID := v.ID
	var first *msi.WorklistDispatchReference
	var firstRequest msi.WorklistRequest
	for n := 0; n < 12; n++ {
		p, e := r.PreviewWorklist(ctx, actor, v.ID, v.Revision, "deliver")
		if e != nil {
			t.Fatal(e)
		}
		v, e = r.ConfirmWorklist(ctx, sess, v.ID, ConfirmWorklistBatch{Revision: v.Revision, Kind: "deliver", Items: p.Items, Acknowledgements: msi.WorklistAcknowledgements{Acknowledged: true}})
		if e != nil {
			t.Fatal("batch capacity", n, e)
		}
		b := v.Batches[len(v.Batches)-1]
		if first == nil {
			first = &msi.WorklistDispatchReference{WorklistID: v.ID, BatchID: b.ID, Item: 0}
			firstRequest = b.Items[0].Request
		}
		v, e = r.CloseWorklistBatch(ctx, actor, v.ID, v.Revision, b.ID)
		if e != nil {
			t.Fatal(e)
		}
	}
	if len(v.Batches) != msi.MaxWorklistBatches {
		t.Fatal("batch retention bound")
	}
	if _, e := r.BatchDispatchContext(ctx, sess, first, firstRequest, msi.WorklistAcknowledgements{Acknowledged: true}); e == nil {
		t.Fatal("pruned batch revived")
	}
	for n := 0; n < 12; n++ {
		var e error
		v, e = r.ArchiveWorklist(ctx, actor, v.ID, v.Revision)
		if e != nil {
			t.Fatal("archive at capacity", n, e)
		}
		v = save()
	}
	if len(s.journal.Worklists) != msi.MaxWorklists || s.journal.Revision <= 24 {
		t.Fatal("journal bound or counter reset")
	}
	if _, e := r.Worklist(ctx, actor, originalID); e == nil {
		t.Fatal("pruned worklist rediscovered")
	}
	if s.members[m.binding.DeviceID].r.TransferID != "" {
		t.Fatal("metadata compaction issued a job")
	}
	// Once issued, an unresolved delivery cannot be compacted as either a batch
	// or an archived worklist, even if a caller bypasses the manager helper.
	p, e := r.PreviewWorklist(ctx, actor, v.ID, v.Revision, "deliver")
	if e != nil {
		t.Fatal(e)
	}
	v, e = r.ConfirmWorklist(ctx, sess, v.ID, ConfirmWorklistBatch{Revision: v.Revision, Kind: "deliver", Items: p.Items, Acknowledgements: msi.WorklistAcknowledgements{Acknowledged: true}})
	if e != nil {
		t.Fatal(e)
	}
	b := v.Batches[len(v.Batches)-1]
	q := b.Items[0].Request
	ref := &msi.WorklistDispatchReference{WorklistID: v.ID, BatchID: b.ID, Item: 0}
	exact, e := r.BatchDispatchContext(ctx, sess, ref, q, b.Acknowledgements)
	if e != nil {
		t.Fatal(e)
	}
	exact, e = WithArtifactRetiredCount(exact, "0")
	if e != nil {
		t.Fatal(e)
	}
	if e = m.DeliverArtifact(exact, actor, q.TransferID, true, artifact, q.BindingDigest); e != nil {
		t.Fatal(e)
	}
	v, e = r.Worklist(ctx, actor, v.ID)
	if e != nil {
		t.Fatal(e)
	}
	v, e = r.ArchiveWorklist(ctx, actor, v.ID, v.Revision)
	if e != nil {
		t.Fatal(e)
	}
	records := map[string]msi.Record{m.binding.DeviceID: s.members[m.binding.DeviceID].r}
	if msi.WorklistReconciled(v.Worklist, records) || msi.WorklistBatchReconciled(v.Worklist, v.Batches[len(v.Batches)-1], records) {
		t.Fatal("unresolved issued reference treated as reconciled")
	}
	raw, _ := json.Marshal(s.journal)
	next, e := msi.DecodeWorklistJournal(raw)
	if e != nil {
		t.Fatal(e)
	}
	for i, w := range next.Worklists {
		if w.ID == v.ID {
			next.Worklists = append(next.Worklists[:i], next.Worklists[i+1:]...)
			break
		}
	}
	next.Revision++
	if msi.WorklistJournalTransition(s.journal, next, records) == nil {
		t.Fatal("store transition dropped unresolved archived job")
	}
}
