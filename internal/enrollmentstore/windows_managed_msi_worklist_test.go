package enrollmentstore

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	"strings"
	"testing"
	"time"
)

func savedMSIStoreFixture(t *testing.T, scheduled ...bool) (windowsSoftwareStoreFixture, msi.Grant, msi.Artifact, msi.WorklistDispatch) {
	t.Helper()
	f := newWindowsSoftwareStoreFixture(t, false)
	ctx := context.Background()
	g := managedStoreGrant(f)
	g.Version = msi.ReusableGrantVersion
	g.ReusableAcknowledged = true
	if len(scheduled) > 0 && scheduled[0] {
		g.Version = msi.ScheduledGrantVersion
		g.ScheduledEnabled = true
		g.ScheduledAcknowledged = true
	}
	g.MutationPlanDigest = msi.Digest([]byte("fresh plan"))
	g.PeerBindingDigest = msi.Digest([]byte("peer"))
	key := f.key.Public().(ed25519.PublicKey)
	if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, key, f.executor.Public().(ed25519.PublicKey), g, f.at, false); e != nil {
		t.Fatal(e)
	}
	sel := preparedMSITestSelection()
	sel.Size = 1024
	for step := 0; step < 5; step++ {
		_, e := f.store.WindowsManagedMSIArtifactTransaction(ctx, key, f.at, func(r *msi.ArtifactRecord, at time.Time) error {
			switch step {
			case 0:
				r.Artifact = &msi.Artifact{Package: sel, NativeAcceptanceDigest: msi.Digest([]byte("native")), PublisherStatus: "unverified", PublisherEvidenceDigest: msi.Digest([]byte("publisher")), IntentAt: at.Unix(), PrefixDigest: msi.Digest(nil)}
			case 1:
				r.Artifact.PendingDigest = sel.SHA256
				r.Artifact.PendingSize = int(sel.Size)
			case 2:
				r.Artifact.CustodyDigest = msi.Digest([]byte("original inert custody"))
			case 3:
				r.Artifact.Offset = sel.Size
				r.Artifact.PrefixDigest = sel.SHA256
				r.Artifact.LastChunkDigest = sel.SHA256
				r.Artifact.PendingDigest = ""
				r.Artifact.PendingSize = 0
			case 4:
				r.Artifact.CompletedAt = at.Unix()
			}
			return nil
		})
		if e != nil {
			t.Fatal("artifact", step, e)
		}
	}
	ar, e := f.store.ReadWindowsManagedMSIArtifact(ctx, key)
	if e != nil {
		t.Fatal(e)
	}
	a := *ar.Artifact
	w := msi.Worklist{ID: "worklist_" + strings.Repeat("a", 32), Revision: 1, Name: "Frozen exact package", CreatedBy: "operator_" + strings.Repeat("a", 32), CreatedAt: f.at.Unix(), ArtifactID: msi.ArtifactIdentity(a), Package: a.Package, NativeAcceptanceDigest: a.NativeAcceptanceDigest, PublisherStatus: a.PublisherStatus, PublisherEvidenceDigest: a.PublisherEvidenceDigest, Targets: []msi.WorklistTarget{{Name: "Exact original target", Binding: g.Binding}}, Batches: []msi.WorklistBatch{}}
	_, e = f.store.WindowsMSIWorklistTransaction(ctx, key, f.at, []msi.Binding{g.Binding}, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, _ time.Time) error {
		j.Worklists = append(j.Worklists, w)
		return nil
	})
	if e != nil {
		t.Fatal("save", e)
	}
	q := msi.WorklistRequest{DeviceID: g.Binding.DeviceID, Operation: "deliver", ArtifactID: w.ArtifactID, ArtifactRetiredCount: "0", BindingDigest: msi.BindingDigest(g.Binding), TransferID: "transfer_" + strings.Repeat("c", 32), ExpiresAt: f.at.Unix() + 60}
	b := msi.WorklistBatch{ID: "batch_" + strings.Repeat("b", 32), Kind: "deliver", ActorID: w.CreatedBy, SessionDigest: msi.Digest([]byte("original session")), SessionExpiresAt: f.at.Unix() + 300, CreatedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 60, Acknowledgements: msi.WorklistAcknowledgements{Acknowledged: true}, Items: []msi.WorklistBatchItem{{Request: q, State: "not_dispatched"}}}
	b.ConfirmationDigest = b.Digest()
	_, e = f.store.WindowsMSIWorklistTransaction(ctx, key, f.at, []msi.Binding{g.Binding}, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, _ time.Time) error {
		w := j.Find(w.ID)
		w.Batches = append(w.Batches, b)
		w.Revision++
		return nil
	})
	if e != nil {
		t.Fatal("confirm", e)
	}
	d := msi.WorklistDispatch{Reference: msi.WorklistDispatchReference{WorklistID: w.ID, BatchID: b.ID, Item: 0}, ActorID: b.ActorID, SessionDigest: b.SessionDigest, SessionExpiresAt: b.SessionExpiresAt, Request: q, Acknowledgements: b.Acknowledgements}
	return f, g, a, d
}
func savedMSIDispatch(f windowsSoftwareStoreFixture, g msi.Grant, a msi.Artifact, d msi.WorklistDispatch, ctx context.Context) error {
	_, _, e := f.store.WindowsManagedMSITransaction(msi.WithWorklistDispatch(ctx, d), g.Binding, f.key.Public().(ed25519.PublicKey), f.at, func(r *msi.Record, c msi.Current, at time.Time) error {
		r.Artifact = &a
		r.Jobs.Sequence = 1
		r.TransferID = d.Request.TransferID
		p := msi.PermitForGrant(msi.Permit{Version: msi.Version, Kind: "deliver", TransferID: r.TransferID, Binding: g.Binding, LeafDigest: c.LeafDigest, Package: a.Package, NativeAcceptanceDigest: a.NativeAcceptanceDigest, ActorID: d.ActorID, IssuedAt: at.Unix(), ExpiresAt: min(at.Unix()+86400, g.ExpiresAt, c.LeafNotAfter)}, g, 1, a)
		var e error
		r.DeliveryPermit, e = msi.SignPermit(p, f.key)
		return e
	})
	return e
}
func TestManagedMSIWorklistAtomicIssueRestartAndReplay(t *testing.T) {
	f, g, a, d := savedMSIStoreFixture(t)
	ctx := context.Background()
	key := f.key.Public().(ed25519.PublicKey)
	before, e := f.store.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, key)
	if e != nil || before.TransferID != "" {
		t.Fatal("save/confirm issued permit", e)
	}
	if e = savedMSIDispatch(f, g, a, d, ctx); e != nil {
		t.Fatal("dispatch", e)
	}
	j, e := f.store.ReadWindowsMSIWorklists(ctx, key)
	if e != nil {
		t.Fatal(e)
	}
	w := j.Find(d.Reference.WorklistID)
	if w.Targets[0].TransferID != d.Request.TransferID || w.Targets[0].JobSequence != 1 || w.Batches[0].Items[0].State != "issued" || w.Batches[0].CloseReason != "finished" {
		t.Fatal("missing atomic references", w)
	}
	if e = savedMSIDispatch(f, g, a, d, ctx); e == nil {
		t.Fatal("duplicate permit")
	}
	raw, _ := json.Marshal(j)
	if e = f.store.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(f.path, f.fixture.config, f.fixture.issuerDER)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	j, e = reopened.ReadWindowsMSIWorklists(ctx, key)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := json.Marshal(j)
	if string(raw) != string(after) {
		t.Fatal("reopen changed worklist")
	}
	r, e := reopened.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, key)
	if e != nil || msi.Digest(r.DeliveryPermit) != w.Batches[0].Items[0].PermitDigest {
		t.Fatal("lost response cannot reconcile exact permit", e)
	}
}
func TestManagedMSIWorklistCloseAndFinalFenceDoNotIssue(t *testing.T) {
	for _, mode := range []string{"closed", "session", "expiry", "body"} {
		t.Run(mode, func(t *testing.T) {
			f, g, a, d := savedMSIStoreFixture(t)
			ctx := context.Background()
			key := f.key.Public().(ed25519.PublicKey)
			switch mode {
			case "closed":
				_, e := f.store.WindowsMSIWorklistTransaction(ctx, key, f.at, nil, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, at time.Time) error {
					w := j.Find(d.Reference.WorklistID)
					w.Batches[0].ClosedAt = at.Unix()
					w.Batches[0].CloseReason = "stopped"
					w.Revision++
					return nil
				})
				if e != nil {
					t.Fatal(e)
				}
			case "session":
				ctx = msi.WithFinalCheck(ctx, func() error { return msi.ErrAuthority })
			case "expiry":
				clock := f.at
				ctx = msi.WithFinalCheck(WithOverviewClock(ctx, func() time.Time { return clock }), func() error { clock = clock.Add(time.Minute); return nil })
			case "body":
				d.Request.TransferID = "transfer_" + strings.Repeat("d", 32)
			}
			if e := savedMSIDispatch(f, g, a, d, ctx); e == nil {
				t.Fatal("fenced dispatch issued")
			}
			r, e := f.store.ReadRegisteredWindowsManagedMSI(context.Background(), g.Binding, key)
			if e != nil || len(r.DeliveryPermit) != 0 || r.TransferID != "" {
				t.Fatal("permit escaped rollback", e)
			}
			j, e := f.store.ReadWindowsMSIWorklists(context.Background(), key)
			if e != nil {
				t.Fatal(e)
			}
			if j.Worklists[0].Batches[0].Items[0].State == "issued" {
				t.Fatal("false issued journal")
			}
		})
	}
}
func TestManagedMSIWorklistMissingUsedStateAndLegacyStayClosed(t *testing.T) {
	f, _, _, _ := savedMSIStoreFixture(t)
	key := f.key.Public().(ed25519.PublicKey)
	if _, e := f.store.db.Exec(`DELETE FROM enrollment_windows_msi_worklists`); e != nil {
		t.Fatal(e)
	}
	if _, e := f.store.ReadWindowsMSIWorklists(context.Background(), key); e == nil {
		t.Fatal("missing used journal adopted")
	}
	legacy := newWindowsSoftwareStoreFixture(t, false)
	g := managedStoreGrant(legacy)
	if e := legacy.store.SetupWindowsManagedMSIFleetCreateOnly(context.Background(), legacy.key.Public().(ed25519.PublicKey), legacy.executor.Public().(ed25519.PublicKey), g, legacy.at, false); e != nil {
		t.Fatal(e)
	}
	if _, e := legacy.store.ReadWindowsMSIWorklists(context.Background(), legacy.key.Public().(ed25519.PublicKey)); !errors.Is(e, msi.ErrUnavailable) {
		t.Fatal("legacy promoted", e)
	}
}

func TestManagedMSIWorklistExpiredDispatchCannotReviveAfterClockRollback(t *testing.T) {
	f, g, a, d := savedMSIStoreFixture(t)
	clock := f.at.Add(61 * time.Second)
	ctx := WithOverviewClock(context.Background(), func() time.Time { return clock })
	if e := savedMSIDispatch(f, g, a, d, ctx); e == nil {
		t.Fatal("expired batch issued")
	}
	j, e := f.store.ReadWindowsMSIWorklists(context.Background(), f.key.Public().(ed25519.PublicKey))
	if e != nil || j.ClockFloor < clock.Unix() {
		t.Fatal("lost rejected clock observation", e)
	}
	clock = f.at.Add(30 * time.Second)
	if e = savedMSIDispatch(f, g, a, d, ctx); e == nil {
		t.Fatal("clock rollback revived confirmation")
	}
	r, e := f.store.ReadRegisteredWindowsManagedMSI(context.Background(), g.Binding, f.key.Public().(ed25519.PublicKey))
	if e != nil || r.TransferID != "" || len(r.DeliveryPermit) != 0 {
		t.Fatal("rollback issued permit", e)
	}
}
