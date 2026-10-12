package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	msi "localrmm/internal/windowsmanagedmsi"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFleetScheduledMSIStoreAtomicIntentJournalAndRestart(t *testing.T) {
	for _, catalogue := range []bool{false, true} {
		t.Run(map[bool]string{false: "singleton", true: "catalogue"}[catalogue], func(t *testing.T) {
			var f windowsSoftwareStoreFixture
			var g msi.Grant
			if catalogue {
				f, g = newCatalogueScheduleBaseline(t)
			} else {
				f, g = newManagedScheduledStoreFixture(t, true)
			}
			ctx := context.Background()
			key := f.key.Public().(ed25519.PublicKey)
			r, j := savedMSIRetirementState(t, f, g)
			w := j.Worklists[0]
			if catalogue {
				ctx = msi.WithCatalogueOccurrence(ctx, w.ArtifactRetiredCount)
			}
			var originalCatalogue msi.CatalogueRecord
			if catalogue {
				var err error
				originalCatalogue, err = f.store.ReadWindowsMSICatalogue(ctx, key)
				if err != nil {
					t.Fatal(err)
				}
			}
			ack := msi.WorklistAcknowledgements{PackageReviewAccepted: true, TermsAccepted: true, SynchronousReviewAccepted: true, ServiceRiskAccepted: true, ScheduleAccepted: true}
			q := msi.WorklistRequest{DeviceID: g.Binding.DeviceID, Operation: "schedule", ArtifactID: w.ArtifactID, ArtifactRetiredCount: strconv.FormatUint(w.ArtifactRetiredCount, 10), BindingDigest: msi.BindingDigest(g.Binding), TransferID: r.TransferID, JobSequence: "1", ReadinessDigest: msi.Digest(r.ReadinessReport), ExpiresAt: f.at.Unix() + 60, StartAt: f.at.Unix() + 120, EndAt: f.at.Unix() + 300}
			batch := msi.WorklistBatch{ID: "batch_" + strings.Repeat("d", 32), Kind: "schedule", ActorID: w.CreatedBy, SessionDigest: msi.Digest([]byte("schedule session")), SessionExpiresAt: f.at.Unix() + 300, CreatedAt: f.at.Unix(), ExpiresAt: q.ExpiresAt, Acknowledgements: ack, Items: []msi.WorklistBatchItem{{Request: q, State: "not_dispatched"}}}
			batch.ConfirmationDigest = batch.Digest()
			_, e := f.store.WindowsMSIWorklistTransaction(ctx, key, f.at, []msi.Binding{g.Binding}, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, _ time.Time) error {
				w := j.Find(w.ID)
				w.Batches = append(w.Batches, batch)
				w.Revision++
				return nil
			})
			if e != nil {
				t.Fatal("confirm schedule", e)
			}
			dispatch := msi.WorklistDispatch{Reference: msi.WorklistDispatchReference{WorklistID: w.ID, BatchID: batch.ID, Item: 0}, ActorID: batch.ActorID, SessionDigest: batch.SessionDigest, SessionExpiresAt: batch.SessionExpiresAt, Request: q, Acknowledgements: ack}
			apply := func(ctx context.Context) error {
				_, _, e := f.store.WindowsManagedMSITransaction(ctx, g.Binding, key, f.at, func(r *msi.Record, c msi.Current, at time.Time) error {
					request, e := q.ScheduleRequest(ack)
					if e != nil {
						return e
					}
					a := msi.ScheduleApproval{Version: msi.ScheduleVersion, Request: request, RequestDigest: msi.ScheduleRequestDigest(request), ActorID: batch.ActorID, ApprovedAt: at.Unix(), GrantDigest: msi.GrantDigest(g), LeafDigest: c.LeafDigest, LeafExpiresAt: c.LeafNotAfter, BaselinePermitDigest: msi.Digest(r.ReadinessPermit)}
					a.Digest = a.CanonicalDigest()
					r.Schedule = &msi.ScheduledIntent{Approval: a, BaselinePermit: bytes.Clone(r.ReadinessPermit), BaselineReport: bytes.Clone(r.ReadinessReport), State: "scheduled"}
					return nil
				})
				return e
			}
			if e = apply(msi.WithWorklistDispatch(ctx, dispatch)); e != nil {
				t.Fatal("dispatch", e)
			}
			before, journal := savedMSIRetirementState(t, f, g)
			item := journal.Worklists[0].Batches[len(journal.Worklists[0].Batches)-1].Items[0]
			if before.Schedule == nil || len(before.InstallPermit) != 0 || item.State != "scheduled" || item.ScheduleDigest != before.Schedule.Approval.Digest || item.PermitDigest != "" {
				t.Fatal("intent/journal not atomic")
			}
			if e = f.store.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := Open(f.path, f.fixture.config, f.fixture.issuerDER)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			f.store = reopened
			after, saved := savedMSIRetirementState(t, f, g)
			if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(journal, saved) {
				t.Fatal("restart changed authority")
			}
			if e = apply(msi.WithWorklistDispatch(ctx, dispatch)); e == nil {
				t.Fatal("issued schedule replay")
			}

			if catalogue {
				afterCatalogue, err := f.store.ReadWindowsMSICatalogue(ctx, key)
				if err != nil || !reflect.DeepEqual(originalCatalogue, afterCatalogue) || len(afterCatalogue.Entries) != 2 || afterCatalogue.ReservedBytes() != 3072 {
					t.Fatal("schedule changed package custody/quota", err)
				}
			}
		})
	}
}

func TestFleetScheduledMSIStoreRejectsWindowBeyondOriginalLeaf(t *testing.T) {
	f, g := newManagedScheduledStoreFixture(t, true)
	ctx := context.Background()
	key := f.key.Public().(ed25519.PublicKey)
	r, j := savedMSIRetirementState(t, f, g)
	w := j.Worklists[0]
	q := msi.WorklistRequest{DeviceID: g.Binding.DeviceID, Operation: "schedule", ArtifactID: w.ArtifactID, ArtifactRetiredCount: "0", BindingDigest: msi.BindingDigest(g.Binding), TransferID: r.TransferID, JobSequence: "1", ReadinessDigest: msi.Digest(r.ReadinessReport), ExpiresAt: f.at.Unix() + 60, StartAt: f.snapshot.Intent.NotAfter - 30, EndAt: f.snapshot.Intent.NotAfter + 30}
	batch := msi.WorklistBatch{ID: "batch_" + strings.Repeat("d", 32), Kind: "schedule", ActorID: w.CreatedBy, SessionDigest: msi.Digest([]byte("schedule session")), SessionExpiresAt: f.at.Unix() + 300, CreatedAt: f.at.Unix(), ExpiresAt: q.ExpiresAt, Acknowledgements: msi.WorklistAcknowledgements{PackageReviewAccepted: true, TermsAccepted: true, SynchronousReviewAccepted: true, ServiceRiskAccepted: true, ScheduleAccepted: true}, Items: []msi.WorklistBatchItem{{Request: q, State: "not_dispatched"}}}
	batch.ConfirmationDigest = batch.Digest()
	_, e := f.store.WindowsMSIWorklistTransaction(ctx, key, f.at, []msi.Binding{g.Binding}, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, _ time.Time) error {
		w := j.Find(w.ID)
		w.Batches = append(w.Batches, batch)
		w.Revision++
		return nil
	})
	if e == nil {
		t.Fatal("beyond-leaf confirmation retained")
	}
	after, saved := savedMSIRetirementState(t, f, g)
	if !reflect.DeepEqual(r, after) || !reflect.DeepEqual(j, saved) {
		t.Fatal("rejected review changed intent/history")
	}
}

// The catalogue path retains another incomplete package while the selected exact
// occurrence is scheduled. It shares the original quota and delivery ledger.
func newCatalogueScheduleBaseline(t *testing.T) (windowsSoftwareStoreFixture, msi.Grant) {
	t.Helper()
	f, g := catalogueStoreFixture(t, true)
	key := f.key.Public().(ed25519.PublicKey)
	selected := catalogueComplete(t, f, catalogueReserve(t, f, 1024, "selected scheduled package"))
	catalogueReserve(t, f, 2048, "independent incomplete package")
	ctx := msi.WithCatalogueOccurrence(context.Background(), selected.RetiredCount)
	if e := catalogueDeliver(f, g, selected, "transfer_"+strings.Repeat("c", 32)); e != nil {
		t.Fatal(e)
	}
	actor := "operator_" + strings.Repeat("a", 32)
	a := *selected.Artifact
	w := msi.Worklist{ID: "worklist_" + strings.Repeat("a", 32), Revision: 1, Name: "Selected catalogue occurrence", CreatedBy: actor, CreatedAt: f.at.Unix(), ArtifactID: msi.ArtifactIdentity(a), ArtifactRetiredCount: selected.RetiredCount, Package: a.Package, NativeAcceptanceDigest: a.NativeAcceptanceDigest, PublisherStatus: a.PublisherStatus, PublisherEvidenceDigest: a.PublisherEvidenceDigest, Targets: []msi.WorklistTarget{{Name: "Exact target", Binding: g.Binding, TransferID: "transfer_" + strings.Repeat("c", 32), JobSequence: 1}}, Batches: []msi.WorklistBatch{}}
	if _, e := f.store.WindowsMSIWorklistTransaction(ctx, key, f.at, []msi.Binding{g.Binding}, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, _ time.Time) error {
		j.Worklists = append(j.Worklists, w)
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	for _, step := range []string{"claim-delivery", "imported", "review", "claim-readiness", "ready"} {
		_, _, e := f.store.WindowsManagedMSITransaction(ctx, g.Binding, key, f.at, func(r *msi.Record, c msi.Current, at time.Time) error {
			var e error
			switch step {
			case "claim-delivery":
				r.DeliveryClaimedAt = at.Unix()
			case "imported":
				r.DeliveryReport, e = savedMSIStoreReport(f, r.DeliveryPermit, "delivery", at.Unix())
			case "review":
				p := msi.PermitForGrant(msi.Permit{Version: msi.Version, Kind: "readiness", TransferID: r.TransferID, Binding: g.Binding, LeafDigest: c.LeafDigest, Package: a.Package, NativeAcceptanceDigest: a.NativeAcceptanceDigest, ActorID: actor, IssuedAt: at.Unix(), ExpiresAt: at.Unix() + 60, Sequence: 1, MaintenanceUntil: at.Unix() + 600, PackageReviewAccepted: true, TermsAccepted: true, SynchronousReviewDigest: msi.SynchronousReviewDigest(a.Package, a.NativeAcceptanceDigest)}, g, r.Jobs.Sequence, a)
				r.ReadinessPermit, e = msi.SignPermit(p, f.key)
			case "claim-readiness":
				r.ReadinessClaimedAt = at.Unix()
			case "ready":
				r.ReadinessReport, e = savedMSIStoreReport(f, r.ReadinessPermit, "readiness", at.Unix())
			}
			return e
		})
		if e != nil {
			t.Fatal(step, e)
		}
	}
	return f, g
}
