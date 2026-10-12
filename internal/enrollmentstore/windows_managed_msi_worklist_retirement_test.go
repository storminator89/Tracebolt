package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every permit/report uses the real reusable signature and record transitions.
// These are inert metadata fixtures, not a native installer or shared-owner release.
func savedMSIRetirementStoreFixture(t *testing.T) (windowsSoftwareStoreFixture, msi.Grant, msi.WorklistDispatch) {
	t.Helper()
	f, g, a, delivered := savedMSIStoreFixture(t)
	ctx := context.Background()
	key := f.key.Public().(ed25519.PublicKey)
	if err := savedMSIDispatch(f, g, a, delivered, ctx); err != nil {
		t.Fatal("deliver saved assignment", err)
	}
	for _, step := range []string{"claim-delivery", "imported", "review", "claim-readiness", "ready", "approve", "claim-install", "result", "shared-idle"} {
		_, _, err := f.store.WindowsManagedMSITransaction(ctx, g.Binding, key, f.at, func(r *msi.Record, c msi.Current, at time.Time) error {
			var err error
			switch step {
			case "claim-delivery":
				r.DeliveryClaimedAt = at.Unix()
			case "imported":
				r.DeliveryReport, err = savedMSIStoreReport(f, r.DeliveryPermit, "delivery", at.Unix())
			case "review":
				p := msi.PermitForGrant(msi.Permit{Version: msi.Version, Kind: "readiness", TransferID: r.TransferID, Binding: g.Binding, LeafDigest: c.LeafDigest, Package: a.Package, NativeAcceptanceDigest: a.NativeAcceptanceDigest, ActorID: delivered.ActorID, IssuedAt: at.Unix(), ExpiresAt: at.Unix() + 60, Sequence: 1, MaintenanceUntil: at.Unix() + 600, PackageReviewAccepted: true, TermsAccepted: true, SynchronousReviewDigest: msi.SynchronousReviewDigest(a.Package, a.NativeAcceptanceDigest)}, g, r.Jobs.Sequence, a)
				r.ReadinessPermit, err = msi.SignPermit(p, f.key)
			case "claim-readiness":
				r.ReadinessClaimedAt = at.Unix()
			case "ready":
				r.ReadinessReport, err = savedMSIStoreReport(f, r.ReadinessPermit, "readiness", at.Unix())
			case "approve":
				p, e := msi.VerifyPermit(r.ReadinessPermit, key)
				if e != nil {
					return e
				}
				p.Kind = "install"
				p.ReadinessDigest = msi.Digest(r.ReadinessReport)
				r.InstallPermit, err = msi.SignPermit(p, f.key)
			case "claim-install":
				r.InstallClaimedAt = at.Unix()
			case "result":
				r.ResultReport, err = savedMSIStoreReport(f, r.InstallPermit, "result", at.Unix())
			case "shared-idle":
				r.MutationReport, err = savedMSIStoreReport(f, r.DeliveryPermit, "mutation", at.Unix())
			}
			return err
		})
		if err != nil {
			t.Fatal(step, err)
		}
	}
	r, err := f.store.ReadRegisteredWindowsManagedMSI(ctx, g.Binding, key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := msi.VerifyReport(r.ResultReport, f.executor.Public().(ed25519.PublicKey))
	if err != nil || !msi.SettledResult(result) {
		t.Fatal("fixture did not settle signed result", err)
	}
	q := delivered.Request
	q.Operation = "retire"
	q.JobSequence = "1"
	q.ResultDigest = msi.Digest(r.ResultReport)
	b := msi.WorklistBatch{ID: "batch_" + strings.Repeat("e", 32), Kind: "retire", ActorID: delivered.ActorID, SessionDigest: delivered.SessionDigest, SessionExpiresAt: delivered.SessionExpiresAt, CreatedAt: f.at.Unix(), ExpiresAt: q.ExpiresAt, Acknowledgements: msi.WorklistAcknowledgements{Acknowledged: true}, Items: []msi.WorklistBatchItem{{Request: q, State: "not_dispatched"}}}
	b.ConfirmationDigest = b.Digest()
	_, err = f.store.WindowsMSIWorklistTransaction(ctx, key, f.at, []msi.Binding{g.Binding}, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, _ time.Time) error {
		w := j.Find(delivered.Reference.WorklistID)
		w.Batches = append(w.Batches, b)
		w.Revision++
		return nil
	})
	if err != nil {
		t.Fatal("confirm exact retirement", err)
	}
	d := delivered
	d.Reference.BatchID = b.ID
	d.Request = q
	d.Acknowledgements = b.Acknowledgements
	return f, g, d
}

func savedMSIStoreReport(f windowsSoftwareStoreFixture, raw []byte, kind string, now int64) ([]byte, error) {
	p, err := msi.VerifyPermit(raw, f.key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	r := msi.Report{Version: p.Version, JobSequence: p.JobSequence, Kind: kind, Binding: p.Binding, TransferID: p.TransferID, PermitDigest: msi.Digest(raw), Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: now, Offset: p.Package.Size}
	switch kind {
	case "delivery":
		r.State = "imported"
	case "readiness":
		r.State = "ready"
		r.Readiness = &msi.Readiness{Selection: p.Package, CapturedAt: now, PackageVerified: msi.Yes, MachineAbsent: msi.Yes, InstallerBusy: msi.No, NativeAcceptance: msi.Yes, PackageReviewAccepted: msi.Yes, MaintenanceWindowEnd: p.MaintenanceUntil}
	case "result":
		r.State = "succeeded"
		r.Result = &msi.Result{JobID: "software_" + strings.TrimPrefix(p.TransferID, "transfer_"), EnvelopeDigest: msi.Digest(raw), Attempted: true, Outcome: "succeeded", ReturnCodeKnown: true, RegistrationVerified: msi.Yes, CompletedAt: now}
	case "mutation":
		r.State = "idle"
		r.Mutation = &fence.Status{Active: true, Phase: "idle", Revision: 10, Retained: 0}
	case "retired":
		r.State = "retired"
		r.Retirement = &msi.RetirementEvidence{ResultDigest: p.RetireResultDigest, ReleaseDigest: msi.Digest([]byte("inert exact release receipt")), CustodyDigest: msi.Digest([]byte("inert exact import custody"))}
	}
	return msi.SignReport(r, f.executor)
}

func savedMSIRetirementDispatch(f windowsSoftwareStoreFixture, g msi.Grant, d msi.WorklistDispatch, ctx context.Context, alter func(*msi.Permit)) error {
	_, _, err := f.store.WindowsManagedMSITransaction(msi.WithWorklistDispatch(ctx, d), g.Binding, f.key.Public().(ed25519.PublicKey), f.at, func(r *msi.Record, c msi.Current, at time.Time) error {
		p := msi.PermitForGrant(msi.Permit{Version: msi.ReusableVersion, Kind: "retire", TransferID: r.TransferID, Binding: g.Binding, LeafDigest: c.LeafDigest, Package: r.Artifact.Package, NativeAcceptanceDigest: r.Artifact.NativeAcceptanceDigest, ActorID: d.ActorID, IssuedAt: at.Unix(), ExpiresAt: min(at.Unix()+60, g.ExpiresAt, c.LeafNotAfter), PackageReviewAccepted: true, TermsAccepted: true, RetireResultDigest: d.Request.ResultDigest, SynchronousReviewDigest: msi.SynchronousReviewDigest(r.Artifact.Package, r.Artifact.NativeAcceptanceDigest)}, g, r.Jobs.Sequence, *r.Artifact)
		if alter != nil {
			alter(&p)
		}
		var err error
		r.RetirePermit, err = msi.SignPermit(p, f.key)
		return err
	})
	return err
}

func savedMSIRetirementState(t *testing.T, f windowsSoftwareStoreFixture, g msi.Grant) (msi.Record, msi.WorklistJournal) {
	t.Helper()
	key := f.key.Public().(ed25519.PublicKey)
	r, err := f.store.ReadRegisteredWindowsManagedMSI(context.Background(), g.Binding, key)
	if err != nil {
		t.Fatal(err)
	}
	j, err := f.store.ReadWindowsMSIWorklists(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return r, j
}

func TestManagedMSIWorklistRetirementAtomicIssueRestartAndReplay(t *testing.T) {
	f, g, d := savedMSIRetirementStoreFixture(t)
	ctx := context.Background()
	before, _ := savedMSIRetirementState(t, f, g)
	if len(before.RetirePermit) != 0 || before.RetireClaimedAt != 0 || len(before.RetiredReport) != 0 {
		t.Fatal("confirmation issued or performed retirement")
	}
	if err := savedMSIRetirementDispatch(f, g, d, ctx, nil); err != nil {
		t.Fatal("retirement dispatch", err)
	}
	r, j := savedMSIRetirementState(t, f, g)
	w := j.Find(d.Reference.WorklistID)
	batch := w.Batches[len(w.Batches)-1]
	item := batch.Items[0]
	p, err := msi.VerifyPermit(r.RetirePermit, f.key.Public().(ed25519.PublicKey))
	if err != nil || p.Kind != "retire" || p.RetireResultDigest != d.Request.ResultDigest || p.RetireResultDigest != msi.Digest(before.ResultReport) || p.TransferID != d.Request.TransferID || p.JobSequence != 1 {
		t.Fatal("retirement permit lost exact result/job binding", err)
	}
	if item.Request != d.Request || item.State != "issued" || item.PermitDigest != msi.Digest(r.RetirePermit) || item.JobSequence != p.JobSequence || item.IssuedAt != p.IssuedAt || batch.CloseReason != "finished" || batch.ClosedAt != f.at.Unix() || w.Targets[0].TransferID != p.TransferID || w.Targets[0].JobSequence != p.JobSequence {
		t.Fatal("permit and journal did not commit together")
	}
	if !bytes.Equal(before.ResultReport, r.ResultReport) || !reflect.DeepEqual(before.Jobs, r.Jobs) || r.RetireClaimedAt != 0 || len(r.RetiredReport) != 0 || msi.WorklistBatchReconciled(*w, batch, map[string]msi.Record{g.Binding.DeviceID: r}) {
		t.Fatal("issued permit fabricated retirement or advanced original job evidence")
	}
	if err := savedMSIRetirementDispatch(f, g, d, ctx, nil); err == nil {
		t.Fatal("duplicate retirement dispatch admitted")
	}
	after, replay := savedMSIRetirementState(t, f, g)
	if !reflect.DeepEqual(r, after) || !reflect.DeepEqual(j, replay) {
		t.Fatal("duplicate retirement changed committed evidence")
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(f.path, f.fixture.config, f.fixture.issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	f.store = reopened
	after, replay = savedMSIRetirementState(t, f, g)
	if !reflect.DeepEqual(r, after) || !reflect.DeepEqual(j, replay) {
		t.Fatal("GET after reopen did not reconcile exact lost response")
	}
	if err := savedMSIRetirementDispatch(f, g, d, ctx, nil); err == nil {
		t.Fatal("restart replay issued retirement")
	}
}

func TestManagedMSIWorklistRetirementPinsStopAndFinalFence(t *testing.T) {
	for _, mode := range []string{"stopped", "result", "occurrence", "artifact", "transfer", "job", "binding", "actor", "session", "session-expiry", "acknowledgement", "final-session", "final-expiry", "permit-result"} {
		t.Run(mode, func(t *testing.T) {
			f, g, d := savedMSIRetirementStoreFixture(t)
			ctx := context.Background()
			var alter func(*msi.Permit)
			switch mode {
			case "stopped":
				_, err := f.store.WindowsMSIWorklistTransaction(ctx, f.key.Public().(ed25519.PublicKey), f.at, nil, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, at time.Time) error {
					w := j.Find(d.Reference.WorklistID)
					b := &w.Batches[len(w.Batches)-1]
					b.ClosedAt, b.CloseReason = at.Unix(), "stopped"
					w.Revision++
					return nil
				})
				if err != nil {
					t.Fatal("stop", err)
				}
			case "result":
				d.Request.ResultDigest = msi.Digest([]byte("another settled result"))
			case "occurrence":
				d.Request.ArtifactRetiredCount = "1"
			case "artifact":
				d.Request.ArtifactID = msi.Digest([]byte("another reviewed artifact"))
			case "transfer":
				d.Request.TransferID = "transfer_" + strings.Repeat("f", 32)
			case "job":
				d.Request.JobSequence = "2"
			case "binding":
				d.Request.BindingDigest = msi.Digest([]byte("another target binding"))
			case "actor":
				d.ActorID = "operator_" + strings.Repeat("f", 32)
			case "session":
				d.SessionDigest = msi.Digest([]byte("another session"))
			case "session-expiry":
				d.SessionExpiresAt++
			case "acknowledgement":
				d.Acknowledgements.Acknowledged = false
			case "final-session":
				ctx = msi.WithFinalCheck(ctx, func() error { return msi.ErrAuthority })
			case "final-expiry":
				clock := f.at
				ctx = msi.WithFinalCheck(WithOverviewClock(ctx, func() time.Time { return clock }), func() error { clock = time.Unix(d.Request.ExpiresAt, 0); return nil })
			case "permit-result":
				alter = func(p *msi.Permit) { p.RetireResultDigest = msi.Digest([]byte("substituted signed result")) }
			}
			before, journal := savedMSIRetirementState(t, f, g)
			if err := savedMSIRetirementDispatch(f, g, d, ctx, alter); err == nil {
				t.Fatal("fenced retirement issued")
			}
			after, next := savedMSIRetirementState(t, f, g)
			if !reflect.DeepEqual(before, after) || len(after.RetirePermit) != 0 || len(after.RetiredReport) != 0 {
				t.Fatal("fenced permit escaped transaction rollback")
			}
			w := next.Find(d.Reference.WorklistID)
			item := w.Batches[len(w.Batches)-1].Items[0]
			if item.State == "issued" || item.PermitDigest != "" || item.IssuedAt != 0 || item.JobSequence != 0 || !reflect.DeepEqual(w.Targets, journal.Find(d.Reference.WorklistID).Targets) {
				t.Fatal("journal retained false issued retirement")
			}
			if mode == "final-expiry" && next.ClockFloor < d.Request.ExpiresAt {
				t.Fatal("final expiry observation was lost")
			}
			if mode == "stopped" && !reflect.DeepEqual(journal, next) {
				t.Fatal("late dispatch changed stopped retirement batch")
			}
		})
	}
}

func TestManagedMSIWorklistRetirementExpiredDispatchCannotRevive(t *testing.T) {
	f, g, d := savedMSIRetirementStoreFixture(t)
	clock := time.Unix(d.Request.ExpiresAt, 0)
	ctx := WithOverviewClock(context.Background(), func() time.Time { return clock })
	if err := savedMSIRetirementDispatch(f, g, d, ctx, nil); err == nil {
		t.Fatal("expired retirement batch issued")
	}
	before, journal := savedMSIRetirementState(t, f, g)
	if journal.ClockFloor < clock.Unix() {
		t.Fatal("expired retirement observation was lost")
	}
	clock = f.at.Add(30 * time.Second)
	if err := savedMSIRetirementDispatch(f, g, d, ctx, nil); !errors.Is(err, msi.ErrExpired) {
		t.Fatal("clock rollback revived retirement", err)
	}
	after, next := savedMSIRetirementState(t, f, g)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(journal, next) || len(after.RetirePermit) != 0 {
		t.Fatal("rollback changed exact job or retirement journal")
	}
}

func TestManagedMSIWorklistRetirementCompactionRequiresSignedReceipt(t *testing.T) {
	f, g, d := savedMSIRetirementStoreFixture(t)
	ctx := context.Background()
	key := f.key.Public().(ed25519.PublicKey)
	if err := savedMSIRetirementDispatch(f, g, d, ctx, nil); err != nil {
		t.Fatal(err)
	}
	compact := func() error {
		_, err := f.store.WindowsMSIWorklistTransaction(ctx, key, f.at, nil, func(j *msi.WorklistJournal, _ msi.ArtifactRecord, _ map[string]msi.Record, _ time.Time) error {
			w := j.Find(d.Reference.WorklistID)
			w.Batches = w.Batches[:len(w.Batches)-1]
			w.Revision++
			return nil
		})
		return err
	}
	if err := compact(); err == nil {
		t.Fatal("permit alone allowed retirement batch compaction")
	}
	for _, claim := range []bool{true, false} {
		_, _, err := f.store.WindowsManagedMSITransaction(ctx, g.Binding, key, f.at, func(r *msi.Record, _ msi.Current, at time.Time) error {
			if claim {
				r.RetireClaimedAt = at.Unix()
				return nil
			}
			var err error
			r.RetiredReport, err = savedMSIStoreReport(f, r.RetirePermit, "retired", at.Unix())
			return err
		})
		if err != nil {
			t.Fatal("record inert signed retirement evidence", err)
		}
		if claim && compact() == nil {
			t.Fatal("claim alone allowed retirement batch compaction")
		}
	}
	before, journal := savedMSIRetirementState(t, f, g)
	w := journal.Find(d.Reference.WorklistID)
	if !msi.WorklistBatchReconciled(*w, w.Batches[len(w.Batches)-1], map[string]msi.Record{g.Binding.DeviceID: before}) {
		t.Fatal("exact signed retirement did not reconcile")
	}
	if err := compact(); err != nil {
		t.Fatal("verified retirement did not allow compaction", err)
	}
	after, next := savedMSIRetirementState(t, f, g)
	if !reflect.DeepEqual(before, after) || len(next.Find(d.Reference.WorklistID).Batches) != 1 || !reflect.DeepEqual(w.Targets, next.Find(d.Reference.WorklistID).Targets) {
		t.Fatal("compaction changed original job or target evidence")
	}
	artifact, err := f.store.ReadWindowsManagedMSIArtifact(ctx, key)
	if err != nil || artifact.Artifact == nil || artifact.RetiredCount != 0 {
		t.Fatal("device retirement retired shared payload", err)
	}
}
