package windowsmutationfence_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"testing"
)

func (p *memoryPayload) Retire(ctx context.Context, r json.RawMessage, final func() error) error {
	if string(r) != `{"object":1,"verified":true}` || p.data == nil {
		return msi.ErrIntegrity
	}
	if p.beforeRetire != nil {
		p.beforeRetire()
	}
	if p.retireError != nil {
		return p.retireError
	}
	if e := final(); e != nil {
		return e
	}
	p.data = nil
	return final()
}
func reusableRetire(t *testing.T, f *pairedDomains) []byte {
	t.Helper()
	r := readMSI(t, f.msiStore)
	result, e := msi.VerifyReport(r.ResultReport, public(f.msiExecutorKey))
	if e != nil || !msi.SettledResult(result) {
		t.Fatal("not settled", e)
	}
	p, e := msi.VerifyPermit(r.Delivery, public(f.msiKey))
	if e != nil {
		t.Fatal(e)
	}
	p.Kind = "retire"
	p.IssuedAt = f.now().Unix()
	p.ExpiresAt = p.IssuedAt + 60
	p.PackageReviewAccepted = true
	p.TermsAccepted = true
	p.RetireResultDigest = msi.Digest(r.ResultReport)
	p.SynchronousReviewDigest = msi.SynchronousReviewDigest(p.Package, p.NativeAcceptanceDigest)
	raw, e := msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func reusableNext(t *testing.T, f *pairedDomains, n uint64) []byte {
	t.Helper()
	ctx := context.Background()
	previous := readMSI(t, f.msiStore)
	p, e := msi.VerifyPermit(previous.Delivery, public(f.msiKey))
	if e != nil {
		t.Fatal(e)
	}
	data := bytes.Repeat([]byte{byte(n)}, 512)
	p.TransferID = id("transfer_", int(n)+100)
	p.JobSequence = n
	p.Package.SHA256 = msi.Digest(data)
	p.Package.Name = "Different inert package"
	p.Package.PackageCode = "{33333333-3333-3333-3333-333333333333}"
	p.IssuedAt = f.now().Unix()
	p.ExpiresAt = p.IssuedAt + 600
	raw, e := msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.endpoint.Accept(ctx, raw); e != nil {
		t.Fatal("next delivery", e)
	}
	if e = f.endpoint.Chunk(ctx, msi.Chunk{TransferID: p.TransferID, Index: 0, PermitDigest: msi.Digest(raw), Digest: msi.Digest(data), Data: data}); e != nil {
		t.Fatal(e)
	}
	p.Kind = "readiness"
	p.Sequence = 1
	p.ExpiresAt = p.IssuedAt + 60
	p.MaintenanceUntil = p.IssuedAt + 600
	p.PackageReviewAccepted = true
	p.TermsAccepted = true
	p.SynchronousReviewDigest = msi.SynchronousReviewDigest(p.Package, p.NativeAcceptanceDigest)
	raw, e = msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.endpoint.Accept(ctx, raw); e != nil {
		t.Fatal(e)
	}
	status, e := f.endpoint.Status(ctx)
	if e != nil {
		t.Fatal(e)
	}
	p.Kind = "install"
	p.ReadinessDigest = msi.Digest(status.Report)
	raw, e = msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestReusableMSISettledRetirementRestartDifferentPackage(t *testing.T) {
	f := newPair(t, true)
	ctx := context.Background()
	grant := f.grant
	original := append([]byte(nil), f.msiPermit...)
	if e := f.endpoint.Accept(ctx, f.msiPermit); e != nil {
		t.Fatal(e)
	}
	f.endpoint.Wait()
	if f.fenceStatus(t).Blocked {
		t.Fatal("exact completion failed to release")
	}
	retire := reusableRetire(t, f)
	if e := f.endpoint.Accept(ctx, retire); e != nil {
		t.Fatal("retirement", e)
	}
	r := readMSI(t, f.msiStore)
	if len(r.RetiredReport) == 0 || f.payload.data != nil {
		t.Fatal("missing durable retirement")
	}
	// Restart both endpoint and shared owner session. Only exact serialized state
	// survives; no native capability or former install permit is reconstructed.
	f.endpoint.Close()
	f.msiSession.Close()
	f.msiSession = f.shared.Session(t, fence.ManagedMSI)
	f.openMSI(t)
	if e := f.endpoint.Accept(ctx, original); e == nil {
		t.Fatal("replayed retired install")
	}
	next := reusableNext(t, f, 2)
	if f.msiNative.calls.Load() != 1 {
		t.Fatal("next package installed without approval")
	}
	if e := f.endpoint.Accept(ctx, next); e != nil {
		t.Fatal(e)
	}
	f.endpoint.Wait()
	r = readMSI(t, f.msiStore)
	if f.msiNative.calls.Load() != 2 || r.Grant != grant || r.Jobs.Sequence != 2 || r.Jobs.RetiredFloor != 1 || len(r.Jobs.Recent) != 1 || r.Jobs.Recent[0].Sequence != 1 || f.fenceStatus(t).Blocked {
		t.Fatal("second independent job failed")
	}
	// The grant-wide sequence, not readiness sequence 1, owns B's shared fence.
	if r.MutationCompletion.Owner.Sequence != 2 {
		t.Fatal("readiness counter used as job counter")
	}
}
func TestReusableMSIUncertainCannotRetireOrAdvance(t *testing.T) {
	f := newPair(t, true)
	f.msiNative.nativeError = errors.New("synthetic unknown cleanup")
	ctx := context.Background()
	if e := f.endpoint.Accept(ctx, f.msiPermit); e != nil {
		t.Fatal(e)
	}
	f.endpoint.Wait()
	r := readMSI(t, f.msiStore)
	p, _ := msi.VerifyPermit(r.Delivery, public(f.msiKey))
	p.Kind = "retire"
	p.ExpiresAt = p.IssuedAt + 60
	p.PackageReviewAccepted = true
	p.TermsAccepted = true
	p.RetireResultDigest = msi.Digest(r.ResultReport)
	p.SynchronousReviewDigest = msi.SynchronousReviewDigest(p.Package, p.NativeAcceptanceDigest)
	raw, e := msi.SignPermit(p, f.msiKey)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.endpoint.Accept(ctx, raw); e == nil {
		t.Fatal("uncertain job retired")
	}
	p.Kind = "deliver"
	p.TransferID = id("transfer_", 200)
	p.JobSequence = 2
	p.PackageReviewAccepted = false
	p.TermsAccepted = false
	p.RetireResultDigest = ""
	p.SynchronousReviewDigest = ""
	raw, _ = msi.SignPermit(p, f.msiKey)
	if e = f.endpoint.Accept(ctx, raw); e == nil {
		t.Fatal("uncertain job advanced")
	}
	if f.payload.data == nil || !f.fenceStatus(t).Blocked || f.msiNative.calls.Load() != 1 {
		t.Fatal("uncertainty lost custody/owner")
	}
}
func TestReusableMSIRetirementBoundedWithoutLifetimeQuota(t *testing.T) {
	f := newPair(t, true)
	ctx := context.Background()
	raw := f.msiPermit
	for i := uint64(1); i <= 36; i++ {
		if i > 1 {
			raw = reusableNext(t, f, i)
		}
		if e := f.endpoint.Accept(ctx, raw); e != nil {
			t.Fatal(i, e)
		}
		f.endpoint.Wait()
		if e := f.endpoint.Accept(ctx, reusableRetire(t, f)); e != nil {
			t.Fatal(i, e)
		}
	}
	r := readMSI(t, f.msiStore)
	if len(r.Jobs.Recent) != msi.MaxRecentJobs || r.Jobs.RetiredFloor != 35 || r.Jobs.Sequence != 36 || f.fenceStatus(t).Retained != 0 {
		t.Fatal("unbounded or reset ledger")
	}
	old, _ := msi.VerifyPermit(f.msiPermit, public(f.msiKey))
	if _, e := f.msiSession.Reserve(ctx, fence.Owner{Domain: fence.ManagedMSI, JobID: old.TransferID, TransferID: old.TransferID, Sequence: old.JobSequence, PermitDigest: msi.Digest(f.msiPermit)}); e == nil {
		t.Fatal("retired fence floor lost")
	}
}

func TestReusableMSIRetirementRechecksCurrentAuthorityAfterWait(t *testing.T) {
	for _, change := range []string{"expiry", "leaf", "revocation", "custody"} {
		t.Run(change, func(t *testing.T) {
			f := newPair(t, true)
			ctx := context.Background()
			if e := f.endpoint.Accept(ctx, f.msiPermit); e != nil {
				t.Fatal(e)
			}
			f.endpoint.Wait()
			retire := reusableRetire(t, f)
			f.payload.beforeRetire = func() {
				switch change {
				case "expiry":
					f.at.Add(61)
				case "leaf":
					f.msiCurrent.LeafDigest = digest("new leaf")
				case "revocation":
					f.msiCurrent.Revoked = true
				}
			}
			if change == "custody" {
				f.payload.retireError = errors.New("synthetic custody replacement")
			}
			if e := f.endpoint.Accept(ctx, retire); e == nil {
				t.Fatal("late authority/custody accepted")
			}
			r := readMSI(t, f.msiStore)
			if len(r.RetiredReport) != 0 || len(r.RetirePermit) == 0 || f.payload.data == nil {
				t.Fatal("unconfirmed retirement lost evidence")
			}
		})
	}
}
