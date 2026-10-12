package windowsmanagedmsi

import (
	"bytes"
	"context"
	"encoding/json"
)

// Retire removes only custody proved by this exact app-created import receipt.
// Implementations revalidate pinned object identity and final authority after
// every wait, delete by handle, and fail closed after any uncertain side effect.
type RetirablePayload interface {
	Retire(context.Context, json.RawMessage, func() error) error
}

func (r EndpointRecord) validateReusableEndpoint() error {
	if !r.Grant.Reusable() {
		if (r.Version == ReusableEndpointVersion || r.Version == ScheduledEndpointVersion) || r.Jobs != nil || len(r.RetirePermit)+len(r.RetiredReport) > 0 {
			return ErrIntegrity
		}
		return nil
	}
	if (r.Version != ReusableEndpointVersion && r.Version != ScheduledEndpointVersion) || (r.Version == ScheduledEndpointVersion) != r.Grant.Scheduled() || r.Jobs.Validate() != nil {
		return ErrIntegrity
	}
	if len(r.Delivery) == 0 {
		if r.Jobs.Sequence != 0 || len(r.RetirePermit)+len(r.RetiredReport) > 0 {
			return ErrIntegrity
		}
		return nil
	}
	p, e := VerifyPermit(r.Delivery, r.ManagerPublicKey)
	if e != nil || p.Version != GrantWire(r.Grant) || p.JobSequence != r.Jobs.Sequence {
		return ErrIntegrity
	}
	for _, raw := range [][]byte{r.DeliveryReport, r.ReadinessReport, r.ResultReport, r.InterventionReport} {
		if len(raw) == 0 {
			continue
		}
		v, e := VerifyReport(raw, r.ExecutorPublicKey)
		if e != nil || v.Version != p.Version || v.JobSequence != p.JobSequence {
			return ErrIntegrity
		}
	}
	if len(r.RetirePermit) == 0 {
		if len(r.RetiredReport) > 0 {
			return ErrIntegrity
		}
		return nil
	}
	q, e := VerifyPermit(r.RetirePermit, r.ManagerPublicKey)
	v, re := VerifyReport(r.ResultReport, r.ExecutorPublicKey)
	if e != nil || re != nil || q.Kind != "retire" || !samePackage(p, q) || q.RetireResultDigest != Digest(r.ResultReport) || !SettledResult(v) || r.MutationCompletion == nil || q.IssuedAt < v.CapturedAt || q.IssuedAt > r.ClockFloor || q.ExpiresAt > r.Grant.ExpiresAt {
		return ErrIntegrity
	}
	if len(r.RetiredReport) > 0 {
		v, e := VerifyReport(r.RetiredReport, r.ExecutorPublicKey)
		receipt, _ := json.Marshal(r.MutationCompletion)
		if e != nil || v.Kind != "retired" || v.Binding != p.Binding || v.TransferID != p.TransferID || v.Package != p.Package || v.NativeAcceptanceDigest != p.NativeAcceptanceDigest || v.JobSequence != p.JobSequence || v.PermitDigest != Digest(r.RetirePermit) || v.Retirement.ResultDigest != q.RetireResultDigest || v.Retirement.ReleaseDigest != Digest(receipt) || v.Retirement.CustodyDigest != Digest(r.ImportReceipt) || v.CapturedAt < q.IssuedAt || v.CapturedAt >= q.ExpiresAt || v.CapturedAt > r.ClockFloor {
			return ErrIntegrity
		}
	}
	return nil
}
func (x *Endpoint) beginNextJob(p Permit) error {
	if !x.record.Grant.Reusable() || x.record.Jobs.Validate() != nil || x.running {
		return ErrConsumed
	}
	var j *JobLedger
	if len(x.record.Delivery) == 0 {
		j = NewJobLedger()
		j.Sequence = 1
	} else {
		if len(x.record.RetiredReport) == 0 {
			return ErrConsumed
		}
		old, _ := VerifyPermit(x.record.Delivery, x.record.ManagerPublicKey)
		result, _ := VerifyReport(x.record.ResultReport, x.record.ExecutorPublicKey)
		retired, _ := VerifyReport(x.record.RetiredReport, x.record.ExecutorPublicKey)
		var e error
		j, e = AdvanceJobLedger(x.record.Jobs, old, result, retired, x.record.RetiredReport)
		if e != nil {
			return e
		}
	}
	if p.JobSequence != j.Sequence {
		return ErrConsumed
	}
	r := x.record
	x.record = EndpointRecord{Version: r.Version, Grant: r.Grant, ManagerPublicKey: r.ManagerPublicKey, ExecutorPublicKey: r.ExecutorPublicKey, ClockFloor: r.ClockFloor, PrefixDigest: Digest(nil), Mutation: r.Mutation, Jobs: j}
	return nil // Accept persists new delivery and intent together, before custody.
}
func (x *Endpoint) retire(ctx context.Context, p Permit, raw []byte) error {
	payload, ok := x.payload.(RetirablePayload)
	if !ok || x.running || !x.record.Grant.Reusable() || x.mutation == nil || x.record.MutationCompletion == nil || len(x.record.RetirePermit) > 0 {
		return ErrConsumed
	}
	delivery, _ := VerifyPermit(x.record.Delivery, x.record.ManagerPublicKey)
	result, e := VerifyReport(x.record.ResultReport, x.record.ExecutorPublicKey)
	if e != nil || !SettledResult(result) || !samePackage(p, delivery) || p.RetireResultDigest != Digest(x.record.ResultReport) {
		return ErrAuthority
	}
	if e = x.mutation.Recover(ctx, *x.record.MutationCompletion, x.verifyMutationCompletion); e != nil {
		return e
	}
	if e = x.check(ctx, &p); e != nil {
		return e
	}
	x.record.RetirePermit = bytes.Clone(raw)
	if e = x.save(); e != nil {
		return e
	}
	check := func() error { return x.check(ctx, &p) }
	if e = check(); e != nil {
		return e
	}
	if e = payload.Retire(ctx, x.record.ImportReceipt, check); e != nil {
		return ErrUncertain
	}
	if e = check(); e != nil {
		return e
	}
	if e = x.mutation.RetireMSI(ctx, *x.record.MutationCompletion, x.verifyMutationCompletion); e != nil {
		return e
	}
	if e = check(); e != nil {
		return e
	}
	receipt, _ := json.Marshal(x.record.MutationCompletion)
	v := Report{Version: p.Version, JobSequence: p.JobSequence, Kind: "retired", Binding: p.Binding, TransferID: p.TransferID, PermitDigest: Digest(raw), Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: x.now().Unix(), Offset: p.Package.Size, State: "retired", Retirement: &RetirementEvidence{ResultDigest: p.RetireResultDigest, ReleaseDigest: Digest(receipt), CustodyDigest: Digest(x.record.ImportReceipt)}}
	x.record.RetiredReport, e = SignReport(v, x.key)
	if e != nil {
		return e
	}
	if e = x.save(); e != nil {
		return e
	}
	return check()
}
