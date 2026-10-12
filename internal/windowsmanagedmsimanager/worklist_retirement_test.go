package windowsmanagedmsimanager

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"strings"
	"testing"
)

// All reports below are synthetic signed evidence; no installer or endpoint
// custody action is invoked by this manager-only fixture.
func retirementWorklistFixture(t *testing.T, outcome string, code uint32, registration msi.Fact, attempted, known bool) (*Registry, *Manager, *worklistMemoryStore, ed25519.PrivateKey, WorklistView, WorklistSession, *int64) {
	t.Helper()
	r, m, s, key, actor, now := savedManagerFixture(t)
	ctx := context.Background()
	artifact := reusableManagerUpload(t, m, actor, 'A')
	transfer := "transfer_" + strings.Repeat("7", 32)
	if e := m.DeliverArtifact(ctx, actor, transfer, true, artifact, msi.BindingDigest(m.binding)); e != nil {
		t.Fatal(e)
	}
	poll, e := m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	delivery := poll.Permit
	reusableManagerReport(t, m, key, delivery, "delivery", *now)
	if e = m.Review(ctx, actor, true, true, true, true); e != nil {
		t.Fatal(e)
	}
	poll, e = m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ready := reusableManagerReport(t, m, key, poll.Permit, "readiness", *now)
	reusableManagerReport(t, m, key, delivery, "mutation", *now)
	if e = m.Approve(ctx, actor, msi.Digest(ready), true); e != nil {
		t.Fatal(e)
	}
	poll, e = m.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	p, e := msi.VerifyPermit(poll.Permit, m.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	result := msi.Result{JobID: "software_" + strings.TrimPrefix(transfer, "transfer_"), EnvelopeDigest: msi.Digest(poll.Permit), Outcome: outcome, ReturnCode: code, RegistrationVerified: registration, Attempted: attempted, ReturnCodeKnown: known, CompletedAt: *now}
	report := msi.Report{Version: p.Version, JobSequence: p.JobSequence, Kind: "result", Binding: p.Binding, TransferID: p.TransferID, PermitDigest: msi.Digest(poll.Permit), Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: *now, Offset: p.Package.Size, State: outcome, Result: &result}
	raw, e := msi.SignReport(report, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Report(ctx, raw); e != nil {
		t.Fatal(e)
	}
	v, e := r.SaveWorklist(ctx, actor, SaveWorklistRequest{Name: "Exact finished jobs", ArtifactID: artifact, ArtifactRetiredCount: "0", Targets: []SaveWorklistTarget{{DeviceID: m.binding.DeviceID, BindingDigest: msi.BindingDigest(m.binding), Name: "Original device"}}})
	if e != nil {
		t.Fatal(e)
	}
	sess := WorklistSession{ActorID: actor, Digest: msi.Digest([]byte("reviewing session")), ExpiresAt: *now + 600}
	return r, m, s, key, v, sess, now
}

func TestWorklistRetirementExactSettledResultAndSignedReconciliation(t *testing.T) {
	for _, tc := range []struct {
		outcome      string
		code         uint32
		registration msi.Fact
	}{{"succeeded", 0, msi.Yes}, {"restart_required", 3010, msi.Yes}, {"busy", 1618, msi.No}, {"failed", 1603, msi.Unknown}} {
		t.Run(tc.outcome, func(t *testing.T) {
			r, m, s, key, v, sess, now := retirementWorklistFixture(t, tc.outcome, tc.code, tc.registration, true, true)
			ctx := context.Background()
			// The old install permit is expired; today's exact shared release is fresh.
			*now += 75
			reusableManagerReport(t, m, key, s.members[m.binding.DeviceID].r.DeliveryPermit, "mutation", *now)
			*now += 10
			p, e := r.PreviewWorklist(ctx, sess.ActorID, v.ID, v.Revision, "retire")
			if e != nil || len(p.Items) != 1 {
				t.Fatal("retirement preview", p, e)
			}
			q := p.Items[0]
			if q.ExpiresAt != *now+50 || q.ResultDigest != msi.Digest(s.members[m.binding.DeviceID].r.ResultReport) || q.ReadinessDigest != "" {
				t.Fatal("wrong reviewed cutoff/result", q)
			}
			v, e = r.ConfirmWorklist(ctx, sess, v.ID, ConfirmWorklistBatch{Revision: v.Revision, Kind: "retire", Items: p.Items, Acknowledgements: msi.WorklistAcknowledgements{Acknowledged: true}})
			if e != nil {
				t.Fatal("retirement confirm", e)
			}
			if len(s.members[m.binding.DeviceID].r.RetirePermit) != 0 {
				t.Fatal("confirm issued cleanup")
			}
			b := v.Batches[0]
			ref := &msi.WorklistDispatchReference{WorklistID: v.ID, BatchID: b.ID, Item: 0}
			exact, e := r.BatchDispatchContext(ctx, sess, ref, q, b.Acknowledgements)
			if e != nil {
				t.Fatal(e)
			}
			exact, e = WithJobOccurrence(exact, q.ArtifactRetiredCount, q.TransferID, q.JobSequence)
			if e != nil {
				t.Fatal(e)
			}
			if e = m.Retire(exact, sess.ActorID, q.ResultDigest, true); e != nil {
				t.Fatal("dispatch", e)
			}
			v, e = r.Worklist(ctx, sess.ActorID, v.ID)
			if e != nil {
				t.Fatal(e)
			}
			b = v.Batches[0]
			rec := s.members[m.binding.DeviceID].r
			permit, e := msi.VerifyPermit(rec.RetirePermit, rec.PublicKey)
			if e != nil || permit.RetireResultDigest != q.ResultDigest || b.Items[0].PermitDigest != msi.Digest(rec.RetirePermit) || b.Items[0].State != "issued" {
				t.Fatal("missing atomic exact cleanup", e)
			}
			records := map[string]msi.Record{m.binding.DeviceID: rec}
			if msi.WorklistBatchReconciled(v.Worklist, b, records) {
				t.Fatal("permit alone compacted")
			}
			if _, e = r.BatchDispatchContext(ctx, sess, ref, q, b.Acknowledgements); e == nil {
				t.Fatal("duplicate dispatch")
			}
			poll, e := m.Poll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			reusableManagerReport(t, m, key, poll.Permit, "retired", *now)
			v, e = r.Worklist(ctx, sess.ActorID, v.ID)
			if e != nil {
				t.Fatal(e)
			}
			if v.Rows[0].View.State != "retired" || v.Rows[0].View.Result.Outcome != tc.outcome || v.Rows[0].View.Result.ReturnCode != tc.code {
				t.Fatal("cleanup erased result truth", v.Rows)
			}
			records[m.binding.DeviceID] = s.members[m.binding.DeviceID].r
			if !msi.WorklistBatchReconciled(v.Worklist, b, records) {
				t.Fatal("exact signed retirement missing")
			}
			wrong := b
			wrong.Items = append([]msi.WorklistBatchItem(nil), b.Items...)
			wrong.Items[0].Request.ResultDigest = msi.Digest([]byte("another result"))
			if msi.WorklistBatchReconciled(v.Worklist, wrong, records) {
				t.Fatal("wrong reviewed result compacted")
			}
			next, e := msi.NextManagerJob(records[m.binding.DeviceID])
			if e != nil {
				t.Fatal(e)
			}
			records[m.binding.DeviceID] = next
			if !msi.WorklistBatchReconciled(v.Worklist, b, records) || msi.WorklistBatchReconciled(v.Worklist, wrong, records) {
				t.Fatal("retained signed evidence lost result pin")
			}
			if s.artifact.Retired || s.artifact.RetirementStarted {
				t.Fatal("batch retired shared payload")
			}
		})
	}
}

func TestWorklistRetirementRejectsUnsettledResults(t *testing.T) {
	for _, tc := range []struct {
		name, outcome    string
		code             uint32
		registration     msi.Fact
		attempted, known bool
	}{{"lost return", "uncertain", 0, msi.Unknown, true, false}, {"uncertain registration", "uncertain", 0, msi.Unknown, true, true}, {"unexpected restart", "unexpected_restart", 1641, msi.Unknown, true, true}, {"not attempted", "not_attempted", 0, msi.Unknown, false, false}, {"unverified 3010", "restart_required", 3010, msi.Unknown, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			r, m, s, _, v, sess, now := retirementWorklistFixture(t, tc.outcome, tc.code, tc.registration, tc.attempted, tc.known)
			p, e := r.PreviewWorklist(context.Background(), sess.ActorID, v.ID, v.Revision, "retire")
			if e != nil || len(p.Items) != 0 || len(p.Excluded) != 1 || p.Excluded[0].Reason != "unsettled" {
				t.Fatal("unsafe result eligible", p, e)
			}
			q := msi.WorklistRequest{DeviceID: m.binding.DeviceID, Operation: "retire", ArtifactID: v.ArtifactID, ArtifactRetiredCount: "0", BindingDigest: msi.BindingDigest(m.binding), TransferID: v.Targets[0].TransferID, JobSequence: "1", ExpiresAt: *now + 60, ResultDigest: msi.Digest(s.members[m.binding.DeviceID].r.ResultReport)}
			if _, e = r.ConfirmWorklist(context.Background(), sess, v.ID, ConfirmWorklistBatch{Revision: v.Revision, Kind: "retire", Items: []msi.WorklistRequest{q}, Acknowledgements: msi.WorklistAcknowledgements{Acknowledged: true}}); e == nil {
				t.Fatal("forged eligibility confirmed")
			}
		})
	}
}

func TestWorklistRetirementPinsAndFreshOwner(t *testing.T) {
	r, m, s, _, v, sess, now := retirementWorklistFixture(t, "succeeded", 0, msi.Yes, true, true)
	p, e := r.PreviewWorklist(context.Background(), sess.ActorID, v.ID, v.Revision, "retire")
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"result", "transfer", "sequence", "occurrence", "binding", "readiness", "deadline", "ack"} {
		t.Run(mode, func(t *testing.T) {
			q := p.Items[0]
			ack := true
			switch mode {
			case "result":
				q.ResultDigest = msi.Digest([]byte("changed"))
			case "transfer":
				q.TransferID = "transfer_" + strings.Repeat("a", 32)
			case "sequence":
				q.JobSequence = "2"
			case "occurrence":
				q.ArtifactRetiredCount = "1"
			case "binding":
				q.BindingDigest = msi.Digest([]byte("binding"))
			case "readiness":
				q.ReadinessDigest = msi.Digest([]byte("ready"))
			case "deadline":
				q.ExpiresAt++
			case "ack":
				ack = false
			}
			if _, e := r.ConfirmWorklist(context.Background(), sess, v.ID, ConfirmWorklistBatch{Revision: v.Revision, Kind: "retire", Items: []msi.WorklistRequest{q}, Acknowledgements: msi.WorklistAcknowledgements{Acknowledged: ack}}); e == nil {
				t.Fatal("changed confirmation accepted")
			}
		})
	}
	if len(s.journal.Worklists[0].Batches) != 0 || len(s.members[m.binding.DeviceID].r.RetirePermit) != 0 {
		t.Fatal("invalid requests changed state")
	}
	row := *v.Rows[0].View
	for _, mode := range []string{"busy", "blocked", "inactive", "stale", "future"} {
		changed := row
		mutation := *row.Mutation
		changed.Mutation = &mutation
		switch mode {
		case "busy":
			mutation.Phase = "reserved"
		case "blocked":
			mutation.Blocked = true
		case "inactive":
			mutation.Active = false
		case "stale":
			changed.MutationCapturedAt = *now - 60
		case "future":
			changed.MutationCapturedAt = *now + 1
		}
		if reason := worklistEligible(v.Worklist, v.Targets[0], changed, "retire", *now); reason != "busy" {
			t.Fatal(mode, reason)
		}
	}
	// A preview cannot turn its fresh status into standing permission.
	*now += 60
	if _, e = r.ConfirmWorklist(context.Background(), sess, v.ID, ConfirmWorklistBatch{Revision: v.Revision, Kind: "retire", Items: p.Items, Acknowledgements: msi.WorklistAcknowledgements{Acknowledged: true}}); e == nil {
		t.Fatal("stale preview confirmed")
	}
	fresh, e := m.View(context.Background())
	if e != nil || fresh.CanRetire {
		t.Fatal("stale owner advertised cleanup", e)
	}
	// These checks only read and reject; original result evidence stays unchanged.
	a, _ := json.Marshal(row.Result)
	b, _ := json.Marshal(fresh.Result)
	if string(a) != string(b) {
		t.Fatal("result mutated")
	}
}
