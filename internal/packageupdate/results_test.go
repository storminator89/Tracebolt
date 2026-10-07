package packageupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestSuccessorPreservesExactHistory(t *testing.T) {
	r, req, p := fixture(t)
	steps := []func(Record) (Record, error){
		func(r Record) (Record, error) { return Prepare(ctx, r, req, actor, at) },
		func(r Record) (Record, error) { return AttachPreview(ctx, r, p, at+1) },
		func(r Record) (Record, error) {
			return Approve(ctx, r, ApprovalRequest{p.RequestID, p.Digest}, actor, at+2)
		},
		func(r Record) (Record, error) { return ClaimForFixture(ctx, r, p.RequestID, p.Digest, at+3) },
	}
	for _, step := range steps {
		next, e := step(r)
		if e != nil || ValidateSuccessor(ctx, r, next) != nil {
			t.Fatal("valid successor rejected", e)
		}
		r = next
	}
	for seq, phase := range []string{Applying, Verifying, Succeeded} {
		res := simulationResult(operationFor(r.Jobs[0]), uint64(seq+1), phase, at+int64(seq)+4, "success", "required")
		next, e := ObserveResult(ctx, r, p.RequestID, p.Digest, res, at+int64(seq)+4)
		if e != nil || ValidateSuccessor(ctx, r, next) != nil {
			t.Fatal("valid result successor", e)
		}
		r = next
	}
	if r.Jobs[0].State != Succeeded || !terminal(r.Jobs[0]) {
		t.Fatal("verified simulation not terminal")
	}
	req.RequestID = "update_22222222222222222222222222222222"
	next, e := Prepare(ctx, r, req, actor, at+7)
	if e != nil || ValidateSuccessor(ctx, r, next) != nil {
		t.Fatal("next exact operation", e)
	}
	for _, mutate := range []func(*Record){
		func(x *Record) { x.Jobs[0].Request.RequestID = "update_33333333333333333333333333333333" },
		func(x *Record) { x.Jobs[0].Results[0].Reason = "runner_state_unknown" },
		func(x *Record) { x.Jobs[0].ApprovedAt++ },
		func(x *Record) { x.Jobs = x.Jobs[1:] },
		func(x *Record) { x.Revision++ },
		func(x *Record) { x.ClockFloor = at - 1 },
	} {
		raw, _ := json.Marshal(next)
		var changed Record
		_ = json.Unmarshal(raw, &changed)
		mutate(&changed)
		if ValidateSuccessor(ctx, r, changed) == nil {
			t.Fatal("mutated prior durable history")
		}
	}
}
func TestResultsCannotInventSuccessOrRebootAbsence(t *testing.T) {
	r, p := approved(t)
	r, e := ClaimForFixture(ctx, r, p.RequestID, p.Digest, at+3)
	if e != nil {
		t.Fatal(e)
	}
	op := operationFor(r.Jobs[0])
	for _, phase := range []string{Applying, Verifying} {
		res := simulationResult(op, uint64(len(r.Jobs[0].Results)+1), phase, at+4, "success", "required")
		r, e = ObserveResult(ctx, r, p.RequestID, p.Digest, res, at+4)
		if e != nil {
			t.Fatal(e)
		}
	}
	final := simulationResult(op, 3, Succeeded, at+5, "success", "required")
	for _, change := range []func(*Result){func(v *Result) { v.Packages = nil }, func(v *Result) { v.Packages[0].ExpectedVersion = "9.9" }, func(v *Result) { v.Packages[0].ObservedVersion = nil }, func(v *Result) { v.DpkgState = "unknown" }, func(v *Result) { v.Reboot.State = "not_required" }, func(v *Result) { v.Reboot.Source = "native" }, func(v *Result) { v.ObservedAt = at - 1 }} {
		raw, _ := json.Marshal(final)
		var bad Result
		_ = json.Unmarshal(raw, &bad)
		change(&bad)
		if _, e = ObserveResult(ctx, r, p.RequestID, p.Digest, bad, at+5); e == nil {
			t.Fatal("fabricated success/evidence")
		}
	}
	done, e := ObserveResult(ctx, r, p.RequestID, p.Digest, final, at+5)
	if e != nil {
		t.Fatal(e)
	}
	again, e := ObserveResult(ctx, done, p.RequestID, p.Digest, final, at+6)
	if e != nil || len(again.Jobs[0].Results) != 3 {
		t.Fatal("same receipt replay", e)
	}
	final.Reason = "changed"
	if _, e = ObserveResult(ctx, done, p.RequestID, p.Digest, final, at+6); !errors.Is(e, ErrConflict) {
		t.Fatal("changed receipt", e)
	}
}

type uncertainClaimStore struct {
	raw        []byte
	loseCommit bool
	fenced     bool
	failClaim  bool
}

func (s *uncertainClaimStore) Open(_ context.Context, _ Binding) ([]byte, error) {
	if s.fenced {
		return nil, ErrUncertain
	}
	return bytes.Clone(s.raw), nil
}
func (s *uncertainClaimStore) CompareAndSwap(c context.Context, b Binding, revision uint64, raw []byte) error {
	if s.fenced {
		return ErrUncertain
	}
	old, e := Decode(c, s.raw)
	if e != nil {
		return e
	}
	next, e := Decode(c, raw)
	if e != nil {
		return e
	}
	if old.Revision != revision || b != old.Binding {
		return ErrConflict
	}
	if e = ValidateSuccessor(c, old, next); e != nil {
		return e
	}
	if s.failClaim && len(next.Jobs) > 0 && next.Jobs[len(next.Jobs)-1].ClaimedAt != 0 {
		if s.loseCommit {
			s.raw = bytes.Clone(raw)
		}
		s.fenced = true
		return ErrUncertain
	}
	s.raw = bytes.Clone(raw)
	return nil
}
func TestUncertainClaimNeverCallsRunnerStart(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			r, req, p := fixture(t)
			raw, _ := Encode(ctx, r)
			s := &uncertainClaimStore{raw: raw, loseCommit: committed}
			m, e := NewSimulation(ctx, s, r.Binding, SimulationFixture{EvidenceMode: "synthetic", Plan: p.Plan, Sources: p.Sources, Outcome: "success", RebootState: "unknown"}, func() time.Time { return time.Unix(at, 0).UTC() })
			if e != nil {
				t.Fatal(e)
			}
			if e = m.Prepare(ctx, r.Binding.DeviceID, actor, req); e != nil {
				t.Fatal(e)
			}
			v, e := m.View(ctx, r.Binding.DeviceID, time.Unix(at, 0).UTC())
			if e != nil {
				t.Fatal(e)
			}
			if e = m.Approve(ctx, r.Binding.DeviceID, actor, ApprovalRequest{RequestID: req.RequestID, PreviewDigest: v.Preview.Digest}); e != nil {
				t.Fatal(e)
			}
			s.failClaim = true
			if e = m.StartPendingSimulation(ctx, r.Binding.DeviceID); !errors.Is(e, ErrUncertain) {
				t.Fatal(e)
			}
			if m.simulation.runner.starts != 0 {
				t.Fatal("runner called without acknowledged durable claim")
			}
			if e = m.StartPendingSimulation(ctx, r.Binding.DeviceID); !errors.Is(e, ErrUncertain) || m.simulation.runner.starts != 0 {
				t.Fatal("uncertain admission retried", e)
			}
		})
	}
}
func TestPersistedPreparingRetryNeverRefreshesEvidence(t *testing.T) {
	r, req, p := fixture(t)
	r, e := Prepare(ctx, r, req, actor, at)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := Encode(ctx, r)
	s := &uncertainClaimStore{raw: raw}
	m, e := NewSimulation(ctx, s, r.Binding, SimulationFixture{EvidenceMode: "synthetic", Plan: p.Plan, Sources: p.Sources, Outcome: "success", RebootState: "unknown"}, func() time.Time { return time.Unix(at+10, 0).UTC() })
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Prepare(ctx, r.Binding.DeviceID, actor, req); e != nil {
		t.Fatal(e)
	}
	saved, e := Decode(ctx, s.raw)
	if e != nil || saved.Jobs[0].Preview != nil || saved.Jobs[0].CreatedAt != at || saved.Jobs[0].State != Preparing {
		t.Fatal("restarted unconfirmed preparation", e)
	}
}
