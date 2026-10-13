package windowsupdatejob

import (
	"bytes"
	"context"
	"encoding/json"

	"localrmm/internal/actionpermit"
)

const ReusableExecutorVersion = "tracebolt.windows-selected-update-executor.v3"

// ReusableExecutorState is present only in freshly provisioned v6 consent.
// Pending retains the exact reviewed retirement before touching the shared
// owner. Compact history retains truthful outcomes and immutable signed acks;
// the scalar floor and hash chain never reset when the bounded history rolls.
type ReusableExecutorState struct {
	RetiredFloor uint64               `json:"retiredFloor,string"`
	RetiredChain string               `json:"retiredChain"`
	BaseFloor    uint64               `json:"baseFloor,string"`
	BaseChain    string               `json:"baseChain"`
	Recent       []RetiredExecutorJob `json:"recent"`
	Pending      []byte               `json:"pending,omitempty"`
}
type RetiredExecutorJob struct {
	Job    RetiredJob `json:"job"`
	Report []byte     `json:"report"`
}

func newReusableExecutorState() *ReusableExecutorState {
	return &ReusableExecutorState{RetiredChain: actionpermit.Digest(nil), BaseChain: actionpermit.Digest(nil), Recent: []RetiredExecutorJob{}}
}
func (r ExecutorRecord) validateReusableExecutor() error {
	s := r.Reusable
	if !r.Consent.Reusable() {
		if s != nil || r.Version == ReusableExecutorVersion {
			return ErrIntegrity
		}
		return nil
	}
	if s == nil || r.Version != ReusableExecutorVersion || r.Mutation == nil || !r.Mutation.ReusableWUA() || len(r.Attempts) > 1 || s.Recent == nil || len(s.Recent) > MaxRecentJobs || !actionpermit.ValidDigest(s.RetiredChain) || !actionpermit.ValidDigest(s.BaseChain) || s.BaseFloor > s.RetiredFloor || s.RetiredFloor > r.Sequence {
		return ErrIntegrity
	}
	if s.BaseFloor == 0 && s.BaseChain != actionpermit.Digest(nil) || s.BaseFloor > 0 && len(s.Recent) != MaxRecentJobs {
		return ErrIntegrity
	}
	floor, chain := s.BaseFloor, s.BaseChain
	seen := map[string]bool{}
	for _, entry := range s.Recent {
		j := entry.Job
		ack, e := VerifyRetirementReport(entry.Report, r.ExecutorPublicKey)
		if e != nil || j.Validate() != nil || j.Occurrence <= floor || seen[j.JobID] || ack.Binding != r.Consent.Binding || ack.JobID != j.JobID || ack.Occurrence != j.Occurrence || ack.Selection != j.Selection || ack.EnvelopeDigest != j.Result.EnvelopeDigest || ack.ResultDigest != j.ResultDigest || actionpermit.Digest(entry.Report) != j.RetirementDigest || ack.IssuedAt != j.RetiredAt || ack.IssuedAt > r.ClockFloor || ack.ExpiresAt > r.Consent.ExpiresAt || !j.Result.Attempted {
			return ErrIntegrity
		}
		if j.ApprovedAt != 0 && (j.ApprovedAt > j.ClaimedAt || j.ClaimedAt > j.Result.CompletedAt) {
			return ErrIntegrity
		}
		seen[j.JobID] = true
		floor, chain = j.Occurrence, retiredChain(chain, j)
	}
	if floor != s.RetiredFloor || chain != s.RetiredChain {
		return ErrIntegrity
	}
	if len(r.Attempts) > 0 {
		p, e := Verify(r.Attempts[0].Envelope, r.PublicKey)
		if e != nil || seen[p.Preview.ID] {
			return ErrIntegrity
		}
	}
	if len(s.Pending) > 0 {
		q, e := VerifyRetirement(s.Pending, r.PublicKey)
		if e != nil || len(r.Attempts) != 1 || q.Binding != r.Consent.Binding || q.IssuedAt > r.ClockFloor || q.ExpiresAt > r.Consent.ExpiresAt || r.matchesRetirement(q) != nil {
			return ErrIntegrity
		}
	}
	return nil
}
func (r ExecutorRecord) matchesRetirement(q RetirementPermit) error {
	if !r.Consent.Reusable() || r.Reusable == nil || len(r.Attempts) != 1 || q.Binding != r.Consent.Binding {
		return ErrAuthority
	}
	a := r.Attempts[0]
	p, e := Verify(a.Envelope, r.PublicKey)
	if e != nil || !p.Reusable() || p.Preview.ID != q.JobID || p.Preview.Readiness.Selection != q.Selection || p.Sequence != q.Occurrence || q.Occurrence <= r.Reusable.RetiredFloor || actionpermit.Digest(a.Envelope) != q.EnvelopeDigest || a.Result == nil || !a.Attempted || !a.Result.Attempted || a.Result.Outcome != "succeeded" || len(a.ResultReport) == 0 || actionpermit.Digest(a.ResultReport) != q.ResultDigest || q.IssuedAt < a.Result.CompletedAt || a.MutationCompletion == nil || a.MutationCompletion.Outcome != "succeeded" || r.validateMutationCompletion(a, p) != nil || r.validateResultReport(a, p) != nil {
		return ErrAuthority
	}
	return nil
}
func (x *Executor) currentRetirement(c Current, p RetirementPermit) (int64, error) {
	n, e := x.currentAuthority(c)
	if e != nil {
		return n, e
	}
	if !x.record.Consent.Reusable() || p.Binding != c.Binding || p.ExpiresAt > x.record.Consent.ExpiresAt {
		return n, x.rejectTime(n, ErrAuthority)
	}
	if n < p.IssuedAt || n >= p.ExpiresAt {
		return n, x.rejectTime(n, ErrExpired)
	}
	return n, nil
}

// Retire compacts only a successful, attempted, exactly released current WUA
// job. It cannot call the adapter, recreate a native capability, renew a report
// or erase uncertainty. Replays reconcile only this exact saved metadata intent.
func (x *Executor) retirementAuthority(ctx context.Context, q RetirementPermit) (Current, int64, error) {
	var current Current
	if err := x.check(); err != nil {
		return current, 0, err
	}
	err := x.authority.WithCurrent(ctx, x.record.Consent.Binding, func(c Current) error {
		current = c
		_, err := x.currentRetirement(c, q)
		return err
	})
	if err != nil {
		return current, 0, err
	}
	// WithCurrent can itself finish slowly. No saved observation or report age
	// may authorize retirement after the original permit or current leaf expires.
	n, err := x.clock()
	if err != nil {
		return current, n, err
	}
	if n < q.IssuedAt || n >= q.ExpiresAt || n >= current.LeafNotAfter || n >= x.record.Consent.ExpiresAt {
		return current, n, x.rejectTime(n, ErrExpired)
	}
	if err = ctx.Err(); err != nil {
		return current, n, err
	}
	return current, n, nil
}
func (x *Executor) Retire(ctx context.Context, raw []byte) ([]byte, error) {
	if x == nil || !x.mu.TryLock() {
		return nil, ErrConflict
	}
	defer x.mu.Unlock()
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := x.check(); err != nil {
		return nil, err
	}
	q, err := VerifyRetirement(raw, x.record.PublicKey)
	if err != nil {
		return nil, err
	}
	if !x.record.Consent.Reusable() || x.record.Reusable == nil || x.mutation == nil || x.running || x.accepted != nil {
		return nil, ErrConflict
	}
	_, n, err := x.retirementAuthority(ctx, q)
	if err != nil {
		return nil, err
	}
	for _, old := range x.record.Reusable.Recent {
		if old.Job.Occurrence == q.Occurrence {
			return x.retiredOutbox(n, q.JobID, actionpermit.Digest(raw))
		}
	}
	if q.Occurrence <= x.record.Reusable.RetiredFloor {
		return nil, ErrConsumed
	}
	if err = x.record.matchesRetirement(q); err != nil {
		return nil, err
	}
	pending := x.record.Reusable.Pending
	if len(pending) > 0 && !bytes.Equal(pending, raw) {
		return nil, ErrConsumed
	}
	if len(pending) == 0 {
		x.record.Reusable.Pending = bytes.Clone(raw)
		if err = x.save(); err != nil {
			return nil, err
		}
	}
	// Reacquire current local authority after each durable wait. Implementations
	// need not hold a credential lock throughout retirement; no nested callbacks.
	if _, _, err = x.retirementAuthority(ctx, q); err != nil {
		return nil, err
	}
	a := x.record.Attempts[0]
	if err = x.mutation.RetireWUA(ctx, *a.MutationCompletion, x.verifyMutationCompletion); err != nil {
		// A lost release can be recovered only from this exact saved receipt.
		if recoverErr := x.mutation.Recover(ctx, *a.MutationCompletion, x.verifyMutationCompletion); recoverErr != nil {
			return nil, err
		}
		if _, _, err = x.retirementAuthority(ctx, q); err != nil {
			return nil, err
		}
		if err = x.mutation.RetireWUA(ctx, *a.MutationCompletion, x.verifyMutationCompletion); err != nil {
			return nil, err
		}
	}
	current, n, err := x.retirementAuthority(ctx, q)
	if err != nil {
		return nil, err
	}
	receipt, _ := json.Marshal(a.MutationCompletion)
	report := RetirementReport{Version: RetirementVersion, Binding: q.Binding, JobID: q.JobID, Selection: q.Selection, Occurrence: q.Occurrence, ReferenceDigest: actionpermit.Digest(raw), EnvelopeDigest: q.EnvelopeDigest, ResultDigest: q.ResultDigest, ReleaseDigest: actionpermit.Digest(receipt), IssuedAt: n, ExpiresAt: min(n+300, q.ExpiresAt, x.record.Consent.ExpiresAt, current.LeafNotAfter)}
	ack, err := SignRetirementReport(report, x.key)
	if err != nil {
		return nil, err
	}
	p, _ := Verify(a.Envelope, x.record.PublicKey)
	j := RetiredJob{Occurrence: q.Occurrence, JobID: q.JobID, Selection: q.Selection, Result: *a.Result, ResultDigest: q.ResultDigest, RetirementDigest: actionpermit.Digest(ack), ApprovedAt: p.ApprovedAt, ClaimedAt: a.ClaimedAt, RetiredAt: n}
	state := x.record.Reusable
	state.Recent = append(state.Recent, RetiredExecutorJob{Job: j, Report: ack})
	state.RetiredFloor, state.RetiredChain = j.Occurrence, retiredChain(state.RetiredChain, j)
	if len(state.Recent) > MaxRecentJobs {
		first := state.Recent[0].Job
		state.BaseFloor, state.BaseChain = first.Occurrence, retiredChain(state.BaseChain, first)
		state.Recent = append([]RetiredExecutorJob(nil), state.Recent[1:]...)
	}
	state.Pending = nil
	x.record.Attempts = []Attempt{}
	x.record.LatestReadiness = nil // Its scalar replay floor is retained forever.
	if err = x.save(); err != nil {
		return nil, err
	}
	_, n, err = x.retirementAuthority(ctx, q)
	if err != nil {
		return nil, err
	}
	if n >= report.ExpiresAt {
		return nil, x.rejectTime(n, ErrExpired)
	}
	return bytes.Clone(ack), nil
}
func (x *Executor) retiredOutbox(n int64, id, reference string) ([]byte, error) {
	if x.record.Reusable == nil {
		return nil, ErrUnavailable
	}
	for _, old := range x.record.Reusable.Recent {
		if old.Job.JobID != id {
			continue
		}
		r, e := VerifyRetirementReport(old.Report, x.record.ExecutorPublicKey)
		if e != nil {
			return nil, ErrIntegrity
		}
		if r.ReferenceDigest != reference {
			return nil, ErrConflict
		}
		if n < r.IssuedAt || n >= r.ExpiresAt {
			return nil, x.rejectTime(n, ErrExpired)
		}
		return bytes.Clone(old.Report), nil
	}
	return nil, ErrUnavailable
}
func (x *Executor) retirementStatus(n int64) []EvidenceStatus {
	// Only the newest acknowledgment needs retry. Older exact bytes remain in
	// Outbox, but advertising them would starve a manager that has advanced.
	if x.record.Reusable == nil || len(x.record.Reusable.Recent) == 0 {
		return nil
	}
	old := x.record.Reusable.Recent[len(x.record.Reusable.Recent)-1]
	r, _ := VerifyRetirementReport(old.Report, x.record.ExecutorPublicKey)
	state := "available"
	if n >= r.ExpiresAt {
		state = "expired"
	}
	return []EvidenceStatus{{Kind: "retired", JobID: r.JobID, ReferenceDigest: r.ReferenceDigest, Selection: r.Selection, Sequence: r.Occurrence, Deadline: r.ExpiresAt, ClaimedAt: r.IssuedAt, Attempted: true, Result: &old.Job.Result, ReportState: state, ReportIssuedAt: r.IssuedAt, ReportExpiresAt: r.ExpiresAt}}
}
