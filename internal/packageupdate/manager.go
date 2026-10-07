package packageupdate

import (
	"context"
	"sync"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/packageplan"
)

// PreparationAdapter is the synchronous simulation evidence seam. Native
// preparation uses packagecontroller and its authenticated endpoint dispatch.
// Cached inventory can supply selection, never installation evidence.
type PreparationAdapter interface {
	Prepare(context.Context, Binding, PrepareRequest, string) (Preview, error)
}

// DurableStore opens existing identity-bound state only. Ambiguous writes must
// leave a persistent fence; ErrUncertain never grants permission to retry a job.
type DurableStore interface {
	Open(context.Context, Binding) ([]byte, error)
	CompareAndSwap(context.Context, Binding, uint64, []byte) error
}

// Manager's zero value is unavailable. Its only nonzero constructor is explicitly
// synthetic, has no native implementation injection, and cannot enable APT.
type Manager struct{ simulation *simulationManager }
type simulationManager struct {
	mu      sync.Mutex
	store   DurableStore
	binding Binding
	fixture SimulationFixture
	runner  *simulatedRunner
	now     func() time.Time
}

// NewSimulation connects real persistence to a fixed in-process simulator. It is
// a source/testing seam, not a production LAN configuration or native grant.
func NewSimulation(ctx context.Context, store DurableStore, binding Binding, fixture SimulationFixture, now func() time.Time) (*Manager, error) {
	if store == nil || now == nil || !validBinding(binding) || fixture.EvidenceMode != "synthetic" || (fixture.Outcome != "success" && fixture.Outcome != "mismatch") || (fixture.RebootState != "required" && fixture.RebootState != "not_reported" && fixture.RebootState != "unknown") {
		return nil, ErrInvalid
	}
	raw, e := store.Open(ctx, binding)
	if e != nil {
		return nil, e
	}
	r, e := Decode(ctx, raw)
	if e != nil || r.Binding != binding {
		return nil, ErrInvalid
	}
	if _, e = packageplan.Encode(ctx, fixture.Plan); e != nil {
		return nil, e
	}
	owned, e := cloneFixture(fixture)
	if e != nil {
		return nil, e
	}
	return &Manager{simulation: &simulationManager{store: store, binding: binding, fixture: owned, runner: newSimulatedRunner(fixture.Outcome, fixture.RebootState), now: now}}, nil
}
func (m Manager) load(ctx context.Context) (Record, error) {
	raw, e := m.simulation.store.Open(ctx, m.simulation.binding)
	if e != nil {
		return Record{}, e
	}
	r, e := Decode(ctx, raw)
	if e != nil || r.Binding != m.simulation.binding {
		return Record{}, ErrInvalid
	}
	return r, nil
}
func (m Manager) save(ctx context.Context, old, next Record) error {
	if e := ValidateSuccessor(ctx, old, next); e != nil {
		return e
	}
	raw, e := Encode(ctx, next)
	if e != nil {
		return e
	}
	return m.simulation.store.CompareAndSwap(ctx, old.Binding, old.Revision, raw)
}
func (m Manager) observe(ctx context.Context, now int64) (Record, error) {
	r, e := m.load(ctx)
	if e != nil {
		return Record{}, e
	}
	next, e := Observe(ctx, r, now)
	if e != nil {
		return Record{}, e
	}
	if e = m.save(ctx, r, next); e != nil {
		return Record{}, e
	}
	return next, nil
}
func (m Manager) check(ctx context.Context, device, actor string) error {
	if ctx == nil || !enrollmentcrypto.ValidID(device, "agent_") || actor != "" && !enrollmentcrypto.ValidID(actor, "operator_") {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if m.simulation == nil {
		return ErrUnavailable
	}
	if device != m.simulation.binding.DeviceID {
		return ErrUnavailable
	}
	return nil
}
func (m Manager) Prepare(ctx context.Context, device, actor string, req PrepareRequest) error {
	if ValidatePrepare(req) != nil || !enrollmentcrypto.ValidID(actor, "operator_") {
		return ErrInvalid
	}
	if e := m.check(ctx, device, actor); e != nil {
		return e
	}
	s := m.simulation
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC().Unix()
	r, e := m.observe(ctx, now)
	if e != nil {
		return e
	}
	existed := false
	for _, saved := range r.Jobs {
		if saved.Request.RequestID == req.RequestID {
			existed = true
		}
	}
	next, e := Prepare(ctx, r, req, actor, now)
	if e != nil {
		return e
	}
	if e = m.save(ctx, r, next); e != nil {
		return e
	}
	if existed {
		return nil
	}
	// A matching persisted request is status recovery, never a second preparation.
	j := next.Jobs[len(next.Jobs)-1]
	if j.Request.RequestID != req.RequestID || j.State != Preparing {
		return nil
	}
	p, e := simulatePreview(ctx, s.binding, req, actor, s.fixture, now)
	if e != nil {
		failed, fe := FailPreparation(ctx, next, req.RequestID, now)
		if fe == nil {
			fe = m.save(ctx, next, failed)
		}
		if fe != nil {
			return fe
		}
		return e
	}
	completed, e := AttachPreview(ctx, next, p, now)
	if e != nil {
		return e
	}
	return m.save(ctx, next, completed)
}
func (m Manager) Approve(ctx context.Context, device, actor string, req ApprovalRequest) error {
	if !enrollmentcrypto.ValidID(actor, "operator_") || !enrollmentcrypto.ValidID(req.RequestID, "update_") || !actionpermit.ValidDigest(req.PreviewDigest) {
		return ErrInvalid
	}
	if e := m.check(ctx, device, actor); e != nil {
		return e
	}
	s := m.simulation
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC().Unix()
	r, e := m.observe(ctx, now)
	if e != nil {
		return e
	}
	next, e := Approve(ctx, r, req, actor, now)
	if e != nil {
		return e
	}
	return m.save(ctx, r, next)
}

// StartPendingSimulation is an explicit fixture dispatcher. Admission commits
// before Start. A lost/ambiguous commit never invokes Start. Reopening a manager
// never automatically starts an approved/claimed operation. Native dispatch needs
// independent live authorization, signature, endpoint fence and runner setup.
func (m Manager) StartPendingSimulation(ctx context.Context, device string) error {
	if e := m.check(ctx, device, ""); e != nil {
		return e
	}
	s := m.simulation
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC().Unix()
	r, e := m.observe(ctx, now)
	if e != nil {
		return e
	}
	if len(r.Jobs) == 0 {
		return ErrConflict
	}
	j := r.Jobs[len(r.Jobs)-1]
	if j.ClaimedAt != 0 {
		return nil
	}
	if j.State != Approved {
		return ErrConflict
	}
	next, e := ClaimForFixture(ctx, r, j.Request.RequestID, j.Preview.Digest, now)
	if e != nil {
		return e
	}
	if e = m.save(ctx, r, next); e != nil {
		return e
	}
	op := operationFor(next.Jobs[len(next.Jobs)-1])
	result, e := s.runner.Start(ctx, op, now)
	if e != nil {
		result = unknownResult(op, uint64(len(j.Results)+1), now)
	}
	observed, e := ObserveResult(ctx, next, op.RequestID, op.PreviewDigest, result, now)
	if e != nil {
		return e
	}
	return m.save(ctx, next, observed)
}
func (m Manager) View(ctx context.Context, device string, now time.Time) (View, error) {
	return m.view(ctx, device, "", now)
}
func (m Manager) ViewJob(ctx context.Context, device, id string, now time.Time) (View, error) {
	if !enrollmentcrypto.ValidID(id, "update_") {
		return View{}, ErrInvalid
	}
	return m.view(ctx, device, id, now)
}
func (m Manager) view(ctx context.Context, device, id string, now time.Time) (View, error) {
	if ctx == nil || !enrollmentcrypto.ValidID(device, "agent_") || now.Location() != time.UTC || !validTime(now.Unix()) {
		return View{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return View{}, e
	}
	if m.simulation == nil {
		if id != "" {
			return View{}, ErrNotFound
		}
		return unavailableView(device, now), nil
	}
	if e := m.check(ctx, device, ""); e != nil {
		return View{}, e
	}
	s := m.simulation
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := m.observe(ctx, now.Unix())
	if e != nil {
		return View{}, e
	}
	if len(r.Jobs) > 0 {
		j := r.Jobs[len(r.Jobs)-1]
		if (id == "" || id == j.Request.RequestID) && j.ClaimedAt != 0 && (j.State == DeliveryUnknown || j.State == Applying || j.State == Verifying) {
			op := operationFor(j)
			result, re := s.runner.Status(ctx, op, now.Unix())
			if re != nil {
				result = unknownResult(op, uint64(len(j.Results)+1), now.Unix())
			}
			next, re := ObserveResult(ctx, r, op.RequestID, op.PreviewDigest, result, now.Unix())
			if re != nil {
				return View{}, re
			}
			if re = m.save(ctx, r, next); re != nil {
				return View{}, re
			}
			r = next
		}
	}
	if id != "" {
		for i, j := range r.Jobs {
			if j.Request.RequestID == id {
				v := projectView(r, now)
				selected := r
				selected.Jobs = r.Jobs[:i+1]
				out := projectView(selected, now)
				out.Available = v.Available
				return out, nil
			}
		}
		return View{}, ErrNotFound
	}
	return projectView(r, now), nil
}
