package packageupdate

import (
	"context"
	"encoding/json"
	"sort"
	"sync"

	"localrmm/internal/packageplan"
)

// Runner is a start/status boundary for an independently surviving operation.
// This slice implements only the in-process synthetic double below. A native
// runner must never bind the APT process lifetime to an HTTP request context.
type Runner interface {
	Start(context.Context, Operation, int64) (Result, error)
	Status(context.Context, Operation, int64) (Result, error)
}
type Operation struct {
	RequestID     string
	Sequence      uint64
	PreviewDigest string
	Preview       Preview
	ApprovedAt    int64
}

func operationFor(j Job) Operation {
	return Operation{j.Request.RequestID, j.Sequence, j.Preview.Digest, *j.Preview, j.ApprovedAt}
}

// SimulationFixture is caller-supplied synthetic data, never discovered inventory.
// Its timestamps are regenerated as simulated observations, never relabeled live
// evidence. No file, command, repository, environment or native adapter is used.
type SimulationFixture struct {
	EvidenceMode string
	Plan         packageplan.Plan
	Sources      []Source
	Outcome      string
	RebootState  string
}

func cloneFixture(f SimulationFixture) (SimulationFixture, error) {
	raw, e := json.Marshal(f)
	var out SimulationFixture
	if e == nil {
		e = json.Unmarshal(raw, &out)
	}
	return out, e
}
func simulatePreview(ctx context.Context, b Binding, req PrepareRequest, actor string, f SimulationFixture, now int64) (Preview, error) {
	f, e := cloneFixture(f)
	if e != nil {
		return Preview{}, e
	}
	p := f.Plan
	p.EndpointID = b.DeviceID
	p.IncarnationDigest = b.IncarnationDigest
	p.RootPolicyDigest = b.RootPolicyDigest
	p.CreatedAt = now
	p.ExpiresAt = now + 60
	p.Evidence.InventoryAt = now
	p.Evidence.MetadataRefreshedAt = now
	candidates := map[Selection]packageplan.Upgrade{}
	for _, u := range p.Packages {
		candidates[Selection{u.Name, u.Architecture}] = u
	}
	p.Packages = nil
	used := map[string]bool{}
	for _, s := range req.Packages {
		u, ok := candidates[s]
		if !ok {
			return Preview{}, ErrConflict
		}
		p.Packages = append(p.Packages, u)
		used[u.Archive.SourceIdentityDigest] = true
	}
	sources := []Source{}
	for _, s := range f.Sources {
		if used[s.IdentityDigest] {
			sources = append(sources, s)
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].IdentityDigest < sources[j].IdentityDigest })
	return DescribePreview(ctx, b, req, actor, p, sources)
}

type simulatedOperation struct {
	operation Operation
	last      Result
}
type simulatedRunner struct {
	mu              sync.Mutex
	outcome, reboot string
	jobs            map[string]simulatedOperation
	starts          int
}

func newSimulatedRunner(outcome, reboot string) *simulatedRunner {
	return &simulatedRunner{outcome: outcome, reboot: reboot, jobs: map[string]simulatedOperation{}}
}
func simulationResult(op Operation, sequence uint64, phase string, now int64, outcome, reboot string) Result {
	r := Result{Sequence: sequence, Phase: phase, ObservedAt: now, Packages: []PackageResult{}, Reboot: RebootEvidence{"unknown", "simulation", now}, DpkgState: "unknown", Reason: "simulated_running"}
	for _, p := range op.Preview.Plan.Packages {
		row := PackageResult{Name: p.Name, Architecture: p.Architecture, ExpectedVersion: p.To.Version, Outcome: "unknown"}
		if phase == Succeeded {
			v := p.To.Version
			row.ObservedVersion = &v
			row.Outcome = "verified"
		}
		if phase == NeedsIntervention && outcome == "mismatch" {
			v := p.From.Version
			row.ObservedVersion = &v
			row.Outcome = "mismatch"
		}
		r.Packages = append(r.Packages, row)
	}
	if phase == Succeeded {
		r.DpkgState = "clean"
		r.Reason = "simulated_verified"
		r.Reboot.State = reboot
	}
	if phase == NeedsIntervention {
		r.Reason = "runner_state_unknown"
		if outcome == "mismatch" {
			r.Reason = "verification_mismatch"
		}
	}
	return r
}
func unknownResult(op Operation, seq uint64, now int64) Result {
	return simulationResult(op, seq, NeedsIntervention, now, "unknown", "unknown")
}
func (s *simulatedRunner) Start(ctx context.Context, op Operation, now int64) (Result, error) {
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if saved, ok := s.jobs[op.RequestID]; ok {
		if !equalJSON(saved.operation, op) {
			return Result{}, ErrConflict
		}
		return saved.last, nil
	}
	r := simulationResult(op, 1, Applying, now, s.outcome, s.reboot)
	s.jobs[op.RequestID] = simulatedOperation{op, r}
	s.starts++
	return r, nil
}
func (s *simulatedRunner) Status(ctx context.Context, op Operation, now int64) (Result, error) {
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, ok := s.jobs[op.RequestID]
	if !ok {
		return Result{}, ErrUnavailable
	}
	if !equalJSON(saved.operation, op) {
		return Result{}, ErrConflict
	}
	phase := saved.last.Phase
	switch phase {
	case Applying:
		phase = Verifying
	case Verifying:
		phase = Succeeded
		if s.outcome == "mismatch" {
			phase = NeedsIntervention
		}
	default:
		return saved.last, nil
	}
	r := simulationResult(op, saved.last.Sequence+1, phase, now, s.outcome, s.reboot)
	saved.last = r
	s.jobs[op.RequestID] = saved
	return r, nil
}
