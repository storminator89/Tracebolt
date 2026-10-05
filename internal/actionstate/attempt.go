package actionstate

import (
	"context"
	"time"

	"localrmm/internal/actionpermit"
)

// These bounded values are the only result information persisted. They exclude
// backend output, errors, executable arguments and arbitrary diagnostic strings.
type NotStartedReason string

const (
	ReasonCanceled      NotStartedReason = "canceled"
	ReasonExpired       NotStartedReason = "expired"
	ReasonPolicyChanged NotStartedReason = "policy_changed"
	ReasonPreflight     NotStartedReason = "preflight"
	ReasonInactive      NotStartedReason = "inactive"
)

type Outcome string

const (
	OutcomeCompleted Outcome = "completed"
	OutcomeUnknown   Outcome = "unknown"
)

type ObservedState string

const (
	ObservedActive   ObservedState = "active"
	ObservedInactive ObservedState = "inactive"
	ObservedFailed   ObservedState = "failed"
	ObservedUnknown  ObservedState = "unknown"
)

// Attempt is an ephemeral capability for one fresh durable runner admission.
// Its zero value is invalid. All copies share single-use transitions. It cannot
// be recovered from a Status, persisted bytes, an old admission or a reopened
// store. It does not itself authorize any host operation: the runtime must still
// check live root policy, peer, unit inputs, deadline and the fixed action scope.
type Attempt struct{ inner *attempt }

type attempt struct {
	owner           *state
	index           int
	dispatchClaimed bool
	terminalClaimed bool
}

func validReason(reason NotStartedReason) bool {
	switch reason {
	case ReasonCanceled, ReasonExpired, ReasonPolicyChanged, ReasonPreflight, ReasonInactive:
		return true
	}
	return false
}

func validObserved(observed ObservedState) bool {
	switch observed {
	case ObservedActive, ObservedInactive, ObservedFailed, ObservedUnknown:
		return true
	}
	return false
}

// MarkDispatching durably records the one possible invocation before a backend
// may be called. It succeeds at most once across all copies. After this barrier,
// the runtime must resample time and recheck live authority before calling the
// backend. Dispatching is intentionally not evidence of an actual invocation.
func (a *Attempt) MarkDispatching(ctx context.Context, now time.Time) (Status, error) {
	return a.transition(ctx, Dispatching, "", "", "", now)
}

// NotStarted closes an admission only when the trusted runtime positively knows
// it has never called the backend, including after a dispatch barrier. Never use
// it for a nonzero exit, timeout, cancellation or error after backend invocation.
// The runtime must serialize its backend call and this assertion.
func (a *Attempt) NotStarted(ctx context.Context, reason NotStartedReason, now time.Time) (Status, error) {
	return a.transition(ctx, NotStarted, reason, "", "", now)
}

// Complete records the result of the sole invocation after MarkDispatching.
// OutcomeCompleted means the backend's operation completed, independently of
// observed service state. Every nonzero/timeout/ambiguous invoked result must use
// OutcomeUnknown, which permanently blocks subsequent admission. Use a bounded
// context independent of a canceled caller to retain the outcome where possible.
func (a *Attempt) Complete(ctx context.Context, outcome Outcome, observed ObservedState, now time.Time) (Status, error) {
	phase := NeedsIntervention
	if outcome == OutcomeCompleted {
		phase = OperationCompleted
	}
	return a.transition(ctx, phase, "", outcome, observed, now)
}

func (a *Attempt) transition(ctx context.Context, phase string, reason NotStartedReason, outcome Outcome, observed ObservedState, now time.Time) (Status, error) {
	if a == nil || a.inner == nil || a.inner.owner == nil {
		return Status{}, ErrAttempt
	}
	token := a.inner
	x := token.owner
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.check(ctx); err != nil {
		return Status{}, err
	}
	if x.active != token || token.terminalClaimed || token.index < 0 || token.index >= len(x.record.Jobs) {
		return Status{}, ErrAttempt
	}
	job := x.record.Jobs[token.index]
	if job.Lifecycle == nil {
		return Status{}, ErrAttempt
	}
	if now.Location() != time.UTC || now.Year() < 1970 || now.Year() > 9999 || now.UnixMicro() <= 0 || now.UnixMicro() < x.record.HighWater {
		return Status{}, actionpermit.ErrClock
	}
	lifecycle := *job.Lifecycle
	switch phase {
	case Dispatching:
		if token.dispatchClaimed || job.Phase != Admitted {
			return Status{}, ErrAttempt
		}
		p, err := actionpermit.Decode(job.Envelope)
		if err != nil {
			return Status{}, ErrCorrupt
		}
		if err := x.verifier.CheckTime(p, now); err != nil {
			return Status{}, err
		}
		token.dispatchClaimed = true
		lifecycle.DispatchAt = now.UnixMicro()
	case NotStarted:
		if (job.Phase != Admitted && job.Phase != Dispatching) || !validReason(reason) {
			return Status{}, ErrTransition
		}
		token.terminalClaimed = true
		lifecycle.Reason = reason
	case OperationCompleted, NeedsIntervention:
		if job.Phase != Dispatching || !token.dispatchClaimed || (outcome != OutcomeCompleted && outcome != OutcomeUnknown) || !validObserved(observed) {
			return Status{}, ErrTransition
		}
		token.terminalClaimed = true
		lifecycle.Outcome, lifecycle.ObservedState = outcome, observed
	default:
		return Status{}, ErrTransition
	}
	lifecycle.TransitionAt = now.UnixMicro()
	job.Phase, job.Lifecycle = phase, &lifecycle
	next := x.record
	next.Version, next.HighWater = RunnerVersion, now.UnixMicro()
	next.Jobs = append([]diskJob(nil), x.record.Jobs...)
	next.Jobs[token.index] = job
	raw, err := encodeRecord(next)
	if err == nil {
		err = x.store.replace(ctx, raw)
	}
	if err != nil {
		// Even an error before writing the result poisons all handle copies.
		x.failed = err
		return Status{}, err
	}
	x.record = next
	if phase != Dispatching {
		x.active = nil
	}
	if canceled(ctx) {
		return Status{}, ErrCanceled
	}
	return status(job), nil
}
