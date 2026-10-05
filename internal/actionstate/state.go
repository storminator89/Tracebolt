// Package actionstate is a durable action-consumption and runner lifecycle core.
// It has no executor, transport, policy loader or host setup. Status is metadata;
// only a fresh Begin can issue an ephemeral, non-reconstructable Attempt.
package actionstate

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"localrmm/internal/actionpermit"
)

const (
	Version            = "tracebolt.action-consumption.v1"
	RunnerVersion      = "tracebolt.action-consumption.v2"
	MaxJobs            = 64
	MaxStateBytes      = 512 << 10
	Admitted           = "admitted"
	Expired            = "expired"
	NeedsIntervention  = "needs_intervention"
	Dispatching        = "dispatching"
	NotStarted         = "not_started"
	OperationCompleted = "operation_completed"
)

var (
	ErrUnsupported = errors.New("action_state_linux_only")
	ErrUnsafe      = errors.New("action_state_unsafe")
	ErrCorrupt     = errors.New("action_state_absent_or_corrupt")
	ErrIO          = errors.New("action_state_unavailable")
	ErrLocked      = errors.New("action_state_locked")
	ErrBinding     = errors.New("action_state_binding_mismatch")
	ErrConflict    = errors.New("action_state_job_conflict")
	ErrReplay      = errors.New("action_state_sequence_consumed")
	ErrBusy        = errors.New("action_state_unresolved_admission")
	ErrCapacity    = errors.New("action_state_capacity")
	ErrNotFound    = errors.New("action_state_job_not_found")
	ErrClosed      = errors.New("action_state_closed")
	ErrCanceled    = errors.New("action_state_canceled")
	ErrUncertain   = errors.New("action_state_uncertain_preserve_for_inspection")
	ErrAttempt     = errors.New("action_state_invalid_or_used_attempt")
	ErrTransition  = errors.New("action_state_invalid_transition")
)

// Status is immutable approval/admission metadata, never an execution permit.
// Admitted and Dispatching do not claim that anything was started. A completed
// operation is separate from the bounded service state observed afterwards.
type Status struct {
	Permit         actionpermit.Permit
	EnvelopeDigest string
	Phase          string
	ConsumedAt     time.Time
	DispatchAt     time.Time
	TransitionAt   time.Time
	Reason         NotStartedReason
	Outcome        Outcome
	ObservedState  ObservedState
}

// State copies share one exclusive OS lifetime lock and poisoned-state flag.
type State struct{ inner *state }
type state struct {
	mu       sync.Mutex
	store    storage
	verifier actionpermit.Verifier
	record   diskRecord
	closed   bool
	failed   error
	active   *attempt
}
type storage interface {
	verify() error
	replace(context.Context, []byte) error
	close() error
}

// Initialize is create-only and is not connected to a runtime. Its eventual
// authorized local setup must establish a fresh action domain and independently
// trusted pins. Never use it to recover a missing ledger or reset a used floor.
// Storage is protected for the current UID; only an independently checked root
// runtime may claim root protection. Tests use unprivileged disposable directories.
func Initialize(ctx context.Context, dir string, verifier actionpermit.Verifier) (*State, error) {
	return open(ctx, dir, verifier, true)
}

// Open is existing-only. It never resets missing state, repairs permissions,
// removes crash temporaries, rotates keys or migrates an endpoint incarnation.
// Reopened admission is durably marked needs_intervention before returning.
func Open(ctx context.Context, dir string, verifier actionpermit.Verifier) (*State, error) {
	return open(ctx, dir, verifier, false)
}

func open(ctx context.Context, dir string, verifier actionpermit.Verifier, initialize bool) (*State, error) {
	if canceled(ctx) {
		return nil, ErrCanceled
	}
	binding, err := verifier.BindingDigest()
	if err != nil {
		return nil, ErrBinding
	}
	store, raw, err := newStorage(ctx, dir, initialize)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*State, error) { _ = store.close(); return nil, err }
	r := diskRecord{Version: Version, BindingDigest: binding, Jobs: []diskJob{}}
	if !initialize {
		r, err = decodeRecord(raw, verifier)
		if err != nil {
			return fail(err)
		}
		if r.BindingDigest != binding {
			return fail(ErrBinding)
		}
	}
	changed := initialize
	for i := range r.Jobs {
		if r.Jobs[i].Phase == Admitted || r.Jobs[i].Phase == Dispatching {
			r.Jobs[i].Phase = NeedsIntervention
			if r.Jobs[i].Lifecycle != nil {
				// Recovery cannot establish when or whether an invocation ran.
				// Preserve the last recorded clock rather than inventing a time.
				r.Jobs[i].Lifecycle.Outcome = OutcomeUnknown
				r.Jobs[i].Lifecycle.ObservedState = ObservedUnknown
			}
			changed = true
		}
	}
	if changed {
		raw, err = encodeRecord(r)
		if err == nil {
			err = store.replace(ctx, raw)
		}
		if err != nil {
			return fail(err)
		}
	}
	if canceled(ctx) {
		return fail(ErrCanceled)
	}
	return &State{&state{store: store, verifier: verifier, record: r}}, nil
}

func canceled(ctx context.Context) bool { return ctx == nil || ctx.Err() != nil }

func (s *state) check(ctx context.Context) error {
	if s.closed {
		return ErrClosed
	}
	if s.failed != nil {
		return s.failed
	}
	if canceled(ctx) {
		return ErrCanceled
	}
	if err := s.store.verify(); err != nil {
		s.failed = err
		return err
	}
	return nil
}

// Admit durably consumes a valid permit before returning admitted metadata. It
// never returns a launch token or callback. Exact duplicates return the existing
// status, even after expiry or disable; their times/phase/floor are unchanged.
// New admissions stop behind any unresolved admission or uncertain outcome.
// Authenticated expired permits consume their sequence, preventing clock revival.
func (s State) Admit(ctx context.Context, raw []byte, now time.Time) (Status, error) {
	got, _, err := s.begin(ctx, raw, now, false)
	return got, err
}

// Begin durably admits a fresh permit and issues its sole live Attempt. Exact
// duplicates (including Admit's legacy admissions), expired permits and every
// failure return a nil Attempt. Neither Status nor reopening can mint one.
// A caller must still enforce live authority and resample its trusted clock
// after every durability wait, immediately before invoking its fixed backend.
func (s State) Begin(ctx context.Context, raw []byte, now time.Time) (Status, *Attempt, error) {
	return s.begin(ctx, raw, now, true)
}

func (s State) begin(ctx context.Context, raw []byte, now time.Time, runner bool) (Status, *Attempt, error) {
	if s.inner == nil {
		return Status{}, nil, ErrClosed
	}
	x := s.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.check(ctx); err != nil {
		return Status{}, nil, err
	}
	if len(raw) == 0 || len(raw) > actionpermit.MaxPermitBytes {
		return Status{}, nil, actionpermit.ErrInvalid
	}
	raw = bytes.Clone(raw)
	p, err := actionpermit.Decode(raw)
	if err != nil {
		return Status{}, nil, err
	}
	for _, job := range x.record.Jobs {
		old, _ := actionpermit.Decode(job.Envelope)
		if old.JobID == p.JobID {
			if !bytes.Equal(raw, job.Envelope) {
				return Status{}, nil, ErrConflict
			}
			return status(job), nil, nil
		}
	}
	p, err = x.verifier.Verify(raw)
	if err != nil {
		return Status{}, nil, err
	}
	if p.Sequence <= x.record.Floor {
		return Status{}, nil, ErrReplay
	}
	if now.Location() != time.UTC || now.Year() < 1970 || now.Year() > 9999 || now.UnixMicro() < x.record.HighWater {
		return Status{}, nil, actionpermit.ErrClock
	}
	timeErr := x.verifier.CheckTime(p, now)
	if timeErr != nil && !errors.Is(timeErr, actionpermit.ErrExpired) {
		return Status{}, nil, timeErr
	}
	for _, job := range x.record.Jobs {
		if job.Phase == Admitted || job.Phase == Dispatching || job.Phase == NeedsIntervention {
			return Status{}, nil, ErrBusy
		}
	}
	if len(x.record.Jobs) >= MaxJobs {
		return Status{}, nil, ErrCapacity
	}
	phase := Admitted
	if timeErr != nil {
		phase = Expired
	}
	job := diskJob{Envelope: append([]byte(nil), raw...), Phase: phase, ConsumedAt: now.UnixMicro()}
	next := x.record
	if runner && phase == Admitted {
		next.Version = RunnerVersion
		job.Lifecycle = &diskLifecycle{TransitionAt: now.UnixMicro()}
	}
	next.Jobs = append(append([]diskJob(nil), x.record.Jobs...), job)
	next.Floor, next.HighWater = p.Sequence, now.UnixMicro()
	encoded, err := encodeRecord(next)
	if err != nil {
		return Status{}, nil, err
	}
	if err = x.store.replace(ctx, encoded); err != nil {
		// Conservatively poison all write failures, including pre-write failures.
		x.failed = err
		return Status{}, nil, err
	}
	x.record = next
	if canceled(ctx) {
		return Status{}, nil, ErrCanceled
	}
	if runner && phase == Admitted {
		token := &attempt{owner: x, index: len(next.Jobs) - 1}
		x.active = token
		return status(job), &Attempt{inner: token}, nil
	}
	return status(job), nil, timeErr
}

// Status looks up only original metadata. It never issues a permit, changes a
// deadline or turns expiry of an admitted job into evidence it is safe to retry.
func (s State) Status(ctx context.Context, jobID string) (Status, error) {
	if s.inner == nil {
		return Status{}, ErrClosed
	}
	x := s.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.check(ctx); err != nil {
		return Status{}, err
	}
	for _, job := range x.record.Jobs {
		p, _ := actionpermit.Decode(job.Envelope)
		if p.JobID == jobID {
			return status(job), nil
		}
	}
	return Status{}, ErrNotFound
}

// BindingDigest returns the original manager/key/endpoint/incarnation binding.
// Policy or transport-profile changes never create a new consumption domain.
func (s State) BindingDigest(ctx context.Context) (string, error) {
	if s.inner == nil {
		return "", ErrClosed
	}
	x := s.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.check(ctx); err != nil {
		return "", err
	}
	return x.record.BindingDigest, nil
}

func (s State) Close() error {
	if s.inner == nil {
		return ErrClosed
	}
	x := s.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return nil
	}
	x.closed = true
	return x.store.close()
}

// RootPolicyDigest describes the verifier opened with this live State handle.
// It does not update policy, reset history or mint an Attempt.
func (s State) RootPolicyDigest(ctx context.Context) (string, error) {
	if s.inner == nil {
		return "", ErrClosed
	}
	x := s.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.check(ctx); err != nil {
		return "", err
	}
	return x.verifier.RootPolicyDigest()
}
