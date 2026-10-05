// Package actionstate is an inert, durable action-consumption/status core.
// It has no executor, launch permission, transport, policy loader or host setup.
// Admission is metadata only and cannot be wired directly to a privileged start.
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
	Version           = "tracebolt.action-consumption.v1"
	MaxJobs           = 64
	MaxStateBytes     = 512 << 10
	Admitted          = "admitted"
	Expired           = "expired"
	NeedsIntervention = "needs_intervention"
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
)

// Status is immutable approval/admission metadata, never an execution permit.
// Admitted does not claim that anything was started. This slice cannot report
// running, succeeded, failed, canceled or a host outcome it cannot establish.
type Status struct {
	Permit         actionpermit.Permit
	EnvelopeDigest string
	Phase          string
	ConsumedAt     time.Time
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
}
type storage interface {
	verify() error
	replace(context.Context, []byte) error
	close() error
}

// Initialize is create-only and is not connected to a runtime. Its eventual
// authorized local setup must establish a fresh action domain and independently
// trusted pins. Never use it to recover a missing ledger or reset a used floor.
// Storage is protected for the current UID; only a future root-owned adapter
// may claim it is root-protected. Tests use unprivileged disposable directories.
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
		if r.Jobs[i].Phase == Admitted {
			r.Jobs[i].Phase = NeedsIntervention
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
	if s.inner == nil {
		return Status{}, ErrClosed
	}
	x := s.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.check(ctx); err != nil {
		return Status{}, err
	}
	if len(raw) == 0 || len(raw) > actionpermit.MaxPermitBytes {
		return Status{}, actionpermit.ErrInvalid
	}
	raw = bytes.Clone(raw)
	p, err := actionpermit.Decode(raw)
	if err != nil {
		return Status{}, err
	}
	for _, job := range x.record.Jobs {
		old, _ := actionpermit.Decode(job.Envelope)
		if old.JobID == p.JobID {
			if !bytes.Equal(raw, job.Envelope) {
				return Status{}, ErrConflict
			}
			return status(job), nil
		}
	}
	p, err = x.verifier.Verify(raw)
	if err != nil {
		return Status{}, err
	}
	if p.Sequence <= x.record.Floor {
		return Status{}, ErrReplay
	}
	if now.Location() != time.UTC || now.Year() < 1970 || now.Year() > 9999 || now.UnixMicro() < x.record.HighWater {
		return Status{}, actionpermit.ErrClock
	}
	timeErr := x.verifier.CheckTime(p, now)
	if timeErr != nil && !errors.Is(timeErr, actionpermit.ErrExpired) {
		return Status{}, timeErr
	}
	for _, job := range x.record.Jobs {
		if job.Phase == Admitted || job.Phase == NeedsIntervention {
			return Status{}, ErrBusy
		}
	}
	if len(x.record.Jobs) >= MaxJobs {
		return Status{}, ErrCapacity
	}
	phase := Admitted
	if timeErr != nil {
		phase = Expired
	}
	job := diskJob{Envelope: append([]byte(nil), raw...), Phase: phase, ConsumedAt: now.UnixMicro()}
	next := x.record
	next.Jobs = append(append([]diskJob(nil), x.record.Jobs...), job)
	next.Floor, next.HighWater = p.Sequence, now.UnixMicro()
	encoded, err := encodeRecord(next)
	if err != nil {
		return Status{}, err
	}
	if err = x.store.replace(ctx, encoded); err != nil {
		// Conservatively poison all write failures, including pre-write failures.
		x.failed = err
		return Status{}, err
	}
	x.record = next
	if canceled(ctx) {
		return Status{}, ErrCanceled
	}
	return status(job), timeErr
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
