package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"time"

	"localrmm/internal/actionpermit"
)

// ExecutorAdapter belongs to a dedicated elevated executor. It must not be
// implemented by the observation worker or the selected-service broker.
// PrepareExact uses one cached-only, no-self-upgrade search and pins the exact
// IUpdate identity/revision. It must not download, accept terms, register a
// source, close applications, change services/policy, or reboot.
type ExecutorAdapter interface {
	PrepareExact(context.Context, Selection) (PreparedUpdate, error)
}

// PreparedUpdate owns that pinned WUA object. Inspect reads ALL readiness facts
// including the full BundledUpdates count; any unreadable fact stays unknown.
// InstallOnce performs at most one IUpdateInstaller.Install over that one object,
// with AllowSourcePrompts=false, IsForced=false and supported quiet/no-app-close
// safeguards set and read back. It must independently recheck readiness just
// before dispatch, never replace the identity/revision, and return each update's
// result/HRESULT/reboot flag. Cancellation/timeout may leave WUA work running and
// must return uncertainty; it must never retry or claim rollback.
type PreparedUpdate interface {
	Inspect(context.Context) (Readiness, error)
	InstallOnce(context.Context) (NativeResult, error)
	Close() error
}
type NativeResult struct {
	OperationResult uint32
	HResult         int32
	RebootRequired  Fact
}

// InactiveExecutor is the only supplied adapter. There is deliberately no WUA
// installer, elevated service/ACL provisioner or endpoint IPC in this slice.
type InactiveExecutor struct{}

func (InactiveExecutor) PrepareExact(context.Context, Selection) (PreparedUpdate, error) {
	return nil, ErrUnavailable
}

type Attempt struct {
	Envelope  []byte  `json:"envelope"`
	ClaimedAt int64   `json:"claimedAt"`
	Attempted bool    `json:"attempted"`
	Result    *Result `json:"result"`
}
type ExecutorRecord struct {
	Version           string    `json:"version"`
	Consent           Consent   `json:"consent"`
	PublicKey         []byte    `json:"publicKey"`
	ExecutorPublicKey []byte    `json:"executorPublicKey"`
	ClockFloor        int64     `json:"clockFloor"`
	Sequence          uint64    `json:"sequence,string"`
	Attempts          []Attempt `json:"attempts"`
}

func NewExecutorRecord(c Consent, key, executorKey ed25519.PublicKey, now int64) (ExecutorRecord, error) {
	r := ExecutorRecord{Version: Version, Consent: c, PublicKey: bytes.Clone(key), ExecutorPublicKey: bytes.Clone(executorKey), ClockFloor: now, Attempts: []Attempt{}}
	return r, r.Validate()
}
func (r ExecutorRecord) Validate() error {
	if _, e := NewRecordWithExecutor(r.Consent, r.PublicKey, r.ExecutorPublicKey, r.ClockFloor); e != nil || r.Version != Version || r.Attempts == nil || len(r.Attempts) > MaxJobs {
		return ErrIntegrity
	}
	var seq uint64
	ids := map[string]bool{}
	for _, a := range r.Attempts {
		p, e := Verify(a.Envelope, r.PublicKey)
		if e != nil || p.Preview.Binding != r.Consent.Binding || p.Sequence <= seq || ids[p.Preview.ID] || a.ClaimedAt < p.ApprovedAt || a.ClaimedAt >= p.Preview.ExpiresAt || a.ClaimedAt > r.ClockFloor {
			return ErrIntegrity
		}
		seq = p.Sequence
		ids[p.Preview.ID] = true
		if a.Result != nil && (a.Result.Validate() != nil || a.Result.JobID != p.Preview.ID || a.Result.EnvelopeDigest != actionpermit.Digest(a.Envelope) || a.Result.Attempted != a.Attempted || a.Result.CompletedAt < a.ClaimedAt || a.Result.CompletedAt > r.ClockFloor) {
			return ErrIntegrity
		}
	}
	if seq != r.Sequence {
		return ErrIntegrity
	}
	return nil
}
func EncodeExecutorRecord(r ExecutorRecord) ([]byte, error) {
	if r.Validate() != nil {
		return nil, ErrIntegrity
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxBytes {
		return nil, ErrIntegrity
	}
	return raw, nil
}

type Executor struct {
	mu        sync.Mutex
	store     Storage
	authority Authority
	adapter   ExecutorAdapter
	now       func() time.Time
	record    ExecutorRecord
	raw       []byte
	failed    bool
}

func OpenExecutor(store Storage, authority Authority, adapter ExecutorAdapter, now func() time.Time) (*Executor, error) {
	if store == nil || authority == nil || adapter == nil || now == nil {
		return nil, ErrInvalid
	}
	raw, e := store.Read("executor.json")
	var r ExecutorRecord
	if e != nil || canonical(raw, &r, MaxBytes) != nil || r.Validate() != nil {
		return nil, ErrIntegrity
	}
	x := &Executor{store: store, authority: authority, adapter: adapter, now: now, record: r, raw: bytes.Clone(raw)}
	if e = x.check(); e != nil {
		return nil, e
	}
	return x, nil
}
func (x *Executor) check() error {
	if x.failed || x.store.Verify() != nil {
		x.failed = true
		return ErrIntegrity
	}
	raw, e := x.store.Read("executor.json")
	if e != nil || !bytes.Equal(raw, x.raw) {
		x.failed = true
		return ErrIntegrity
	}
	want, _ := json.Marshal(x.record.Consent)
	for _, name := range []string{"started.json", "receipt.json"} {
		raw, e = x.store.Read(name)
		if e != nil || !bytes.Equal(raw, want) {
			x.failed = true
			return ErrIntegrity
		}
	}
	return nil
}
func (x *Executor) observeTime() (int64, error) {
	n := x.now().UTC().Unix()
	if !validTime(n) || n < x.record.ClockFloor {
		return n, ErrExpired
	}
	if n > x.record.ClockFloor {
		if e := x.save(); e != nil {
			return n, e
		}
	}
	return n, nil
}
func (x *Executor) current(c Current, p Permit) error {
	n, e := x.observeTime()
	if e != nil {
		return e
	}
	if c.Binding != x.record.Consent.Binding || p.Preview.Binding != c.Binding || !c.Enabled || c.Revoked || !actionpermit.ValidDigest(c.LeafDigest) || c.LeafGeneration == 0 || !x.record.Consent.Enabled || !x.record.Consent.Acknowledged {
		return ErrAuthority
	}
	if !validTime(n) || n < x.record.ClockFloor || n < c.LeafNotBefore || n >= c.LeafNotAfter || n >= x.record.Consent.ExpiresAt || n < p.ApprovedAt || n >= p.Preview.ExpiresAt {
		return ErrExpired
	}
	return nil
}
func (x *Executor) save() error {
	n := x.now().UTC().Unix()
	if !validTime(n) || n < x.record.ClockFloor {
		x.failed = true
		return ErrUncertain
	}
	x.record.ClockFloor = n
	raw, e := EncodeExecutorRecord(x.record)
	if e != nil || x.store.Write("executor.json", raw) != nil {
		x.failed = true
		return ErrUncertain
	}
	x.raw = bytes.Clone(raw)
	return nil
}

// Execute consumes once BEFORE source access, then persists Attempted BEFORE
// dispatch. A reopened unfinished attempt is status-only and blocks new jobs.
func (x *Executor) Execute(ctx context.Context, raw []byte) (Result, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if ctx == nil {
		return Result{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	if e := x.check(); e != nil {
		return Result{}, e
	}
	if _, e := x.observeTime(); e != nil {
		return Result{}, e
	}
	p, e := Verify(raw, x.record.PublicKey)
	if e != nil {
		return Result{}, e
	}
	for _, a := range x.record.Attempts {
		old, _ := Verify(a.Envelope, x.record.PublicKey)
		if old.Preview.ID == p.Preview.ID {
			if a.Result != nil && bytes.Equal(a.Envelope, raw) {
				return *a.Result, ErrConsumed
			}
			return Result{}, ErrConsumed
		}
		if a.Result == nil || a.Result.Outcome == "uncertain" || a.Result.Outcome == "failed" {
			return Result{}, ErrConflict
		}
	}
	if len(x.record.Attempts) >= MaxJobs || p.Sequence <= x.record.Sequence {
		return Result{}, ErrConsumed
	}
	e = x.authority.WithCurrent(ctx, x.record.Consent.Binding, func(c Current) error {
		if e := x.current(c, p); e != nil {
			return e
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		x.record.Sequence = p.Sequence
		x.record.Attempts = append(x.record.Attempts, Attempt{Envelope: bytes.Clone(raw), ClaimedAt: x.now().UTC().Unix()})
		return x.save()
	})
	if e != nil {
		return Result{}, e
	}
	a := &x.record.Attempts[len(x.record.Attempts)-1]
	finish := func(outcome string, native NativeResult) (Result, error) {
		r := Result{JobID: p.Preview.ID, EnvelopeDigest: actionpermit.Digest(raw), Attempted: a.Attempted, Outcome: outcome, OperationResult: native.OperationResult, HResult: native.HResult, RebootRequired: native.RebootRequired, CompletedAt: x.now().UTC().Unix()}
		if r.Validate() != nil {
			return Result{}, ErrInvalid
		}
		a.Result = &r
		if e := x.save(); e != nil {
			return Result{}, e
		}
		return r, nil
	}
	noAttempt := func() (Result, error) { return finish("not_attempted", NativeResult{RebootRequired: Unknown}) }
	prepared, e := x.adapter.PrepareExact(ctx, p.Preview.Readiness.Selection)
	if e != nil || prepared == nil {
		return noAttempt()
	}
	readiness, e := prepared.Inspect(ctx)
	if e != nil || readiness.Reason() != "ready" || !SameFacts(readiness, p.Preview.Readiness) || readiness.CapturedAt < x.record.ClockFloor || readiness.CapturedAt > x.now().UTC().Unix() {
		_ = prepared.Close()
		return noAttempt()
	}
	var result NativeResult
	e = x.authority.WithCurrent(ctx, x.record.Consent.Binding, func(c Current) error {
		if e := x.check(); e != nil {
			return e
		}
		if e := x.current(c, p); e != nil {
			return e
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		a.Attempted = true
		if e := x.save(); e != nil {
			return e
		}
		// Retest time after durable persistence while the same live fence is held.
		if e := x.current(c, p); e != nil {
			return e
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		var err error
		result, err = prepared.InstallOnce(ctx)
		return err
	})
	closeErr := prepared.Close()
	if x.failed {
		return Result{}, ErrUncertain
	}
	if !a.Attempted {
		return noAttempt()
	}
	if e != nil || closeErr != nil || !fact(result.RebootRequired) || result.OperationResult > 5 {
		return finish("uncertain", NativeResult{RebootRequired: Unknown})
	}
	switch result.OperationResult {
	case 2:
		if result.HResult >= 0 && result.RebootRequired != Unknown {
			return finish("succeeded", result)
		}
	case 4, 5:
		return finish("failed", result)
	}
	return finish("uncertain", result)
}
