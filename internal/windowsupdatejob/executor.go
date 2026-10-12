package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
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
// result/HRESULT/reboot flag. It must CheckInstallStart on the original kernel
// fence immediately before native dispatch after blocking preparation, separately
// from operation duration. Cancellation/timeout may leave WUA work running and
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

// InactiveExecutor remains the default. The separately constructed source-only
// windowsupdateexecutor adapter is not wired into a runtime or provisioner.
type InactiveExecutor struct{}

func (InactiveExecutor) PrepareExact(context.Context, Selection) (PreparedUpdate, error) {
	return nil, ErrUnavailable
}

type Attempt struct {
	Envelope     []byte  `json:"envelope"`
	ClaimedAt    int64   `json:"claimedAt"`
	Attempted    bool    `json:"attempted"`
	Result       *Result `json:"result"`
	ResultReport []byte  `json:"resultReport"`
}
type ExecutorRecord struct {
	Version           string            `json:"version"`
	Consent           Consent           `json:"consent"`
	PublicKey         []byte            `json:"publicKey"`
	ExecutorPublicKey []byte            `json:"executorPublicKey"`
	ClockFloor        int64             `json:"clockFloor"`
	Sequence          uint64            `json:"sequence,string"`
	ReadinessSequence uint64            `json:"readinessSequence,string"`
	LatestReadiness   *ReadinessAttempt `json:"latestReadiness"`
	Attempts          []Attempt         `json:"attempts"`
}

func NewExecutorRecord(c Consent, key, executorKey ed25519.PublicKey, now int64) (ExecutorRecord, error) {
	r := ExecutorRecord{Version: Version, Consent: c, PublicKey: bytes.Clone(key), ExecutorPublicKey: bytes.Clone(executorKey), ClockFloor: now, Attempts: []Attempt{}}
	return r, r.Validate()
}
func (r ExecutorRecord) Validate() error {
	if _, e := NewRecordWithExecutor(r.Consent, r.PublicKey, r.ExecutorPublicKey, r.ClockFloor); e != nil || r.Version != Version || r.Attempts == nil || len(r.Attempts) > MaxJobs {
		return ErrIntegrity
	}
	if e := r.validateReadiness(); e != nil {
		return e
	}
	var seq uint64
	ids := map[string]bool{}
	for _, a := range r.Attempts {
		p, e := Verify(a.Envelope, r.PublicKey)
		if e != nil || p.Preview.Binding != r.Consent.Binding || p.Sequence <= seq || ids[p.Preview.ID] || a.ClaimedAt < p.IssuedAt() || a.ClaimedAt >= p.Preview.ExpiresAt || a.ClaimedAt > r.ClockFloor {
			return ErrIntegrity
		}
		seq = p.Sequence
		ids[p.Preview.ID] = true
		if a.Result != nil && (a.Result.Validate() != nil || a.Result.JobID != p.Preview.ID || a.Result.EnvelopeDigest != actionpermit.Digest(a.Envelope) || a.Result.Attempted != a.Attempted || a.Result.CompletedAt < a.ClaimedAt || a.Result.CompletedAt > r.ClockFloor) {
			return ErrIntegrity
		}
		if e := r.validateResultReport(a, p); e != nil {
			return e
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
	key       ed25519.PrivateKey
	accepted  *Accepted
	running   bool
}

// OpenExecutor opens only previously provisioned protected state. The supplied
// dedicated executor private key must be internally consistent and match the
// exact public pin. It is never generated, saved or inferred from another domain.
func OpenExecutor(store Storage, authority Authority, adapter ExecutorAdapter, key ed25519.PrivateKey, now func() time.Time) (*Executor, error) {
	if store == nil || authority == nil || adapter == nil || now == nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])) {
		return nil, ErrInvalid
	}
	raw, e := store.Read("executor.json")
	var r ExecutorRecord
	if e != nil || canonical(raw, &r, MaxBytes) != nil || r.Validate() != nil || !bytes.Equal(key.Public().(ed25519.PublicKey), r.ExecutorPublicKey) {
		return nil, ErrIntegrity
	}
	x := &Executor{store: store, authority: authority, adapter: adapter, now: now, record: r, raw: bytes.Clone(raw), key: bytes.Clone(key)}
	if e = x.check(); e != nil {
		clear(x.key)
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

// clock is a non-writing final check. Never use a timestamp sampled before a
// durability wait to authorize source access or release an expiring report.
func (x *Executor) clock() (int64, error) {
	n := x.now().UTC().Unix()
	if !validTime(n) || n < x.record.ClockFloor {
		return n, ErrExpired
	}
	return n, nil
}
func (x *Executor) observeTime() (int64, error) {
	n, e := x.clock()
	if e != nil {
		return n, e
	}
	if n > x.record.ClockFloor {
		if e = x.saveFloor(n); e != nil {
			return n, e
		}
	}
	return x.clock()
}

// A rejected post-write observation must itself remain durable so rollback
// cannot revive expired authority. This terminal write releases no evidence and
// starts no source work, even if its persistence takes still more time.
func (x *Executor) rejectTime(n int64, reason error) error {
	if n > x.record.ClockFloor {
		if e := x.saveFloor(n); e != nil {
			return e
		}
	}
	return reason
}
func (x *Executor) current(c Current, p Permit) error {
	_, e := x.currentPermit(c, p)
	return e
}
func (x *Executor) currentPermit(c Current, p Permit) (int64, error) {
	n, e := x.currentAuthority(c)
	if e != nil {
		return n, e
	}
	if p.Preview.Binding != c.Binding {
		return n, x.rejectTime(n, ErrAuthority)
	}
	if p.Schedule != nil && (!x.record.Consent.ScheduleAcknowledged || x.record.Consent.ScheduleScope != ScheduleScope) {
		return n, x.rejectTime(n, ErrAuthority)
	}
	if n < p.IssuedAt() || n >= p.Preview.ExpiresAt {
		return n, x.rejectTime(n, ErrExpired)
	}
	return n, nil
}
func (x *Executor) save() error { return x.saveFloor(x.record.ClockFloor) }
func (x *Executor) saveFloor(minimum int64) error {
	n := x.now().UTC().Unix()
	if !validTime(n) || n < x.record.ClockFloor || n < minimum {
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

// Accepted is a private, one-use in-memory capability. It cannot be rebuilt from
// a persisted attempt, deserialized, or used by another Executor. Restarted or
// abandoned admissions remain status/outbox-only and block later installs.
type Accepted struct {
	owner *Executor
	index int
	used  bool
}

// Accept durably consumes one exact permit without any adapter access. The
// caller may acknowledge only after it succeeds. It must hand the capability to
// one independent owner, never retry submission after a lost acknowledgement.
func (x *Executor) Accept(ctx context.Context, raw []byte) (*Accepted, error) {
	if x == nil || !x.mu.TryLock() {
		return nil, ErrConflict
	}
	defer x.mu.Unlock()
	if ctx == nil {
		return nil, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := x.check(); e != nil {
		return nil, e
	}
	if _, e := x.observeTime(); e != nil {
		return nil, e
	}
	p, e := Verify(raw, x.record.PublicKey)
	if e != nil {
		return nil, e
	}
	for _, a := range x.record.Attempts {
		old, _ := Verify(a.Envelope, x.record.PublicKey)
		if old.Preview.ID == p.Preview.ID {
			// Reconciliation uses the authority-checked Status/Outbox paths.
			return nil, ErrConsumed
		}
		if a.Result == nil || a.Result.Outcome == "uncertain" || a.Result.Outcome == "failed" {
			return nil, ErrConflict
		}
	}
	if len(x.record.Attempts) >= MaxJobs || p.Sequence <= x.record.Sequence {
		return nil, ErrConsumed
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
		return nil, e
	}
	h := &Accepted{owner: x, index: len(x.record.Attempts) - 1}
	x.accepted = h
	return h, nil
}

// Execute is the synchronous compatibility seam. IPC uses Accept followed by
// RunAccepted in its one independent operation owner instead of waiting here.
func (x *Executor) Execute(ctx context.Context, raw []byte) (Result, error) {
	h, err := x.Accept(ctx, raw)
	if err != nil {
		return Result{}, err
	}
	return x.RunAccepted(ctx, h)
}

// RunAccepted never inherits a pipe connection context. Disconnect cannot cancel
// or replay an admitted operation. The long install runs outside the record
// mutex; preparation yields bounded busy via TryLock, then Status/Outbox remain usable and a second owner cannot enter.
func (x *Executor) RunAccepted(ctx context.Context, h *Accepted) (Result, error) {
	if x == nil || ctx == nil {
		return Result{}, ErrInvalid
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if h == nil || h.owner != x || h != x.accepted || h.used || x.running || h.index != len(x.record.Attempts)-1 || x.failed {
		return Result{}, ErrConsumed
	}
	h.used = true
	x.running = true
	defer func() { x.running = false; x.accepted = nil }()
	raw := x.record.Attempts[h.index].Envelope
	p, e := Verify(raw, x.record.PublicKey)
	if e != nil || x.record.Attempts[h.index].Result != nil {
		return Result{}, ErrIntegrity
	}

	a := &x.record.Attempts[len(x.record.Attempts)-1]
	finish := func(outcome string, native NativeResult) (Result, error) {
		r := Result{JobID: p.Preview.ID, EnvelopeDigest: actionpermit.Digest(raw), Attempted: a.Attempted, Outcome: outcome, OperationResult: native.OperationResult, HResult: native.HResult, RebootRequired: native.RebootRequired, CompletedAt: x.now().UTC().Unix()}
		if r.Validate() != nil {
			return Result{}, ErrInvalid
		}
		// Evidence is signed once at the actual completion time and persisted in
		// the same record as Result. Recovery never synthesizes either field.
		report, e := SignStatement(Statement{Version: RelayVersion, Kind: "result", Binding: x.record.Consent.Binding, JobID: r.JobID, ReferenceDigest: r.EnvelopeDigest, Deadline: p.Preview.ExpiresAt, IssuedAt: r.CompletedAt, ExpiresAt: min(r.CompletedAt+300, int64(253402300799)), Result: &r}, x.key)
		if e != nil {
			x.failed = true
			return Result{}, ErrUncertain
		}
		a.Result = &r
		a.ResultReport = report
		if e := x.save(); e != nil {
			return Result{}, e
		}
		return r, nil
	}
	noAttempt := func() (Result, error) { return finish("not_attempted", NativeResult{RebootRequired: Unknown}) }
	var prepared PreparedUpdate
	var readiness Readiness
	var sourceAt int64
	// Consumption is irrevocable, but it is not authority to begin native reads
	// after a slow write or a local credential/consent change.
	e = x.authority.WithCurrent(ctx, x.record.Consent.Binding, func(c Current) error {
		if err := x.check(); err != nil {
			return err
		}
		var err error
		sourceAt, err = x.currentPermit(c, p)
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		prepared, err = x.adapter.PrepareExact(ctx, p.Preview.Readiness.Selection)
		if err != nil || prepared == nil {
			return ErrUnavailable
		}
		readiness, err = prepared.Inspect(ctx)
		return err
	})
	if e != nil || prepared == nil {
		if prepared != nil {
			_ = prepared.Close()
		}
		if x.failed {
			return Result{}, ErrUncertain
		}
		return noAttempt()
	}
	if readiness.Reason() != "ready" || !SameFacts(readiness, p.Preview.Readiness) || readiness.CapturedAt < sourceAt || readiness.CapturedAt > x.now().UTC().Unix() {
		_ = prepared.Close()
		return noAttempt()
	}

	var result NativeResult
	var startCtx context.Context
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
		startCtx = withInstallStartFence(ctx, x.record.ClockFloor, p.Preview.ExpiresAt, x.record.Consent.ExpiresAt, c.LeafNotAfter)
		startCtx = withInstallStartCurrent(startCtx, x.now, func(start context.Context) (installStartBounds, error) {
			if !x.mu.TryLock() {
				return installStartBounds{}, ErrConflict
			}
			defer x.mu.Unlock()
			if x.failed || x.accepted != h || !x.running || !h.used {
				return installStartBounds{}, ErrAuthority
			}
			var admitted Current
			err := x.authority.WithCurrent(start, x.record.Consent.Binding, func(fresh Current) error {
				if err := x.check(); err != nil {
					return err
				}
				if err := x.current(fresh, p); err != nil {
					return err
				}
				admitted = fresh
				return start.Err()
			})
			if err != nil {
				return installStartBounds{}, err
			}
			// WithCurrent may itself finish slowly. Carry the current leaf and
			// latest durable floor to the adapter's post-callback time sample.
			n, err := x.clock()
			if err != nil {
				return installStartBounds{}, err
			}
			if admitted.Binding != x.record.Consent.Binding || !admitted.Enabled || admitted.Revoked || n >= admitted.LeafNotAfter || n >= x.record.Consent.ExpiresAt || n >= p.Preview.ExpiresAt {
				return installStartBounds{}, ErrExpired
			}
			return installStartBounds{x.record.ClockFloor, x.record.Consent.ExpiresAt, admitted.LeafNotAfter}, start.Err()
		})
		return nil
	})
	x.mu.Unlock()
	if e == nil {
		result, e = prepared.InstallOnce(startCtx)
	}
	closeErr := prepared.Close()
	x.mu.Lock()
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

// Close clears only the in-memory signing key. Protected evidence is retained.
func (x *Executor) Close() {
	if x == nil {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.failed = true
	clear(x.key)
}
func (*Executor) String() string   { return "<dedicated Windows update executor>" }
func (*Executor) GoString() string { return "<dedicated Windows update executor>" }
func (*Executor) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "<dedicated Windows update executor>")
}
func (*Executor) MarshalJSON() ([]byte, error) { return []byte(`{"secretsRedacted":true}`), nil }
