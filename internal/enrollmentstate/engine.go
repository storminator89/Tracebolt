package enrollmentstate

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"sort"
	"sync"
)

type record struct {
	snapshot           Snapshot
	verifier           [32]byte
	publicKeyDERBase64 string
}

// Engine is bounded, process-local and non-durable. Copies share one locked
// private state; copying the handle never copies its mutex. An external
// transaction/reconciliation layer is required before any signing or delivery.
// Operator commands here are privileged internal calls, not authenticated APIs.
// A context cancellation observed before the locked commit causes no mutation;
// cancellation after the linearization point cannot undo a committed operation.
type Engine struct{ *engineState }

type engineState struct {
	mu      sync.Mutex
	config  Config
	records map[string]record
}

func (Engine) String() string               { return "enrollment state (contents redacted; non-durable)" }
func (Engine) GoString() string             { return "enrollmentstate.Engine{contents:redacted}" }
func (e Engine) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.String()) }
func (Engine) MarshalJSON() ([]byte, error) {
	return []byte(`{"contentsRedacted":true,"durable":false}`), nil
}

func DefaultConfig(binding Binding) Config {
	return Config{Binding: binding, InvitationTTL: MaxInvitationTTL, PendingTTL: MaxPendingTTL, RecordLimit: MaxRecords, InvitationLimit: MaxInvitations, PendingLimit: MaxPending}
}

func New(config Config) (*Engine, error) {
	if validateConfig(config) != nil {
		return nil, ErrInvalid
	}
	return &Engine{engineState: &engineState{config: config, records: make(map[string]record)}}, nil
}

func (e *Engine) Get(id string) (Snapshot, error) {
	if e == nil || e.engineState == nil || !validID(id, "invite") {
		return Snapshot{}, ErrInvalid
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.records[id]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	return r.snapshot, nil
}

// Snapshots returns a newly allocated, sorted copy. It excludes private verifiers.
func (e *Engine) Snapshots() []Snapshot {
	if e == nil || e.engineState == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s := make([]Snapshot, 0, len(e.records))
	for _, r := range e.records {
		s = append(s, r.snapshot)
	}
	sort.Slice(s, func(i, j int) bool { return s[i].InvitationID < s[j].InvitationID })
	return s
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	return ctx.Err()
}

func (e *Engine) CreateInvitation(ctx context.Context, c CreateCommand) (Snapshot, error) {
	if e == nil || e.engineState == nil || validateCreate(c) != nil {
		return Snapshot{}, ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	h := hashBytes(c.InvitationHash)
	if r, ok := e.records[c.InvitationID]; ok {
		s := r.snapshot
		if s.CreateRequestID != c.RequestID || s.Platform != c.Platform || subtle.ConstantTimeCompare(r.verifier[:], h[:]) != 1 {
			return Snapshot{}, ErrConflict
		}
		if s.State != Created {
			return Snapshot{}, ErrState
		}
		if c.Now < s.UpdatedAt {
			return Snapshot{}, ErrInvalid
		}
		if c.Now >= s.DeadlineAt {
			return Snapshot{}, ErrExpired
		}
		return s, nil
	}
	if e.requestUsed(c.RequestID) {
		return Snapshot{}, ErrConflict
	}
	// Reusing a verifier would let one invitation secret authorize another
	// public invitation ID. Keep this uniqueness constraint across tombstones.
	for _, r := range e.records {
		if subtle.ConstantTimeCompare(r.verifier[:], h[:]) == 1 {
			return Snapshot{}, ErrConflict
		}
	}
	if len(e.records) >= e.config.RecordLimit || e.count(Created) >= e.config.InvitationLimit {
		return Snapshot{}, ErrCapacity
	}
	s := Snapshot{Version: SnapshotVersion, Binding: e.config.Binding, InvitationID: c.InvitationID, CreateRequestID: c.RequestID, Platform: c.Platform, Revision: 1, State: Created, CreatedAt: c.Now, DeadlineAt: c.Now + e.config.InvitationTTL, UpdatedAt: c.Now}
	if ValidateSnapshot(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	e.records[c.InvitationID] = record{snapshot: s, verifier: h}
	return s, nil
}

func (e *Engine) Approve(ctx context.Context, c ApproveCommand) (Snapshot, error) {
	if e == nil || e.engineState == nil || validateApprove(c) != nil {
		return Snapshot{}, ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.lookup(ctx, c.Control)
	if err != nil {
		return Snapshot{}, err
	}
	s := r.snapshot
	if s.State == Approved {
		if s.Approval.RequestID != c.Control.RequestID || s.Approval.DeviceID != c.DeviceID || s.Approval.KeyFingerprint != c.KeyFingerprint {
			return Snapshot{}, ErrConflict
		}
		return s, nil
	}
	if s.State != ClaimedPending {
		return Snapshot{}, ErrState
	}
	if err := e.cas(s, c.Control); err != nil {
		return Snapshot{}, err
	}
	if c.KeyFingerprint != s.Claim.KeyFingerprint {
		return Snapshot{}, ErrProof
	}
	for _, r := range e.records {
		if r.snapshot.Approval.DeviceID == c.DeviceID {
			return Snapshot{}, ErrConflict
		}
	}
	s.State = Approved
	s.Approval = Approval{RequestID: c.Control.RequestID, DeviceID: c.DeviceID, KeyFingerprint: c.KeyFingerprint, At: c.Control.Now}
	return e.commit(ctx, r, s, c.Control.Now)
}

func (e *Engine) BeginIssuance(ctx context.Context, c IntentCommand) (Snapshot, error) {
	if e == nil || e.engineState == nil || validateIntent(c) != nil {
		return Snapshot{}, ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.lookup(ctx, c.Control)
	if err != nil {
		return Snapshot{}, err
	}
	s := r.snapshot
	i := Intent{IntentID: c.IntentID, RequestID: c.Control.RequestID, SerialHex: c.SerialHex, TemplateVersion: c.TemplateVersion, DeviceID: s.Approval.DeviceID, KeyFingerprint: s.Claim.KeyFingerprint, NotBefore: c.NotBefore, NotAfter: c.NotAfter, At: c.Control.Now}
	if s.State == IssuanceIntent {
		i.At = s.Intent.At
		if i != s.Intent {
			return Snapshot{}, ErrConflict
		}
		return s, nil
	}
	if s.State != Approved {
		return Snapshot{}, ErrState
	}
	if c.NotBefore > c.Control.Now || c.NotBefore < c.Control.Now-300 || c.NotAfter <= c.Control.Now {
		return Snapshot{}, ErrInvalid
	}
	if err := e.cas(s, c.Control); err != nil {
		return Snapshot{}, err
	}
	for _, r := range e.records {
		if r.snapshot.Intent.IntentID == c.IntentID || r.snapshot.Intent.SerialHex == c.SerialHex {
			return Snapshot{}, ErrConflict
		}
	}
	s.State = IssuanceIntent
	s.Intent = i
	if err := validateSigningIntent(r, s); err != nil {
		return Snapshot{}, err
	}
	return e.commit(ctx, r, s, c.Control.Now)
}

// Terminate records a retained tombstone. Expiry is explicit: a rejected expired
// operation never secretly changes state. Cancel is allowed before activation;
// reject only before approval; revocation is required after activation.
func (e *Engine) Terminate(ctx context.Context, c TerminalCommand) (Snapshot, error) {
	if e == nil || e.engineState == nil || validateControl(c.Control) != nil || !terminal(c.State) {
		return Snapshot{}, ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.records[c.Control.InvitationID]
	if !ok {
		return Snapshot{}, ErrNotFound
	}
	s := r.snapshot
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	if c.Control.Now < s.UpdatedAt {
		return Snapshot{}, ErrInvalid
	}
	if terminal(s.State) {
		if s.State == c.State && s.Termination.RequestID == c.Control.RequestID {
			return s, nil
		}
		return Snapshot{}, ErrState
	}
	if err := e.cas(s, c.Control); err != nil {
		return Snapshot{}, err
	}
	n := stage(s.State)
	if c.State == Rejected && n != 2 || c.State == Canceled && n >= 6 || c.State == Revoked && n < 3 {
		return Snapshot{}, ErrState
	}
	if c.State == Expired && c.Control.Now < deadline(s) {
		return Snapshot{}, ErrState
	}
	s.Termination = Termination{RequestID: c.Control.RequestID, From: s.State, At: c.Control.Now}
	s.State = c.State
	return e.commit(ctx, r, s, c.Control.Now)
}

func (e *Engine) lookup(ctx context.Context, c Control) (record, error) {
	if err := contextError(ctx); err != nil {
		return record{}, err
	}
	r, ok := e.records[c.InvitationID]
	if !ok {
		return record{}, ErrNotFound
	}
	if c.Now < r.snapshot.UpdatedAt {
		return record{}, ErrInvalid
	}
	if terminal(r.snapshot.State) {
		return record{}, ErrState
	}
	if c.Now >= deadline(r.snapshot) {
		return record{}, ErrExpired
	}
	return r, nil
}

func (e *Engine) cas(s Snapshot, c Control) error {
	if s.Revision != c.ExpectedRevision || s.Revision == MaxRevision || e.requestUsed(c.RequestID) {
		return ErrConflict
	}
	return nil
}

func (e *Engine) commit(ctx context.Context, old record, s Snapshot, now int64) (Snapshot, error) {
	if old.snapshot.Revision >= MaxRevision {
		return Snapshot{}, ErrConflict
	}
	s.Revision = old.snapshot.Revision + 1
	s.UpdatedAt = now
	if ValidateSnapshot(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	if err := contextError(ctx); err != nil {
		return Snapshot{}, err
	}
	old.snapshot = s
	e.records[s.InvitationID] = old
	return s, nil
}

func (e *Engine) count(state State) int {
	n := 0
	for _, r := range e.records {
		if r.snapshot.State == state {
			n++
		}
	}
	return n
}
func (e *Engine) pendingCount() int {
	n := 0
	for _, r := range e.records {
		s := stage(r.snapshot.State)
		if s >= 2 && s <= 5 {
			n++
		}
	}
	return n
}
func (e *Engine) requestUsed(id string) bool {
	for _, r := range e.records {
		s := r.snapshot
		if id == s.CreateRequestID || id == s.Claim.RequestID || id == s.Approval.RequestID || id == s.Intent.RequestID || id == s.Issuance.RequestID || id == s.Activation.RequestID || id == s.Termination.RequestID {
			return true
		}
	}
	return false
}

// These named boundaries fail closed until separately reviewed protocols exist.
func (*Engine) Renew(context.Context) error   { return ErrNotImplemented }
func (*Engine) Recover(context.Context) error { return ErrNotImplemented }
func (*Engine) Migrate(context.Context) error { return ErrNotImplemented }
