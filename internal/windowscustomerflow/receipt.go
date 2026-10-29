package windowscustomerflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/windowsstate"
)

const receiptVersion = "tracebolt.windows-customer-continuation-receipt.v1"
const receiptName = "receipt.json"
const receiptLock = "customer.lock"
const receiptTemp = "customer.tmp"
const receiptLimit = 16 << 10

var ErrReceipt = errors.New("customer continuation receipt unavailable or invalid")
var ErrUncertain = errors.New("customer continuation write outcome or authority is uncertain; reconcile without retry")

// Guard represents a separately held live authority and independently durable
// write-fence owner. No implementation is supplied here: integration is blocked
// until one is protected, create-only, restart-safe and independently reviewed.
// Check must fail on cancellation, replaced identity, revoked authority, or
// storage/used-marker inconsistency. CheckReconciled must prove the exact old
// receipt's outcome from durable independent state and native evidence, never
// merely trust the receipt bytes. BeginWrite must durably record an unresolved
// fence binding both hashes BEFORE returning, and reject unresolved prior work.
// This package never clears that fence. A separate owner must reconcile the
// persisted receipt, original local identity and any native side effects before
// CheckReconciled may succeed. Errors, panics and lost outcomes remain fenced.
// The caller must retain the real lease through the write and any later native
// operation. An implementation that simply returns nil provides no protection.
type Guard interface {
	Check() error
	CheckReconciled(receiptHash [32]byte) error
	BeginWrite(oldHash, newHash [32]byte, oldAbsent bool) error
}

type receiptStore interface {
	RequireInstallerSchema([]string, string, string, int64) error
	Read(string) ([]byte, error)
	CompareAndWrite(string, []byte, bool, []byte) error
}

// Journal wraps an already-open protected installer-only Store. Attach does not
// create a store or authorize a write. The owner must prevent other code from
// mutating this store directly, establish a durable independently protected
// used marker before creating fresh state, and never recreate a missing used
// store. Native ACL/host lifecycle acceptance remains separately required.
type Journal struct{ store receiptStore }

// Attach verifies the protected installer's fixed receipt schema. It performs no
// host creation or mutation and does not establish endpoint or operator consent.
func Attach(store *windowsstate.Store) (*Journal, error) {
	if store == nil {
		return nil, ErrReceipt
	}
	return attach(store)
}

func attach(store receiptStore) (*Journal, error) {
	if store == nil || store.RequireInstallerSchema([]string{receiptName}, receiptLock, receiptTemp, receiptLimit) != nil {
		return nil, ErrReceipt
	}
	return &Journal{store: store}, nil
}

type receipt struct {
	Version string `json:"version"`
	State   State  `json:"state"`
}

func encodeReceipt(s State) ([]byte, error) {
	if !validState(s) {
		return nil, ErrReceipt
	}
	raw, err := json.Marshal(receipt{Version: receiptVersion, State: clone(s)})
	if err != nil || len(raw) == 0 || len(raw) > receiptLimit {
		return nil, ErrReceipt
	}
	return raw, nil
}
func decodeReceipt(raw []byte) (State, error) {
	var r receipt
	if len(raw) == 0 || len(raw) > receiptLimit || json.Unmarshal(raw, &r) != nil || r.Version != receiptVersion {
		return State{}, ErrReceipt
	}
	canonical, err := encodeReceipt(r.State)
	if err != nil || !bytes.Equal(canonical, raw) {
		return State{}, ErrReceipt
	}
	return clone(r.State), nil
}

// Read returns structurally valid canonical bytes and a value copy. It does not
// prove that a post-CAS guard or clock check completed, that a native operation
// succeeded, or that the state can be used as authority after restart. Only a
// separate durable reconciliation guard can establish that. A missing or
// damaged used file is never treated as a fresh installation by this method.
func (j *Journal) Read() (State, []byte, error) {
	if j == nil || j.store == nil {
		return State{}, nil, ErrReceipt
	}
	raw, err := j.store.Read(receiptName)
	if err != nil {
		return State{}, nil, ErrReceipt
	}
	s, err := decodeReceipt(raw)
	if err != nil {
		return State{}, nil, ErrReceipt
	}
	return s, bytes.Clone(raw), nil
}

// Initialize is an explicit create-only step, not a fallback for missing
// state. The caller must hold an independently recorded fresh/used-marker lease
// across the call, with original scope/finalizer consent and protected identity
// established separately. A failed guard after the CAS is an uncertain write;
// it must never be retried or used as authority for a host action. A successful
// return leaves the external write fence unresolved: independent reconciliation
// must happen before any later transition or native effect.
func (j *Journal) Initialize(binding Binding, consent Consent, clock func() time.Time, fresh Guard) (out State, encoded []byte, result error) {
	mutationPossible := false
	defer func() {
		if recover() != nil {
			out, encoded = State{}, nil
			if mutationPossible {
				result = ErrUncertain
			} else {
				result = ErrReceipt
			}
		}
	}()
	if j == nil || j.store == nil || fresh == nil || clock == nil {
		return State{}, nil, ErrReceipt
	}
	started := clock().UTC()
	if started.Unix() <= 0 || started.Unix() > maxTimestamp || fresh.Check() != nil {
		return State{}, nil, ErrReceipt
	}
	before := clock().UTC()
	if before.Before(started) {
		return State{}, nil, ErrReceipt
	}
	s, err := New(binding, consent, before)
	if err != nil {
		return State{}, nil, err
	}
	raw, err := encodeReceipt(s)
	if err != nil {
		return State{}, nil, err
	}
	preCAS := clock().UTC()
	if preCAS.Before(before) || preCAS.Unix() > maxTimestamp || preCAS.Unix() >= binding.DeadlineAt {
		return State{}, nil, ErrReceipt
	}
	var zero [32]byte
	nextHash := sha256.Sum256(raw)
	// A guard failure may itself follow a durable fence write, so treat every
	// result from this point as uncertain until explicitly reconciled.
	mutationPossible = true
	if err = fresh.BeginWrite(zero, nextHash, true); err != nil {
		return State{}, nil, ErrUncertain
	}
	if err = fresh.Check(); err != nil {
		return State{}, nil, ErrUncertain
	}
	edge := clock().UTC()
	if edge.Before(preCAS) || edge.Unix() > maxTimestamp || edge.Unix() >= binding.DeadlineAt {
		return State{}, nil, ErrUncertain
	}
	if err = j.store.CompareAndWrite(receiptName, nil, true, raw); err != nil {
		return State{}, nil, ErrUncertain
	}
	if err = fresh.Check(); err != nil {
		return State{}, nil, ErrUncertain
	}
	after := clock().UTC()
	if after.Before(edge) || after.Unix() > maxTimestamp || after.Unix() >= binding.DeadlineAt {
		return State{}, nil, ErrUncertain
	}
	return clone(s), bytes.Clone(raw), nil
}

// Transition requires the exact previously read receipt bytes and a live guard.
// The atomic protected CAS records a started fence before any native mutation;
// it does not itself perform or authorize one, even when it returns nil. The
// external owner must reconcile its write fence before any native operation or
// subsequent transition. Any failed/uncertain store write
// must stop work; a previously started phase must not be automatically retried.
// For Interrupt the caller still needs a held guard for the original local
// receipt, but manager authority may already have expired; this action only
// records uncertainty and never authorizes a native operation.
func (j *Journal) Transition(expected []byte, action Action, evidence Evidence, clock func() time.Time, live Guard) (out State, encoded []byte, result error) {
	mutationPossible := false
	defer func() {
		if recover() != nil {
			out, encoded = State{}, nil
			if mutationPossible {
				result = ErrUncertain
			} else {
				result = ErrReceipt
			}
		}
	}()
	if j == nil || j.store == nil || live == nil || clock == nil {
		return State{}, nil, ErrReceipt
	}
	started := clock().UTC()
	if started.Unix() <= 0 || started.Unix() > maxTimestamp || live.Check() != nil {
		return State{}, nil, ErrReceipt
	}
	old, err := decodeReceipt(expected)
	if err != nil {
		return State{}, nil, err
	}
	oldHash := sha256.Sum256(expected)
	if err = live.CheckReconciled(oldHash); err != nil {
		return State{}, nil, ErrReceipt
	}
	if err = live.Check(); err != nil {
		return State{}, nil, ErrReceipt
	}
	before := clock().UTC()
	if before.Before(started) {
		return State{}, nil, ErrReceipt
	}
	next, err := Advance(old, action, evidence, before)
	if err != nil {
		return State{}, nil, err
	}
	raw, err := encodeReceipt(next)
	if err != nil {
		return State{}, nil, err
	}
	preCAS := clock().UTC()
	if preCAS.Before(before) || preCAS.Unix() > maxTimestamp || (action != Interrupt && preCAS.Unix() >= old.Binding.DeadlineAt) {
		return State{}, nil, ErrReceipt
	}
	if err = live.CheckReconciled(oldHash); err != nil {
		return State{}, nil, ErrReceipt
	}
	nextHash := sha256.Sum256(raw)
	mutationPossible = true
	if err = live.BeginWrite(oldHash, nextHash, false); err != nil {
		return State{}, nil, ErrUncertain
	}
	if err = live.Check(); err != nil {
		return State{}, nil, ErrUncertain
	}
	edge := clock().UTC()
	if edge.Before(preCAS) || edge.Unix() > maxTimestamp || (action != Interrupt && edge.Unix() >= old.Binding.DeadlineAt) {
		return State{}, nil, ErrUncertain
	}
	if err = j.store.CompareAndWrite(receiptName, expected, false, raw); err != nil {
		return State{}, nil, ErrUncertain
	}
	if err = live.Check(); err != nil {
		return State{}, nil, ErrUncertain
	}
	after := clock().UTC()
	if after.Before(edge) || after.Unix() > maxTimestamp || (action != Interrupt && after.Unix() >= old.Binding.DeadlineAt) {
		return State{}, nil, ErrUncertain
	}
	return clone(next), bytes.Clone(raw), nil
}
