// Package inventorystate durably retains one exact complete-inventory transfer.
// It performs no collection, transport, enrollment, or credential management.
// Only an enroller may initialize a fresh domain; senders must OpenExisting.
package inventorystate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/fullinventory"
	"localrmm/internal/inventorywire"
	"sync"
	"time"
)

const (
	MaxSequence     = inventorywire.MaxSequence
	MaxStateBytes   = 16 << 10
	MaxReceiptBytes = 4 << 10
	// Payload limits are independent from framing: no silent lower chunk ceiling.
	MaxRawBytes  = fullinventory.MaxGenerationRawBytes
	MaxPackBytes = MaxRawBytes + (fullinventory.MaxGenerationChunks+2)*1024
	// At most one pack (or unpublished pack), the ledger, and a ledger temporary.
	MaxDiskBytes = MaxPackBytes + 2*MaxStateBytes
	stateVersion = 1
)

var (
	ErrUnsupported    = errors.New("inventory spool is supported on Linux only")
	ErrUnsafe         = errors.New("inventory spool permissions or identity are unsafe")
	ErrCorrupt        = errors.New("inventory spool is invalid")
	ErrIO             = errors.New("inventory spool storage is unavailable")
	ErrLocked         = errors.New("inventory spool is already in use")
	ErrBinding        = errors.New("inventory spool binding does not match")
	ErrPending        = errors.New("inventory spool has unresolved work")
	ErrSequence       = errors.New("inventory spool sequence is invalid or exhausted")
	ErrAcknowledgment = errors.New("inventory spool acknowledgment does not match")
	ErrBody           = errors.New("inventory spool generation is invalid or exceeds its limit")
	ErrClosed         = errors.New("inventory spool is closed")
	ErrCanceled       = errors.New("inventory spool operation canceled")
	ErrUncertain      = errors.New("inventory spool publication is uncertain; preserved for recovery")
)

type storage interface {
	verify() error
	inspect() error
	replace([]byte) error
	loadPack(bool) ([]byte, error)
	publishPack(context.Context, []byte) error
	verifyPack(bool) error
	removePack() error
	close() error
}

// State copies share the same mutex, OS lifetime lock, and state. An I/O failure
// poisons every copy; close and reopen to inspect the durable outcome.
type State struct{ inner *state }
type state struct {
	mu     sync.Mutex
	store  storage
	record diskRecord
	pack   *generationPack
	permit *allocationPermit
	closed bool
	failed error
}

func (State) String() string               { return "inventory spool (contents redacted)" }
func (State) GoString() string             { return "inventorystate.State{redacted}" }
func (s State) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (State) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

// Allocation permits staging only in the live handle that durably allocated it.
// Restart offers the original fixed failure report instead of recollecting.
type Allocation struct {
	Sequence     uint64
	GenerationID string
	AttemptedAt  time.Time
	permit       *allocationPermit
}
type allocationPermit struct{ sequence uint64 }

func (Allocation) String() string               { return "inventory allocation (contents redacted)" }
func (Allocation) GoString() string             { return "inventorystate.Allocation{redacted}" }
func (a Allocation) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }
func (Allocation) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

// Work exposes only selected, detached request metadata. Body returns a fresh
// copy. Formatting, including pointer/value %#v, never discloses the payload.
type Work struct {
	Operation                  string
	Sequence                   uint64
	GenerationID, ManifestHash string
	Ordinal                    int
	Digest                     string
	body                       *workBody
}
type workBody struct{ raw []byte }

func (w Work) Body() []byte {
	if w.body == nil {
		return nil
	}
	return bytes.Clone(w.body.raw)
}
func (Work) String() string               { return "inventory work (contents redacted)" }
func (Work) GoString() string             { return "inventorystate.Work{redacted}" }
func (w Work) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, w.String()) }
func (Work) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

// InitializeNew is exclusively for enrollment. It requires a missing or empty
// private directory, and never adopts or overwrites any existing state.
// binding is a lowercase SHA-256 over the exact configuration, instance,
// origins, profile and key identity. The integration owns that canonical hash.
func InitializeNew(dir, binding, agentID string) (*State, error) {
	return open(dir, binding, agentID, true, false)
}
func OpenExisting(dir, binding, agentID string) (*State, error) {
	return open(dir, binding, agentID, false, true)
}

// ValidateExisting acquires the same exclusive lock and fully checks all data;
// it never creates, cleans up, or changes any file, including recovery phases.
func ValidateExisting(dir, binding, agentID string) error {
	s, e := open(dir, binding, agentID, false, false)
	if e != nil {
		return e
	}
	return s.Close()
}
func open(dir, binding, agentID string, fresh, recover bool) (*State, error) {
	return openKind(packageTransfer, dir, binding, agentID, fresh, recover)
}
func openKind(kind transferKind, dir, binding, agentID string, fresh, recover bool) (*State, error) {
	if !validDigest(binding) {
		return nil, ErrBinding
	}
	if _, e := kind.generationID(agentID, 1); e != nil {
		return nil, ErrBinding
	}
	store, raw, isNew, e := newStorageMode(dir, fresh)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*State, error) { _ = store.close(); return nil, e }
	var r diskRecord
	if isNew {
		r = diskRecord{kind: kind, Version: kind.stateVersion(), Binding: binding, AgentID: agentID, Phase: "idle"}
		raw, e = encodeRecord(r)
		if e == nil {
			e = store.replace(raw)
		}
		if e != nil {
			return fail(e)
		}
	} else {
		r, e = decodeRecordKind(kind, raw)
		if e != nil {
			return fail(e)
		}
		if r.Binding != binding || r.AgentID != agentID {
			return fail(ErrBinding)
		}
	}
	// Never inspect or remove temporary artifacts before validating schema+binding.
	if e = store.inspect(); e != nil {
		return fail(e)
	}
	var pack *generationPack
	wantPack := r.Phase == "ready" || r.Phase == "abort" || r.Phase == "retiring"
	raw, e = store.loadPack(r.Phase == "retiring")
	if e != nil {
		return fail(e)
	}
	if !wantPack && len(raw) != 0 {
		return fail(ErrUncertain)
	}
	if wantPack && len(raw) == 0 && r.Phase != "retiring" {
		return fail(ErrCorrupt)
	}
	if len(raw) > 0 {
		if int64(len(raw)) != r.PackBytes || digest(raw) != r.PackSHA256 {
			return fail(ErrCorrupt)
		}
		pack, e = decodePack(context.Background(), raw, r)
		if e != nil {
			return fail(e)
		}
	}
	s := &State{inner: &state{store: store, record: r, pack: pack}}
	if recover && r.Phase == "retiring" {
		if e = s.inner.finishRetirement(); e != nil {
			return fail(e)
		}
	}
	return s, nil
}
func (s *State) locked() (*state, error) {
	if s == nil || s.inner == nil {
		return nil, ErrClosed
	}
	v := s.inner
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return nil, ErrClosed
	}
	if v.failed != nil {
		e := v.failed
		v.mu.Unlock()
		return nil, e
	}
	if e := v.store.verify(); e != nil {
		v.failed = e
		v.mu.Unlock()
		return nil, e
	}
	if e := v.store.inspect(); e != nil {
		v.failed = e
		v.mu.Unlock()
		return nil, e
	}
	want := v.record.Phase == "ready" || v.record.Phase == "abort" || v.record.Phase == "retiring"
	if e := v.store.verifyPack(want); e != nil {
		v.failed = e
		v.mu.Unlock()
		return nil, e
	}
	return v, nil
}
func (v *state) save(r diskRecord) error {
	raw, e := encodeRecord(r)
	if e != nil {
		return e
	}
	if e = v.store.replace(raw); e != nil {
		v.failed = e
		return e
	}
	v.record = r
	return nil
}
func canceled(ctx context.Context) bool { return ctx == nil || ctx.Err() != nil }
func (s *State) SequenceFloor() (uint64, error) {
	v, e := s.locked()
	if e != nil {
		return 0, e
	}
	defer v.mu.Unlock()
	return v.record.Floor, nil
}

// Allocate reserves the sequence and immutable original attempt time BEFORE
// capture. Cancellation after publication does not rewind that reservation.
func (s *State) Allocate(ctx context.Context, at time.Time) (Allocation, error) {
	if canceled(ctx) {
		return Allocation{}, ErrCanceled
	}
	if !validTime(at) {
		return Allocation{}, ErrBody
	}
	v, e := s.locked()
	if e != nil {
		return Allocation{}, e
	}
	defer v.mu.Unlock()
	if v.record.Phase != "idle" {
		return Allocation{}, ErrPending
	}
	if v.record.Floor == MaxSequence {
		return Allocation{}, ErrSequence
	}
	r := v.record
	r.Floor++
	r.Phase = "allocated"
	r.Generation, _ = r.kind.generationID(r.AgentID, r.Floor)
	r.AttemptedAt = at.Format(time.RFC3339Nano)
	r.Failure, e = failureBody(r, "collection_failed")
	if e != nil {
		return Allocation{}, e
	}
	if e = v.save(r); e != nil {
		return Allocation{}, e
	}
	if canceled(ctx) {
		return Allocation{}, ErrCanceled
	}
	v.permit = &allocationPermit{r.Floor}
	return Allocation{r.Floor, r.Generation, at, v.permit}, nil
}
func (v *state) matches(a Allocation) bool {
	return v.record.Phase == "allocated" && a.permit != nil && v.permit == a.permit && a.Sequence == v.record.Floor && a.GenerationID == v.record.Generation && a.AttemptedAt.Format(time.RFC3339Nano) == v.record.AttemptedAt
}

// Stage validates the entire generation before writing. Payload bytes, including
// harmless JSON whitespace, are preserved exactly inside immutable wire bodies.
// Collection time must equal the allocated attempt time; retries cannot refresh it.
func (s *State) Stage(ctx context.Context, a Allocation, manifest []byte, chunks [][]byte) error {
	if canceled(ctx) {
		return ErrCanceled
	}
	v, e := s.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	if !v.matches(a) {
		return ErrPending
	}
	pack, hash, e := buildPack(ctx, v.record, manifest, chunks)
	if e != nil {
		return e
	}
	if canceled(ctx) {
		return ErrCanceled
	}
	if e = v.store.publishPack(ctx, pack.raw); e != nil {
		v.failed = e
		return e
	}
	// Once publication starts, finish the journal transition even if canceled.
	r := v.record
	r.Phase = "ready"
	r.ManifestHash = hash
	r.Count = uint32(len(chunks))
	r.PackSHA256 = digest(pack.raw)
	r.PackBytes = int64(len(pack.raw))
	r.Failure = nil
	if e = v.save(r); e != nil {
		return e
	}
	v.pack = pack
	v.permit = nil
	return nil
}
func (s *State) StageFailure(ctx context.Context, a Allocation, reason string) error {
	if canceled(ctx) {
		return ErrCanceled
	}
	v, e := s.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	if !v.matches(a) {
		return ErrPending
	}
	r := v.record
	r.Phase = "failure"
	r.Failure, e = failureBody(r, reason)
	if e != nil {
		return e
	}
	if e = v.save(r); e != nil {
		return e
	}
	v.permit = nil
	return nil
}
func (v *state) next() (Work, bool, error) {
	r := v.record
	switch r.Phase {
	case "idle", "retiring":
		return Work{}, false, nil
	case "allocated", "failure":
		return makeWorkKind(r.kind, "failure", r.Failure), true, nil
	case "abort":
		raw, e := r.kind.encodeMessage("abort", r.Floor, r.Generation, r.ManifestHash, struct{}{})
		if e != nil {
			return Work{}, false, ErrCorrupt
		}
		return makeWorkKind(r.kind, "abort", raw), true, nil
	case "ready":
		if v.pack == nil || int(r.Next) >= len(v.pack.frames) {
			return Work{}, false, ErrCorrupt
		}
		op := "append"
		if r.Next == 0 {
			op = "begin"
		}
		if r.Next == r.Count+1 {
			op = "finalize"
		}
		return makeWorkKind(r.kind, op, v.pack.frames[r.Next]), true, nil
	}
	return Work{}, false, ErrCorrupt
}

// NextWork revokes an unfinished live collection permit before returning its
// deterministic fallback report. Calling it after restart never recaptures.
func (s *State) NextWork() (Work, bool, error) {
	v, e := s.locked()
	if e != nil {
		return Work{}, false, e
	}
	defer v.mu.Unlock()
	v.permit = nil
	return v.next()
}
func makeWork(op string, raw []byte) Work {
	return makeWorkKind(packageTransfer, op, raw)
}
func makeWorkKind(kind transferKind, op string, raw []byte) Work {
	m, e := kind.decodeMessage(op, raw)
	if e != nil {
		return Work{}
	}
	ordinal := -1
	if n, _, ok := m.ChunkFacts(); ok {
		ordinal = int(n)
	}
	return Work{op, m.Sequence, m.GenerationID, m.ManifestHash, ordinal, digest(raw), &workBody{bytes.Clone(raw)}}
}
func sameWork(a, b Work) bool {
	return a.Operation == b.Operation && a.Sequence == b.Sequence && a.GenerationID == b.GenerationID && a.ManifestHash == b.ManifestHash && a.Ordinal == b.Ordinal && a.Digest == b.Digest && a.body != nil && b.body != nil && bytes.Equal(a.body.raw, b.body.raw)
}

// Acknowledge accepts only the exact current operation/body digest and bounded
// validated response bytes. The transport caller MUST verify the operation's
// server receipt and transport identity before calling; HTTP-test responses
// remain unauthenticated. An exact last-ack retry is
// idempotent, including after restart; a changed receipt is always refused.
func (s *State) Acknowledge(work Work, receipt []byte) error {
	if work.body == nil {
		return ErrAcknowledgment
	}
	if len(receipt) == 0 || len(receipt) > MaxReceiptBytes || !json.Valid(receipt) || bytes.Equal(bytes.TrimSpace(receipt), []byte("null")) {
		return ErrAcknowledgment
	}
	v, e := s.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	decoded, e := v.record.kind.decodeReceipt(receipt, work.Operation, work.body.raw)
	if e != nil {
		return ErrAcknowledgment
	}
	if a := v.record.Last; a != nil && a.matches(work) {
		if bytes.Equal(a.Receipt, receipt) {
			return nil
		}
		return ErrAcknowledgment
	}
	current, ok, e := v.next()
	if e != nil {
		return e
	}
	if !ok || !sameWork(current, work) {
		return ErrAcknowledgment
	}
	r := v.record
	r.Last = ackFor(work, receipt)
	switch work.Operation {
	case "begin":
		r.StartedAt = decoded.StartedAt.Format(time.RFC3339Nano)
		r.ExpiresAt = decoded.ExpiresAt.Format(time.RFC3339Nano)
		r.ReceiptAt = r.StartedAt
	case "append", "finalize":
		at := decoded.ReceivedAt
		if work.Operation == "finalize" {
			at = decoded.CompletedAt
			if decoded.CollectedAt.Format(time.RFC3339Nano) != r.AttemptedAt {
				return ErrAcknowledgment
			}
		}
		prior, ok := parseTime(r.ReceiptAt)
		expires, ok2 := parseTime(r.ExpiresAt)
		if !ok || !ok2 || at.Before(prior) || !at.Before(expires) {
			return ErrAcknowledgment
		}
		r.ReceiptAt = at.Format(time.RFC3339Nano)
	}
	v.permit = nil
	if work.Operation == "failure" {
		r = idleRecord(r)
		return v.save(r)
	}
	r.Next++
	if work.Operation == "abort" {
		r.Next = r.Count + 2
	}
	if work.Operation == "finalize" || work.Operation == "abort" {
		r.Phase = "retiring"
	}
	if e = v.save(r); e != nil {
		return e
	}
	if r.Phase == "retiring" {
		return v.finishRetirement()
	}
	return nil
}

// StatusWork returns a purpose-bound request without altering the transfer.
// A status response never directly advances the upload cursor or clears bytes.
func (s *State) StatusWork() (Work, error) {
	v, e := s.locked()
	if e != nil {
		return Work{}, e
	}
	defer v.mu.Unlock()
	r := v.record
	if r.Phase != "ready" && r.Phase != "abort" {
		return Work{}, ErrPending
	}
	raw, e := r.kind.encodeMessage("status", r.Floor, r.Generation, r.ManifestHash, struct{}{})
	if e != nil {
		return Work{}, ErrCorrupt
	}
	return makeWorkKind(r.kind, "status", raw), nil
}

// RequestAbort requests only a purpose-bound abort. The caller must first verify
// a matching status receipt reporting expired/failed. Exact generation bytes are
// retained until Acknowledge verifies the abort receipt. No sequence is reset.
func (s *State) RequestAbort() error {
	v, e := s.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	if v.record.Phase == "abort" {
		return nil
	}
	if v.record.Phase != "ready" {
		return ErrPending
	}
	r := v.record
	r.Phase = "abort"
	return v.save(r)
}

func (v *state) finishRetirement() error {
	if e := v.store.removePack(); e != nil {
		v.failed = e
		return e
	}
	if e := v.save(idleRecord(v.record)); e != nil {
		return e
	}
	v.pack = nil
	return nil
}
func idleRecord(r diskRecord) diskRecord {
	return diskRecord{kind: r.kind, Version: r.Version, Binding: r.Binding, AgentID: r.AgentID, Floor: r.Floor, Phase: "idle", AttemptedAt: r.AttemptedAt, Last: r.Last}
}
func (s *State) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	v := s.inner
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	v.pack = nil
	v.permit = nil
	return v.store.close()
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1970 && t.Year() <= 9999
}
func failureBody(r diskRecord, reason string) ([]byte, error) {
	raw, e := r.kind.encodeMessage("failure", r.Floor, r.Generation, "", struct {
		AttemptedAt string `json:"attemptedAt"`
		Reason      string `json:"reason"`
	}{r.AttemptedAt, reason})
	if e != nil {
		return nil, ErrBody
	}
	return raw, nil
}

// ValidateStatus validates the response's exact request binding and retained
// manifest counts/receipt context. It does not advance or discard anything.
// HTTP-test responses remain unauthenticated even when all consistency checks pass.
func (s *State) ValidateStatus(work Work, raw []byte) (inventorywire.Receipt, error) {
	bad := func() (inventorywire.Receipt, error) { return inventorywire.Receipt{}, ErrAcknowledgment }
	if work.Operation != "status" || work.body == nil {
		return bad()
	}
	v, e := s.locked()
	if e != nil {
		return inventorywire.Receipt{}, e
	}
	defer v.mu.Unlock()
	receipt, e := v.record.kind.decodeReceipt(raw, "status", work.body.raw)
	if e != nil {
		return bad()
	}
	return v.validateStatus(work, receipt)
}
func (v *state) validateStatus(work Work, receipt inventorywire.Receipt) (inventorywire.Receipt, error) {
	bad := func() (inventorywire.Receipt, error) { return inventorywire.Receipt{}, ErrAcknowledgment }
	r := v.record
	if (r.Phase != "ready" && r.Phase != "abort") || v.pack == nil {
		return bad()
	}
	body, e := r.kind.encodeMessage("status", r.Floor, r.Generation, r.ManifestHash, struct{}{})
	if e != nil || !sameWork(work, makeWorkKind(r.kind, "status", body)) {
		return bad()
	}
	first, e := r.kind.decodeMessage("begin", v.pack.frames[0])
	collectedAt, chunkCount, observedCount, valid := first.ManifestFacts()
	if e != nil || !valid {
		return bad()
	}
	if receipt.ExpectedChunks != chunkCount || receipt.AcceptedRows > observedCount || receipt.StartedAt.Before(collectedAt) {
		return bad()
	}
	var rows uint64
	for i := uint32(0); i < receipt.AcceptedChunks; i++ {
		m, e := r.kind.decodeMessage("append", v.pack.frames[i+1])
		_, count, valid := m.ChunkFacts()
		if e != nil || !valid {
			return bad()
		}
		rows += count
	}
	if rows != receipt.AcceptedRows {
		return bad()
	}
	if r.StartedAt != "" && receipt.StartedAt.Format(time.RFC3339Nano) != r.StartedAt {
		return bad()
	}
	if receipt.CompletedAt.IsZero() {
		if receipt.ExpiresAt.Sub(receipt.StartedAt) != 15*time.Minute {
			return bad()
		}
		if r.ExpiresAt != "" && receipt.ExpiresAt.Format(time.RFC3339Nano) != r.ExpiresAt {
			return bad()
		}
	} else {
		if receipt.State != "complete" && receipt.State != "expired" || receipt.AcceptedRows != observedCount || receipt.AcceptedChunks != chunkCount || !receipt.CompletedAt.Before(receipt.StartedAt.Add(15*time.Minute)) || !receipt.ExpiresAt.Equal(collectedAt.Add(24*time.Hour)) {
			return bad()
		}
	}
	if (receipt.State == "pending" || receipt.State == "complete") && r.Next > 1 && receipt.AcceptedChunks < r.Next-1 {
		return bad()
	}
	return receipt, nil
}

// LastAttemptedAt returns the original latest collection attempt, including after
// successful retirement, so a restart cannot erase the runtime's cooldown.
func (s *State) LastAttemptedAt() (time.Time, error) {
	v, e := s.locked()
	if e != nil {
		return time.Time{}, e
	}
	defer v.mu.Unlock()
	if v.record.AttemptedAt == "" {
		return time.Time{}, nil
	}
	at, ok := parseTime(v.record.AttemptedAt)
	if !ok {
		return time.Time{}, ErrCorrupt
	}
	return at, nil
}

// RequestAbortAfterStatus atomically validates an exact current status receipt
// and requests abort only for an expired/failed, uncompleted transfer. It cannot
// discard a completed generation or acknowledge any operation on its own.
func (s *State) RequestAbortAfterStatus(work Work, raw []byte) error {
	if work.Operation != "status" || work.body == nil {
		return ErrAcknowledgment
	}
	v, e := s.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	receipt, e := v.record.kind.decodeReceipt(raw, "status", work.body.raw)
	if e != nil {
		return ErrAcknowledgment
	}
	receipt, e = v.validateStatus(work, receipt)
	if e != nil {
		return e
	}
	if (receipt.State != "expired" && receipt.State != "failed") || !receipt.CompletedAt.IsZero() {
		return ErrAcknowledgment
	}
	if v.record.Phase == "abort" {
		return nil
	}
	r := v.record
	r.Phase = "abort"
	return v.save(r)
}
