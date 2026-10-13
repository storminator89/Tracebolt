package macosinventorystate

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	wire "localrmm/internal/macosinventorywire"
)

// DurableCommitter is the ONLY persistence seam. No implementation is included.
// A real adapter must hold exclusive ownership across load, all calls and close;
// atomically compare exact expected bytes, preserve an independent irreversible
// used marker even if the checkpoint is missing, and return nil only after a
// verified durable commit. CreateFresh must reject every previously used identity,
// including a missing checkpoint or interrupted initialization. Commit must reject
// missing/replaced state, even when expected and next are identical (a verified
// no-op is permitted). Any uncertain write is an error, never a retry/reset.
// These obligations, protected storage and crash/power-loss behavior are not
// established by this interface or the memory fake in tests. Calls must not reenter
// State. The adapter must not retain or mutate arguments after a call returns.
type DurableCommitter interface {
	CreateFresh(next []byte) error
	Commit(expected, next []byte) error
}

// State serializes transitions within one owner. It cannot cancel/join a worker
// or stop a network send after bytes/lease have already been returned. The future
// integrator must serialize final authority checks and send admission with disable,
// and cancel/join collectors and senders before disable/credential cutover returns.
// Every supplied time/current authority is external and unproven here.
type State struct {
	mu       sync.Mutex
	durable  DurableCommitter
	record   checkpoint
	raw      []byte
	poisoned bool
	closed   bool
}

func (*State) String() string               { return "macOS inventory sender state (contents redacted)" }
func (s *State) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.String()) }
func (*State) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

// InitializeFresh is separate from Restore and is never a recovery fallback.
// An authenticated initializer must establish fresh unpredictable grant creation,
// explicit scope consent and immutable original binding BEFORE calling it.
// No collectable lease is available until the exact enable receipt is committed.
func InitializeFresh(d DurableCommitter, originalEnable []byte, now time.Time) (*State, error) {
	if d == nil {
		return nil, ErrInvalid
	}
	control, e := wire.DecodeControl(originalEnable)
	if e != nil || !control.Enabled {
		return nil, ErrInvalid
	}
	if !validTime(now) || now.Before(control.ChangedAt) {
		return nil, ErrClock
	}
	c := checkpoint{SchemaVersion: CheckpointVersion, Used: true, Enable: bytes.Clone(originalEnable), ClockAt: now}
	raw, e := encode(c)
	if e != nil {
		return nil, e
	}
	if d.CreateFresh(bytes.Clone(raw)) != nil {
		return nil, ErrUncertain
	}
	return &State{durable: d, record: c, raw: raw}, nil
}

// Restore requires a present, canonical used checkpoint and exact original enable.
// It must run under the adapter's exclusive ownership after old workers are joined.
// A reserved capture becomes durably lost before this returns: its sequence and
// original capture time remain consumed. Pending report/control bytes and original
// receipts survive unchanged. No current certificate is stored or substituted.
func Restore(d DurableCommitter, originalEnable, raw []byte, now time.Time) (*State, error) {
	if d == nil {
		return nil, ErrInvalid
	}
	c, e := decode(raw)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(originalEnable, c.Enable) {
		return nil, ErrConflict
	}
	if !validTime(now) || now.Before(c.ClockAt) {
		return nil, ErrClock
	}
	s := &State{durable: d, record: c, raw: bytes.Clone(raw)}
	next := advance(c, now)
	if next.Attempt != nil && next.Attempt.Status == "reserved" {
		next.Attempt.Status, next.Attempt.Reason = "lost", FailureInterrupted
		f := *next.Attempt
		next.LastFailure = &f
	}
	if e := s.commit(next); e != nil {
		return nil, e
	}
	return s, nil
}

// Lease exposes immutable capture metadata, not authenticated permission to read.
// Only its originating live State can settle it, exactly once. A reopen never
// returns another lease for the consumed sequence.
type Lease struct {
	owner        *State
	sequence     uint64
	collectedAt  time.Time
	generationID string
}

func (l Lease) Sequence() uint64       { return l.sequence }
func (l Lease) CollectedAt() time.Time { return l.collectedAt }
func (l Lease) GenerationID() string   { return l.generationID }

func (s *State) check(now time.Time) error {
	if s.closed {
		return ErrClosed
	}
	if s.poisoned {
		return ErrUncertain
	}
	if !validTime(now) || now.Before(s.record.ClockAt) {
		return ErrClock
	}
	return nil
}
func (s *State) commit(c checkpoint) error {
	raw, e := encode(c)
	if e != nil {
		return e
	}
	// Separate copies prevent a synchronous faulty adapter from corrupting the
	// canonical in-memory state or the exact expected bytes retained by this owner.
	// Poison before the external callback: a panic recovered by its caller also
	// leaves an uncertain outcome. Only a successful return and assignment clear it.
	s.poisoned = true
	if s.durable.Commit(bytes.Clone(s.raw), bytes.Clone(raw)) != nil {
		return ErrUncertain
	}
	s.record, s.raw = c, raw
	s.poisoned = false
	return nil
}

// Reserve durably consumes sequence and capture time BEFORE returning a lease.
// Failed/lost captures participate in pacing, including after reopen.
func (s *State) Reserve(now time.Time) (Lease, error) {
	if s == nil {
		return Lease{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(now); e != nil {
		return Lease{}, e
	}
	c := advance(s.record, now)
	if c.Disable != nil {
		return Lease{}, ErrDisabled
	}
	if c.EnableReceipt == nil {
		return Lease{}, ErrNotEnabled
	}
	if c.Attempt != nil && (c.Attempt.Status == "reserved" || c.Attempt.Status == "pending") {
		return Lease{}, ErrBusy
	}
	if c.LastCaptureAt != nil && now.Before(c.LastCaptureAt.Add(wire.CaptureInterval)) {
		return Lease{}, ErrPacing
	}
	if c.Floor == wire.MaxSequence || !validTime(now.Add(wire.Retention)) {
		return Lease{}, ErrBounds
	}
	enable, _ := wire.DecodeControl(c.Enable)
	id, e := wire.GenerationID(enable.Binding, enable.GrantID, enable.GrantRevision, c.Floor+1)
	if e != nil {
		return Lease{}, ErrInvalid
	}
	c.Floor++
	c.LastCaptureAt = &now
	c.Attempt = &attempt{Sequence: c.Floor, CollectedAt: now, Status: "reserved"}
	if e := s.commit(c); e != nil {
		return Lease{}, e
	}
	return Lease{owner: s, sequence: c.Floor, collectedAt: now, generationID: id}, nil
}
func (s *State) matches(l Lease, c checkpoint) bool {
	return l.owner == s && c.Attempt != nil && c.Attempt.Status == "reserved" && l.sequence == c.Floor && l.collectedAt.Equal(c.Attempt.CollectedAt)
}

// Stage preserves a completed canonical report byte-for-byte. No collector is
// called here. Invalid results leave the reservation consumed; use Fail or reopen
// to record its failure/loss. A report is sendable only after this commit succeeds.
func (s *State) Stage(l Lease, report []byte, now time.Time) error {
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(now); e != nil {
		return e
	}
	c := advance(s.record, now)
	if c.Disable != nil {
		return ErrDisabled
	}
	if !s.matches(l, c) {
		return ErrConflict
	}
	r, e := wire.DecodeReport(report)
	enable, _ := wire.DecodeControl(c.Enable)
	if e != nil || wire.ValidateReportBinding(r, enable) != nil || r.CaptureSequence != l.sequence || r.GenerationID != l.generationID || !r.CollectedAt.Equal(l.collectedAt) {
		return ErrInvalid
	}
	if wire.ValidateLifetime(r, now) != nil {
		return ErrExpired
	}
	p, e := describe(report)
	if e != nil {
		return e
	}
	c.Report, c.Attempt.Status = p, "pending"
	return s.commit(c)
}

// Fail accepts only collection_failed or interrupted, never provider text.
func (s *State) Fail(l Lease, reason FailureReason, now time.Time) error {
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(now); e != nil {
		return e
	}
	c := advance(s.record, now)
	if c.Disable != nil {
		return ErrDisabled
	}
	if !s.matches(l, c) {
		return ErrConflict
	}
	switch reason {
	case FailureCollection:
		c.Attempt.Status = "failed"
	case FailureInterrupted:
		c.Attempt.Status = "lost"
	default:
		return ErrInvalid
	}
	c.Attempt.Reason = reason
	f := *c.Attempt
	c.LastFailure = &f
	return s.commit(c)
}

func (s *State) PendingControl(now time.Time) ([]byte, error) {
	if s == nil {
		return nil, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(now); e != nil {
		return nil, e
	}
	c := advance(s.record, now)
	raw, ack := c.Enable, c.EnableReceipt
	if c.Disable != nil {
		raw, ack = c.Disable, c.DisableReceipt
	}
	if e := s.commit(c); e != nil {
		return nil, e
	}
	if ack != nil {
		return nil, ErrNoPending
	}
	return bytes.Clone(raw), nil
}

// AcknowledgeControl verifies exact pending bytes and ReceivedAt <= caller time.
// Authentication and actual remote durable admission remain external. An exact
// duplicate receipt is idempotent; a newly timestamped receipt is a conflict.
func (s *State) AcknowledgeControl(ack []byte, now time.Time) error {
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(now); e != nil {
		return e
	}
	c := advance(s.record, now)
	request, old := c.Enable, c.EnableReceipt
	if c.Disable != nil {
		request, old = c.Disable, c.DisableReceipt
	}
	if receipt(ack, request, now) != nil {
		return ErrInvalid
	}
	if old != nil && !bytes.Equal(old, ack) {
		return ErrConflict
	}
	if c.Disable != nil {
		c.DisableReceipt = bytes.Clone(ack)
	} else {
		c.EnableReceipt = bytes.Clone(ack)
	}
	return s.commit(c)
}

// PendingReport returns a detached copy of the exact pending canonical bytes.
// At original expiry it durably drops source bytes and returns ErrExpired. It
// never refreshes a timestamp, reports success after a failed commit or returns
// a report after terminal disable, even when captured before that decision.
func (s *State) PendingReport(now time.Time) ([]byte, error) {
	if s == nil {
		return nil, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(now); e != nil {
		return nil, e
	}
	if s.record.Disable != nil {
		return nil, ErrDisabled
	}
	c := advance(s.record, now)
	if e := s.commit(c); e != nil {
		return nil, e
	}
	if c.Attempt != nil && c.Attempt.Status == "expired" {
		return nil, ErrExpired
	}
	if c.Attempt == nil || c.Attempt.Status != "pending" {
		return nil, ErrNoPending
	}
	return bytes.Clone(c.Report.Body), nil
}
func (s *State) AcknowledgeReport(ack []byte, now time.Time) error {
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(now); e != nil {
		return e
	}
	if s.record.Disable != nil {
		return ErrDisabled
	}
	c := advance(s.record, now)
	if c.Report != nil && c.Report.Body == nil {
		if e := s.commit(c); e != nil {
			return e
		}
		return ErrExpired
	}
	if c.Attempt == nil || c.Attempt.Status != "pending" && c.Attempt.Status != "recorded" || c.Report == nil || c.Report.Sequence != c.Floor {
		return ErrNoPending
	}
	if receipt(ack, c.Report.Body, now) != nil {
		return ErrInvalid
	}
	if c.Report.Receipt != nil && !bytes.Equal(c.Report.Receipt, ack) {
		return ErrConflict
	}
	c.Report.Receipt, c.Attempt.Status = bytes.Clone(ack), "recorded"
	return s.commit(c)
}

// Disable is irreversible in v1. It captures the final reservation floor,
// consumes an in-flight reservation as lost, and permanently forbids collection,
// report retry and report acknowledgement. The returned control is sendable only
// after its durable commit. Repeated calls reuse its original bytes/time.
func (s *State) Disable(now time.Time) ([]byte, error) {
	if s == nil {
		return nil, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(now); e != nil {
		return nil, e
	}
	c := advance(s.record, now)
	if c.Disable == nil {
		enable, _ := wire.DecodeControl(c.Enable)
		control, e := wire.Disable(enable, c.Floor, now)
		if e != nil {
			return nil, ErrInvalid
		}
		c.Disable, e = wire.EncodeControl(control)
		if e != nil {
			return nil, ErrInvalid
		}
		if c.Attempt != nil {
			switch c.Attempt.Status {
			case "reserved":
				c.Attempt.Status, c.Attempt.Reason = "lost", FailureDisabled
				f := *c.Attempt
				c.LastFailure = &f
			case "pending":
				c.Attempt.Status, c.Attempt.Reason = "abandoned", FailureDisabled
			}
		}
	}
	if e := s.commit(c); e != nil {
		return nil, e
	}
	return bytes.Clone(c.Disable), nil
}

// Status contains only bounded progress/quality metadata, not captured rows.
// Source coverage remains independent from caller-evaluated freshness.
type Status struct {
	Used                bool
	Terminal            bool
	EnableAcknowledged  bool
	DisableAcknowledged bool
	Floor               uint64
	LastCaptureAt       time.Time
	AttemptStatus       string
	FailureSequence     uint64
	FailureReason       FailureReason
	ReportSequence      uint64
	SourceQuality       string
	Freshness           string
}

func (s *State) Inspect(now time.Time) (Status, error) {
	if s == nil {
		return Status{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(now); e != nil {
		return Status{}, e
	}
	c := advance(s.record, now)
	if e := s.commit(c); e != nil {
		return Status{}, e
	}
	out := Status{Used: true, Terminal: c.Disable != nil, EnableAcknowledged: c.EnableReceipt != nil, DisableAcknowledged: c.DisableReceipt != nil, Floor: c.Floor}
	if c.LastCaptureAt != nil {
		out.LastCaptureAt = *c.LastCaptureAt
	}
	if c.Attempt != nil {
		out.AttemptStatus = c.Attempt.Status
	}
	if c.LastFailure != nil {
		out.FailureSequence, out.FailureReason = c.LastFailure.Sequence, c.LastFailure.Reason
	}
	if c.Report != nil {
		out.ReportSequence, out.SourceQuality, out.Freshness = c.Report.Sequence, c.Report.SourceQuality, "fresh"
		if !now.Before(c.Report.ExpiresAt) {
			out.Freshness = "expired"
		} else if !now.Before(c.Report.CollectedAt.Add(wire.CaptureInterval)) {
			out.Freshness = "stale"
		}
	}
	return out, nil
}

// CheckpointBytes returns a copy of already committed private state for an
// adapter/test. It is not a transport or public-data API; it does not advance time.
func (s *State) CheckpointBytes() ([]byte, error) {
	if s == nil {
		return nil, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if s.poisoned {
		return nil, ErrUncertain
	}
	return bytes.Clone(s.raw), nil
}

// Close invalidates this owner only. It does not revoke old returned bytes,
// release an adapter's external ownership, cancel workers or prove joined work.
func (s *State) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.record, s.raw = checkpoint{}, nil
}
