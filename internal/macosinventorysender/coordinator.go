package macosinventorysender

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	inventory "localrmm/internal/macosinventory"
	state "localrmm/internal/macosinventorystate"
	wire "localrmm/internal/macosinventorywire"
)

// Coordinator owns one State and its external exclusive storage lock. Operations
// are single-flight. Disable and Close close admission, cancel, then join the
// active collector/transport before changing durable control or releasing custody.
// The constructor alone performs no source read or network operation.
type Coordinator struct {
	mu        sync.Mutex
	stopMu    sync.Mutex
	state     *state.State
	authority Authority
	enable    wire.Control
	original  []byte
	now       func() time.Time
	collect   func(context.Context, inventory.Request) (inventory.Snapshot, error)
	release   func() error
	active    context.CancelFunc
	done      chan struct{}
	draining  bool
	closed    bool
	closeErr  error
}

func (*Coordinator) String() string               { return "macOS inventory sender (contents redacted)" }
func (c *Coordinator) Format(f fmt.State, _ rune) { fmt.Fprint(f, c.String()) }
func (*Coordinator) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

// NewNative takes ownership of an already initialized/restored State and lock
// only on success. On rejection the caller must close its own state/storage.
// Only the reviewed fixed CollectNative implementation is selectable by callers.
// Fresh initialization and protected authenticated consent are separate required
// gates; passing canonical enable JSON alone can never authorize collection.
// There is deliberately no production Authority adapter or runtime registration.
func NewNative(s *state.State, originalEnable []byte, authority Authority, release func() error) (*Coordinator, error) {
	if runtime.GOOS != "darwin" {
		return nil, ErrAuthority
	}
	return newCoordinator(s, originalEnable, authority, release, func() time.Time { return time.Now().UTC() }, inventory.CollectNative)
}
func newCoordinator(s *state.State, raw []byte, a Authority, release func() error, now func() time.Time, collect func(context.Context, inventory.Request) (inventory.Snapshot, error)) (*Coordinator, error) {
	if s == nil || a == nil || release == nil || now == nil || collect == nil {
		return nil, ErrAuthority
	}
	e, err := wire.DecodeControl(raw)
	if err != nil || !e.Enabled {
		return nil, ErrAuthority
	}
	checkpoint, err := s.CheckpointBytes()
	if err != nil || state.ValidateCheckpoint(checkpoint, raw) != nil {
		return nil, ErrAuthority
	}
	return &Coordinator{state: s, authority: a, enable: e, original: bytes.Clone(raw), now: now, collect: collect, release: release}, nil
}
func (c *Coordinator) begin(ctx context.Context) (context.Context, func(), error) {
	if c == nil || ctx == nil {
		return nil, nil, ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.state == nil || c.authority == nil || c.now == nil || c.collect == nil || c.release == nil {
		return nil, nil, ErrClosed
	}
	if c.draining || c.active != nil {
		return nil, nil, ErrBusy
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	run, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.active, c.done = cancel, done
	return run, func() {
		cancel()
		c.mu.Lock()
		c.active = nil
		c.done = nil
		close(done)
		c.mu.Unlock()
	}, nil
}
func (c *Coordinator) checked(ctx context.Context, a ActiveAuthority, leaf string) (inventory.Consent, string, error) {
	if e := ctx.Err(); e != nil {
		return inventory.Consent{}, "", e
	}
	if a == nil {
		return inventory.Consent{}, "", ErrAuthority
	}
	now := c.now()
	v, e := a.Check(now)
	if e != nil {
		return inventory.Consent{}, "", ErrAuthority
	}
	at := c.now()
	if at.Before(now) {
		return inventory.Consent{}, "", state.ErrClock
	}
	consent, current, e := validateEvidence(v, c.enable, c.original, at)
	if e != nil || leaf != "" && leaf != current {
		return inventory.Consent{}, "", ErrAuthority
	}
	// The authenticated clock must also respect the durable checkpoint watermark.
	// This recheck occurs after the potentially slow platform authority read and
	// before any source/send edge. Even a verified no-op checks custody on disk.
	if _, e := c.state.Inspect(at); e != nil {
		return inventory.Consent{}, "", e
	}
	final := c.now()
	if final.Before(at) {
		return inventory.Consent{}, "", state.ErrClock
	}
	if _, _, e := validateEvidence(v, c.enable, c.original, final); e != nil {
		return inventory.Consent{}, "", e
	}
	if e := ctx.Err(); e != nil {
		return inventory.Consent{}, "", e
	}
	return consent, current, nil
}
func (c *Coordinator) exchange(ctx context.Context, a ActiveAuthority, leaf, path string, raw []byte, ack func([]byte, time.Time) error) error {
	var report wire.Report
	if path == ReportPath {
		// Revalidate actual durable custody, not just a previously returned copy.
		pending, e := c.state.PendingReport(c.now())
		if e != nil {
			return e
		}
		if !bytes.Equal(pending, raw) {
			return state.ErrConflict
		}
		report, e = wire.DecodeReport(raw)
		if e != nil {
			return state.ErrInvalid
		}
	}
	if _, _, e := c.checked(ctx, a, leaf); e != nil {
		return e
	}
	// Authority inspection can take time. Recheck ORIGINAL report lifetime at
	// the actual send edge, after that inspection, and prune on expiry.
	if path == ReportPath && wire.ValidateLifetime(report, c.now()) != nil {
		if _, e := c.state.Inspect(c.now()); e != nil {
			return e
		}
		return state.ErrExpired
	}
	receipt, e := a.Exchange(ctx, path, bytes.Clone(raw))
	if e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrTransport
	}
	if _, _, e = c.checked(ctx, a, leaf); e != nil {
		return e
	}
	if len(receipt) == 0 || len(receipt) > wire.MaxReceiptBytes {
		return ErrTransport
	}
	if e = ack(bytes.Clone(receipt), c.now()); e != nil {
		return e
	}
	return nil
}

// Cycle first advances retention even if authority has expired. It acknowledges
// the exact pending control before any capture, retries committed pending report
// bytes before considering another reservation, and never retries collection.
// Error messages are closed codes; raw provider/transport/authority text is lost.
func (c *Coordinator) Cycle(ctx context.Context) error {
	run, end, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer end()
	if _, e = c.state.Inspect(c.now()); e != nil {
		return e
	}
	calls := 0
	var result error
	e = c.authority.WithCurrent(run, func(a ActiveAuthority) error {
		calls++
		if calls != 1 {
			return ErrAuthority
		}
		result = c.cycle(run, a)
		return result
	})
	if e != nil {
		if result != nil {
			return result
		}
		if run.Err() != nil {
			return run.Err()
		}
		return ErrAuthority
	}
	if calls != 1 {
		return ErrAuthority
	}
	return result
}
func (c *Coordinator) cycle(ctx context.Context, a ActiveAuthority) error {
	consent, leaf, e := c.checked(ctx, a, "")
	if e != nil {
		return e
	}
	control, e := c.state.PendingControl(c.now())
	if e == nil {
		if e = c.exchange(ctx, a, leaf, ControlPath, control, c.state.AcknowledgeControl); e != nil {
			return e
		}
	} else if !errors.Is(e, state.ErrNoPending) {
		return e
	}
	status, e := c.state.Inspect(c.now())
	if e != nil {
		return e
	}
	if status.Terminal {
		return nil
	}
	report, e := c.state.PendingReport(c.now())
	if e == nil {
		return c.exchange(ctx, a, leaf, ReportPath, report, c.state.AcknowledgeReport)
	}
	if !errors.Is(e, state.ErrNoPending) && !errors.Is(e, state.ErrExpired) {
		return e
	}
	if _, _, e = c.checked(ctx, a, leaf); e != nil {
		return e
	}
	lease, e := c.state.Reserve(c.now())
	if e != nil {
		return e
	}
	failed := func(reason state.FailureReason, cause error) error {
		if e := c.state.Fail(lease, reason, c.now()); e != nil {
			return e
		}
		return cause
	}
	// An authority/cancellation failure AFTER reservation still consumes that floor.
	if _, _, e = c.checked(ctx, a, leaf); e != nil {
		return failed(state.FailureInterrupted, e)
	}
	request := inventory.Request{Consent: consent, SenderBinding: c.enable.Binding.SenderBinding, GenerationID: lease.GenerationID(), CollectedAt: lease.CollectedAt()}
	snapshot, e := c.collect(ctx, request)
	if e != nil {
		if ctx.Err() != nil {
			return failed(state.FailureInterrupted, ctx.Err())
		}
		return failed(state.FailureCollection, ErrCollection)
	}
	if _, _, e = c.checked(ctx, a, leaf); e != nil {
		return failed(state.FailureInterrupted, e)
	}
	if inventory.ValidateBinding(snapshot, lease.GenerationID(), c.enable.GrantID, lease.CollectedAt()) != nil {
		return failed(state.FailureCollection, ErrCollection)
	}
	built, e := wire.BuildReport(c.enable, lease.Sequence(), snapshot)
	if e != nil {
		return failed(state.FailureCollection, ErrCollection)
	}
	report, e = wire.EncodeReport(built)
	if e != nil {
		return failed(state.FailureCollection, ErrCollection)
	}
	if e = c.state.Stage(lease, report, c.now()); e != nil {
		if errors.Is(e, state.ErrExpired) {
			return failed(state.FailureInterrupted, e)
		}
		return e
	}
	return c.exchange(ctx, a, leaf, ReportPath, report, c.state.AcknowledgeReport)
}

// Maintain drives original-expiry pruning without a live credential, a source
// read or network. An eventual runtime must call it regularly even when disabled.
// This source does not promise wall-clock erasure while all callers are stopped.
func (c *Coordinator) Maintain(ctx context.Context) (state.Status, error) {
	_, end, e := c.begin(ctx)
	if e != nil {
		return state.Status{}, e
	}
	defer end()
	return c.state.Inspect(c.now())
}
func (c *Coordinator) drain() error {
	c.mu.Lock()
	if c.closed || c.state == nil || c.now == nil || c.release == nil {
		c.mu.Unlock()
		return ErrClosed
	}
	c.draining = true
	cancel, done := c.active, c.done
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	return nil
}

// Disable is a local terminal decision. It cancels and joins before durably
// publishing the final consumed floor; it needs no network or valid current leaf
// to stop future collection. Cycle may later retry its exact disable control.
// The caller must already have authorization to disable this local grant.
func (c *Coordinator) Disable() error {
	if c == nil {
		return ErrClosed
	}
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	if e := c.drain(); e != nil {
		return e
	}
	_, e := c.state.Disable(c.now())
	// A requested stop cannot silently reopen collection after a failed clock or
	// durability check. Only a committed terminal decision reopens admission for
	// disable-control retry/maintenance. Explicit Disable retry or Close remains.
	if e == nil {
		c.mu.Lock()
		c.draining = false
		c.mu.Unlock()
	}
	return e
}

// Close is the renewal/stop barrier. It joins every active operation before
// invalidating State or releasing the protected lock. It never disables the
// grant, changes credentials, reconstructs bytes or initializes another store.
// A renewal owner may activate its candidate only AFTER successful Close, then
// reopen existing storage/State with the SAME original enable. No scheduler is
// connected here; activation before this barrier would violate its contract.
func (c *Coordinator) Close() error {
	if c == nil {
		return nil
	}
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	c.mu.Lock()
	if c.closed {
		e := c.closeErr
		c.mu.Unlock()
		return e
	}
	c.mu.Unlock()
	if e := c.drain(); e != nil {
		return e
	}
	c.state.Close()
	e := c.release()
	c.mu.Lock()
	c.closed = true
	c.draining = false
	c.closeErr = e
	c.mu.Unlock()
	return e
}
