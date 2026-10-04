// Package journalstate consumes an authoritative on-demand journal grant before
// a future local adapter invokes its helper. It stores metadata only, never log
// content, and performs no collection, transport, enrollment or policy loading.
package journalstate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/journalrequest"
)

const Version = "tracebolt.journal-consumption.v1"
const MaxStateBytes = 4095

// Errors contain no paths, query details, operating-system text or content.
var (
	ErrUnsupported = errors.New("journal consumption state is supported on Linux only")
	ErrUnsafe      = errors.New("journal consumption state permissions or identity are unsafe")
	ErrCorrupt     = errors.New("journal consumption state is invalid or absent")
	ErrIO          = errors.New("journal consumption state storage is unavailable")
	ErrLocked      = errors.New("journal consumption state is already in use")
	ErrBinding     = errors.New("journal consumption current binding does not match")
	ErrGrant       = errors.New("journal consumption grant is invalid")
	ErrConsumed    = errors.New("journal consumption grant is already consumed")
	ErrHelper      = errors.New("journal consumption helper attempt failed")
	ErrExpired     = errors.New("journal consumption grant has expired")
	ErrClosed      = errors.New("journal consumption state is closed")
	ErrCanceled    = errors.New("journal consumption operation canceled")
	ErrUncertain   = errors.New("journal consumption durability is uncertain; preserve state for manual inspection")
)

// Current must come from independently validated, existing v3 enrollment and
// current local policy. SenderBinding is that existing exact binding, not a new
// journal-specific hash. This struct is not proof of consent or authentication.
type Current struct {
	SenderBinding   string
	DeviceID        string
	CertificateHash string
	PolicyDigest    string
}

// State copies share one mutex, exclusive OS lifetime lock and all permits.
// Any uncertain write poisons every copy. Close and inspect rather than repair.
type State struct{ inner *state }
type state struct {
	mu     sync.Mutex
	store  storage
	record diskRecord
	permit *permission
	closed bool
	failed error
}
type storage interface {
	verify() error
	replace(context.Context, []byte) error
	close() error
}

// Permit is an in-memory single-use admission. Copies share the same permission.
// Restart, Close, a newer admission, or a failed/canceled use never reissues it.
// It is not serializable and carries no log content.
type Permit struct{ inner *permission }
type permission struct {
	owner *state
	grant journalrequest.Grant
	used  bool
}

func (State) String() string                 { return "journal consumption state (contents redacted)" }
func (State) GoString() string               { return "journalstate.State{redacted}" }
func (s State) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, s.String()) }
func (State) MarshalJSON() ([]byte, error)   { return []byte(`{"contentsRedacted":true}`), nil }
func (Permit) String() string                { return "journal consumption permit (contents redacted)" }
func (Permit) GoString() string              { return "journalstate.Permit{redacted}" }
func (p Permit) Format(f fmt.State, _ rune)  { _, _ = io.WriteString(f, p.String()) }
func (Permit) MarshalJSON() ([]byte, error)  { return []byte(`{"contentsRedacted":true}`), nil }
func (Current) String() string               { return "journal consumption context (contents redacted)" }
func (Current) GoString() string             { return "journalstate.Current{redacted}" }
func (c Current) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }
func (Current) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

// Initialize is create-only, exclusively for a future acknowledged local opt-in
// while the existing validated v3 agent is stopped, running under that agent's
// numeric identity. The caller must establish those facts; this package does
// not enable consent, provision identities, or initialize existing sender state.
// It never adopts existing files, repairs permissions or resets a lost floor.
func Initialize(ctx context.Context, dir, senderBinding string) (*State, error) {
	return open(ctx, dir, senderBinding, true)
}

// Open is existing-only, even for an absent or empty directory. No file is
// created, cleaned or repaired. Ambiguous temporary files require manual review.
func Open(ctx context.Context, dir, senderBinding string) (*State, error) {
	return open(ctx, dir, senderBinding, false)
}
func open(ctx context.Context, dir, binding string, initialize bool) (*State, error) {
	if canceled(ctx) {
		return nil, ErrCanceled
	}
	if !validBinding(binding) {
		return nil, ErrBinding
	}
	store, raw, e := newStorage(ctx, dir, initialize)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*State, error) { _ = store.close(); return nil, e }
	var r diskRecord
	if initialize {
		r = diskRecord{Version: Version, SenderBinding: binding}
		raw, e = encodeRecord(r)
		if e == nil {
			e = store.replace(ctx, raw)
		}
	} else {
		r, e = decodeRecord(raw)
		if e == nil && r.SenderBinding != binding {
			e = ErrBinding
		}
	}
	if e != nil {
		return fail(e)
	}
	if canceled(ctx) {
		return fail(ErrCanceled)
	}
	return &State{inner: &state{store: store, record: r}}, nil
}
func canceled(ctx context.Context) bool { return ctx == nil || ctx.Err() != nil }
func validBinding(s string) bool        { return enrollmentcrypto.ValidHash(s) }
func validCurrent(c Current) bool {
	return validBinding(c.SenderBinding) && enrollmentcrypto.ValidID(c.DeviceID, "agent_") && enrollmentcrypto.ValidHash(c.CertificateHash) && journalrequest.ValidDigest(c.PolicyDigest)
}
func checkGrant(g journalrequest.Grant, c Current, binding string, now time.Time) error {
	if !validCurrent(c) || c.SenderBinding != binding || g.Description.DeviceID != c.DeviceID || g.Description.CertificateHash != c.CertificateHash || g.PolicyDigest != c.PolicyDigest {
		return ErrBinding
	}
	r := journalrequest.Record{Description: g.Description, State: journalrequest.Claimed, PolicyDigest: g.PolicyDigest, ClaimedAt: &g.ClaimedAt}
	if journalrequest.Validate(r) != nil {
		return ErrGrant
	}
	e := journalrequest.CheckTime(r, now)
	if errors.Is(e, journalrequest.ErrExpired) {
		return ErrExpired
	}
	if e != nil {
		return ErrGrant
	}
	return nil
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
	return v, nil
}

// SequenceFloor is the greatest consumed SERVER sequence, never a count of
// captures. Expiry, result loss and acknowledgment cannot decrease it.
func (s *State) SequenceFloor() (uint64, error) {
	v, e := s.locked()
	if e != nil {
		return 0, e
	}
	defer v.mu.Unlock()
	return v.record.Sequence, nil
}

// Consume durably records the exact grant metadata before returning a Permit.
// Any sequence greater than the floor is valid: canceled server queries may
// leave gaps. At/below the floor is always rejected, even with changed metadata.
// A coherent, current-binding expired grant also advances the durable floor,
// but returns ErrExpired without permission. Clock reversal cannot revive it.
// A lost return value deliberately loses permission; it cannot be recovered.
func (s *State) Consume(ctx context.Context, c Current, g journalrequest.Grant, now time.Time) (Permit, error) {
	if canceled(ctx) {
		return Permit{}, ErrCanceled
	}
	v, e := s.locked()
	if e != nil {
		return Permit{}, e
	}
	defer v.mu.Unlock()
	grantErr := checkGrant(g, c, v.record.SenderBinding, now)
	if grantErr != nil && grantErr != ErrExpired {
		return Permit{}, grantErr
	}
	if g.Description.Identity.Sequence <= v.record.Sequence {
		return Permit{}, ErrConsumed
	}
	next := diskRecord{Version: Version, SenderBinding: v.record.SenderBinding, Sequence: g.Description.Identity.Sequence, QueryID: g.Description.Identity.ID, QueryDigest: g.Description.Identity.QueryDigest, PolicyDigest: g.PolicyDigest, ExpiresAt: g.Description.ExpiresAt.Format(time.RFC3339Nano)}
	raw, e := encodeRecord(next)
	if e != nil {
		return Permit{}, e
	}
	if canceled(ctx) {
		return Permit{}, ErrCanceled
	}
	// Revoke any old admission before mutation; a failure cannot revive it.
	v.permit = nil
	if e = v.store.replace(ctx, raw); e != nil {
		v.failed = e
		return Permit{}, e
	}
	v.record = next
	if grantErr == ErrExpired {
		return Permit{}, ErrExpired
	}
	if canceled(ctx) {
		return Permit{}, ErrCanceled
	}
	p := &permission{owner: v, grant: g}
	v.permit = p
	return Permit{inner: p}, nil
}

// Use invokes the supplied future helper adapter at most once, after Consume's
// successful durable commit. The callback receives the exact admitted grant.
// Obtain Current and now freshly immediately before Use; the adapter must still
// enforce its own live policy, deadline and authenticated-helper checks. The
// callback must make one helper attempt, and must never retain/reuse the grant
// as collection permission. Any callback error/panic consumes permission too.
// Callback errors are deliberately replaced with ErrHelper, never logged/wrapped.
// Holding the shared state lock through the callback serializes collection and
// Close; the callback must not reenter this State. No callback output is stored.
func (s *State) Use(ctx context.Context, p Permit, c Current, now time.Time, invoke func(context.Context, journalrequest.Grant) error) error {
	v, e := s.locked()
	if e != nil {
		return e
	}
	defer v.mu.Unlock()
	if p.inner == nil || p.inner.owner != v || v.permit != p.inner || p.inner.used {
		return ErrConsumed
	}
	p.inner.used = true
	v.permit = nil
	if canceled(ctx) {
		return ErrCanceled
	}
	if e = checkGrant(p.inner.grant, c, v.record.SenderBinding, now); e != nil {
		return e
	}
	if invoke == nil {
		return ErrGrant
	}
	if invoke(ctx, p.inner.grant) != nil {
		return ErrHelper
	}
	return nil
}

// Close releases the writer lock and permanently revokes in-memory permission.
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
	v.permit = nil
	return v.store.close()
}
