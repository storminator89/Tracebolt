// Package systemstate durably retains one exact native telemetry request until
// it is acknowledged or explicitly discarded. This is local plaintext state,
// not a credential store. Open is supported only on Linux; native ACL policies
// must be reviewed before enabling other operating systems.
package systemstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

const (
	MaxBodyBytes  = (1 << 20) + 4096
	MaxStateBytes = 2 << 20
	// MaxSequence matches the signed 64-bit sequence domain of the receiver.
	MaxSequence  = uint64(math.MaxInt64)
	stateVersion = 1
)

// Errors deliberately contain no paths, observations, or operating-system text.
var (
	ErrUnsupported = errors.New("system observation sender state is supported on Linux only")
	ErrUnsafe      = errors.New("system observation sender state permissions or identity are unsafe")
	ErrCorrupt     = errors.New("system observation sender state is invalid")
	ErrIO          = errors.New("system observation sender state storage is unavailable")
	ErrLocked      = errors.New("system observation sender state is already in use")
	ErrBinding     = errors.New("system observation sender state binding does not match")
	ErrPending     = errors.New("system observation sender state has an unresolved request")
	ErrSequence    = errors.New("system observation sender state sequence is invalid or exhausted")
	ErrDigest      = errors.New("system observation sender pending digest does not match")
	ErrBody        = errors.New("system observation sender request is invalid or exceeds its size limit")
	ErrClosed      = errors.New("system observation sender state is closed")
)

// Pending is an immutable snapshot of a staged request. Changing these public
// metadata fields does not change the retained request. Body returns a copy.
// Formatting and JSON encoding intentionally never include the request body.
type Pending struct {
	Sequence uint64
	Digest   string
	body     *pendingBody
}
type pendingBody struct{ raw []byte }

func (p Pending) Body() []byte {
	if p.body == nil {
		return nil
	}
	return bytes.Clone(p.body.raw)
}
func (Pending) String() string               { return "system observation sender pending request (body redacted)" }
func (Pending) GoString() string             { return "systemstate.Pending{body:redacted}" }
func (p Pending) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }
func (p Pending) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Sequence     uint64 `json:"sequence"`
		Digest       string `json:"digest"`
		BodyRedacted bool   `json:"bodyRedacted"`
	}{p.Sequence, p.Digest, true})
}

// State must be closed by its owner. Its OS lock remains held through request
// transmission and acknowledgment. Copies refer to the same synchronized state.
// A storage failure invalidates the handle; close and reopen before proceeding.
type State struct{ inner *state }
type state struct {
	mu     sync.Mutex
	store  storage
	record diskRecord
	closed bool
	failed error
}

func (State) String() string               { return "system observation sender state (contents redacted)" }
func (State) GoString() string             { return "systemstate.State{contents:redacted}" }
func (s State) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (State) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

type storage interface {
	verify() error
	cleanup() error
	replace([]byte) error
	close() error
}

// Open validates the lowercase SHA-256 binding before using the state. The
// caller binds its profile, exact server origin, certificate fingerprint and
// identity to this value. An existing binding is never changed implicitly.
// Missing directories are created privately; insecure existing paths are never
// repaired with chmod. A leftover lock with missing state fails closed.
func Open(dir, binding string) (*State, error) { return open(dir, binding, true, true) }

// InitializeNew creates the independent system sequence domain once. It never
// adopts an existing ledger or acts as recovery for a lost pending observation.
func InitializeNew(dir, binding string) (*State, error) {
	return openConfigured(dir, binding, true, false, true)
}

// OpenExisting loads a previously initialized exact sender ledger. It never
// creates a fresh sequence domain when the ledger is absent, including an empty
// replacement directory. Guided enrollment uses this after its durable handoff.
func OpenExisting(dir, binding string) (*State, error) { return open(dir, binding, false, true) }

// ValidateExisting verifies a bound existing ledger under its exclusive lock,
// then closes it without creating files or cleaning sender-owned temporaries.
func ValidateExisting(dir, binding string) error {
	state, e := open(dir, binding, false, false)
	if e != nil {
		return e
	}
	return state.Close()
}
func open(dir, binding string, allowFresh, recoverTemp bool) (*State, error) {
	return openConfigured(dir, binding, allowFresh, recoverTemp, false)
}
func openConfigured(dir, binding string, allowFresh, recoverTemp, requireNew bool) (*State, error) {
	if !validDigest(binding) {
		return nil, ErrBinding
	}
	store, raw, fresh, err := newStorageMode(dir, allowFresh)
	if err != nil {
		return nil, err
	}
	if requireNew && !fresh {
		_ = store.close()
		return nil, ErrUnsafe
	}
	if fresh && !allowFresh {
		_ = store.close()
		return nil, ErrCorrupt
	}
	record := diskRecord{Version: stateVersion, Binding: binding}
	if !fresh {
		record, err = decodeRecord(raw)
		if err == nil && record.Binding != binding {
			err = ErrBinding
		}
		// Recovery may remove only an uncommitted temporary belonging to an
		// already valid, correctly bound ledger. Rejected state is untouched.
		if err == nil && recoverTemp {
			err = store.cleanup()
		}
	} else {
		raw, err = encodeRecord(record)
		if err == nil {
			err = store.replace(raw)
		}
	}
	if err != nil {
		_ = store.close()
		return nil, err
	}
	return &State{inner: &state{store: store, record: record}}, nil
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
		err := v.failed
		v.mu.Unlock()
		return nil, err
	}
	if err := v.store.verify(); err != nil {
		v.failed = err
		v.mu.Unlock()
		return nil, err
	}
	return v, nil
}

// NextSequence does not reserve a sequence or mutate storage. Stage atomically
// consumes that exact sequence with its pending body. Exhaustion fails closed.
func (s *State) NextSequence() (uint64, error) {
	v, err := s.locked()
	if err != nil {
		return 0, err
	}
	defer v.mu.Unlock()
	if v.record.LastSequence >= MaxSequence {
		return 0, ErrSequence
	}
	return v.record.LastSequence + 1, nil
}

// Pending returns nil when no request awaits resolution, or a defensive snapshot
// containing the original request bytes, including whitespace and timestamps.
func (s *State) Pending() (*Pending, error) {
	v, err := s.locked()
	if err != nil {
		return nil, err
	}
	defer v.mu.Unlock()
	if v.record.Pending == nil {
		return nil, nil
	}
	p := snapshot(v.record.Pending)
	return &p, nil
}

// Stage persists the consumed sequence and exact JSON bytes before returning.
// The caller must never send a request if this method reports any error.
func (s *State) Stage(sequence uint64, body []byte) (Pending, error) {
	v, err := s.locked()
	if err != nil {
		return Pending{}, err
	}
	defer v.mu.Unlock()
	if v.record.Pending != nil {
		return Pending{}, ErrPending
	}
	if v.record.LastSequence >= MaxSequence || sequence != v.record.LastSequence+1 {
		return Pending{}, ErrSequence
	}
	if !validBody(body) {
		return Pending{}, ErrBody
	}
	hash := sha256.Sum256(body)
	p := &diskPending{Sequence: sequence, Digest: hex.EncodeToString(hash[:]), Body: bytes.Clone(body)}
	next := v.record
	next.LastSequence, next.Pending = sequence, p
	if err = v.commit(next); err != nil {
		return Pending{}, err
	}
	return snapshot(p), nil
}

// Acknowledge clears only the pending request with this exact digest. Call only
// after the sender has verified a successful, identity-bound server receipt.
func (s *State) Acknowledge(digest string) error { return s.clear(digest) }

// Discard explicitly abandons a pending request without reusing its sequence.
// It does not make a network request or alter the original observation.
func (s *State) Discard(digest string) error { return s.clear(digest) }

func (s *State) clear(digest string) error {
	v, err := s.locked()
	if err != nil {
		return err
	}
	defer v.mu.Unlock()
	if !validDigest(digest) || v.record.Pending == nil || v.record.Pending.Digest != digest {
		return ErrDigest
	}
	next := v.record
	next.Pending = nil
	return v.commit(next)
}

func (v *state) commit(next diskRecord) error {
	raw, err := encodeRecord(next)
	if err != nil {
		return err
	}
	if err = v.store.replace(raw); err != nil {
		v.failed = err
		return err
	}
	v.record = next
	return nil
}

// Close releases the writer lock. Calling Close again is harmless.
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
	v.record.Pending = nil
	return v.store.close()
}

func snapshot(p *diskPending) Pending {
	return Pending{Sequence: p.Sequence, Digest: p.Digest, body: &pendingBody{raw: bytes.Clone(p.Body)}}
}
func validBody(body []byte) bool {
	return len(body) > 0 && len(body) <= MaxBodyBytes && json.Valid(body)
}
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type diskRecord struct {
	Version      int          `json:"version"`
	Binding      string       `json:"binding"`
	LastSequence uint64       `json:"lastSequence"`
	Pending      *diskPending `json:"pending"`
}
type diskPending struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
	Body     []byte `json:"body"`
}

func encodeRecord(v diskRecord) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxStateBytes {
		return nil, ErrCorrupt
	}
	return raw, nil
}

// Parse explicit objects so duplicates, unknown keys, case-insensitive aliases,
// absent values, null scalar values, and trailing JSON all fail closed.
func strictObject(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, ErrCorrupt
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	fields := make(map[string]json.RawMessage, len(keys))
	for d.More() {
		tok, err = d.Token()
		if err != nil {
			return nil, ErrCorrupt
		}
		key, ok := tok.(string)
		if !ok || !allowed[key] || fields[key] != nil {
			return nil, ErrCorrupt
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrCorrupt
		}
		fields[key] = value
	}
	if tok, err = d.Token(); err != nil || tok != json.Delim('}') || len(fields) != len(keys) {
		return nil, ErrCorrupt
	}
	var extra json.RawMessage
	if d.Decode(&extra) != io.EOF {
		return nil, ErrCorrupt
	}
	return fields, nil
}
func scalar(raw json.RawMessage, dst any) bool {
	return !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && json.Unmarshal(raw, dst) == nil
}
func decodeRecord(raw []byte) (diskRecord, error) {
	var v diskRecord
	if len(raw) == 0 || len(raw) > MaxStateBytes {
		return v, ErrCorrupt
	}
	f, err := strictObject(raw, "version", "binding", "lastSequence", "pending")
	if err != nil {
		return v, err
	}
	if !scalar(f["version"], &v.Version) || v.Version != stateVersion || !scalar(f["binding"], &v.Binding) || !validDigest(v.Binding) || !scalar(f["lastSequence"], &v.LastSequence) || v.LastSequence > MaxSequence {
		return v, ErrCorrupt
	}
	if bytes.Equal(bytes.TrimSpace(f["pending"]), []byte("null")) {
		return v, nil
	}
	p, err := strictObject(f["pending"], "sequence", "digest", "body")
	if err != nil {
		return v, err
	}
	var pending diskPending
	var encoded string
	if !scalar(p["sequence"], &pending.Sequence) || pending.Sequence == 0 || pending.Sequence != v.LastSequence || !scalar(p["digest"], &pending.Digest) || !validDigest(pending.Digest) || !scalar(p["body"], &encoded) {
		return v, ErrCorrupt
	}
	pending.Body, err = base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(pending.Body) != encoded || !validBody(pending.Body) {
		return v, ErrCorrupt
	}
	hash := sha256.Sum256(pending.Body)
	if hex.EncodeToString(hash[:]) != pending.Digest {
		return v, ErrCorrupt
	}
	v.Pending = &pending
	return v, nil
}
