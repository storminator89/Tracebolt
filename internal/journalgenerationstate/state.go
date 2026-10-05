// Package journalgenerationstate holds the separately approved policy generation
// and report sequence under the existing agent identity. It never reads logs or
// changes root policy, and never touches the journal-consumption directory.
package journalgenerationstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/journalgeneration"
	"math"
	"sync"
	"time"
)

const Version = "tracebolt.journal-generation-state.v1"
const MaxStateBytes = 4095

var (
	ErrUnsupported = errors.New("journal generation state unsupported")
	ErrUnsafe      = errors.New("journal generation state unsafe")
	ErrCorrupt     = errors.New("journal generation state corrupt")
	ErrIO          = errors.New("journal generation state unavailable")
	ErrLocked      = errors.New("journal generation state locked")
	ErrUncertain   = errors.New("journal generation state uncertain; preserve all evidence")
	ErrCanceled    = errors.New("journal generation state canceled")
	ErrClosed      = errors.New("journal generation state closed")
	ErrBinding     = errors.New("journal generation state binding mismatch")
)

type Record struct {
	SchemaVersion    string                  `json:"schemaVersion"`
	SenderBinding    string                  `json:"senderBinding"`
	DeviceID         string                  `json:"deviceId"`
	CertificateHash  string                  `json:"certificateHash"`
	PolicyGeneration journalgeneration.Tuple `json:"policyGeneration"`
	ReportSequence   uint64                  `json:"reportSequence,string"`
}
type storage interface {
	verify() error
	replace(context.Context, []byte) error
	close() error
}
type State struct{ *state }
type state struct {
	mu     sync.Mutex
	store  storage
	record Record
	closed bool
	failed error
}

func canceled(c context.Context) bool { return c == nil || c.Err() != nil }
func valid(r Record) bool {
	return r.SchemaVersion == Version && enrollmentcrypto.ValidHash(r.SenderBinding) && enrollmentcrypto.ValidID(r.DeviceID, "agent_") && enrollmentcrypto.ValidHash(r.CertificateHash) && journalgeneration.Validate(r.PolicyGeneration) == nil
}
func encode(r Record) ([]byte, error) {
	if !valid(r) {
		return nil, ErrCorrupt
	}
	b, e := json.Marshal(r)
	if e != nil || len(b) > MaxStateBytes {
		return nil, ErrCorrupt
	}
	return b, nil
}
func decode(b []byte) (Record, error) {
	var r Record
	if len(b) == 0 || len(b) > MaxStateBytes || json.Unmarshal(b, &r) != nil {
		return Record{}, ErrCorrupt
	}
	c, e := encode(r)
	if e != nil || !bytes.Equal(b, c) {
		return Record{}, ErrCorrupt
	}
	return r, nil
}

// Initialize is create-only, and only the explicit stopped-agent amendment CLI
// may call it after validating a pending root activation with the same tuple.
func Initialize(ctx context.Context, dir string, r Record) (*State, error) {
	if !valid(r) || r.PolicyGeneration.Revision != 1 || r.ReportSequence != 0 {
		return nil, ErrBinding
	}
	return open(ctx, dir, &r)
}
func Open(ctx context.Context, dir string) (*State, error) { return open(ctx, dir, nil) }
func open(ctx context.Context, dir string, initial *Record) (*State, error) {
	if canceled(ctx) {
		return nil, ErrCanceled
	}
	st, b, e := newStorage(ctx, dir, initial != nil)
	if e != nil {
		return nil, e
	}
	var r Record
	if initial != nil {
		r = *initial
		b, e = encode(r)
		if e == nil {
			e = st.replace(ctx, b)
		}
	} else {
		r, e = decode(b)
	}
	if e != nil {
		_ = st.close()
		return nil, e
	}
	return &State{&state{store: st, record: r}}, nil
}
func (s *State) check() error {
	if s == nil || s.state == nil || s.closed {
		return ErrClosed
	}
	if s.failed != nil {
		return s.failed
	}
	if e := s.store.verify(); e != nil {
		s.failed = e
		return e
	}
	return nil
}
func (s *State) Record() (Record, error) {
	if s == nil || s.state == nil {
		return Record{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(); e != nil {
		return Record{}, e
	}
	return s.record, nil
}
func (s *State) write(ctx context.Context, r Record) error {
	b, e := encode(r)
	if e != nil {
		return e
	}
	if e = s.store.replace(ctx, b); e != nil {
		s.failed = e
		return e
	}
	s.record = r
	return nil
}

// Advance never resets report or consumed-request floors. Exact expected bytes,
// same identity, next revision and a new nonce are mandatory. No retry/adoption.
func (s *State) Advance(ctx context.Context, expected Record, next journalgeneration.Tuple) error {
	if s == nil || s.state == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if canceled(ctx) {
		return ErrCanceled
	}
	if e := s.check(); e != nil {
		return e
	}
	if s.record != expected || journalgeneration.Validate(next) != nil || expected.PolicyGeneration.Revision == math.MaxUint64 || next.Revision != expected.PolicyGeneration.Revision+1 || next.Generation == expected.PolicyGeneration.Generation {
		return ErrBinding
	}
	r := expected
	r.PolicyGeneration = next
	return s.write(ctx, r)
}

// NextReport consumes a durable report sequence before transmission. A lost
// response creates a harmless gap; neither restart nor retry refreshes old bytes.
func (s *State) NextReport(ctx context.Context, expected Record, now time.Time) (journalgeneration.Report, error) {
	if s == nil || s.state == nil {
		return journalgeneration.Report{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if canceled(ctx) {
		return journalgeneration.Report{}, ErrCanceled
	}
	if e := s.check(); e != nil {
		return journalgeneration.Report{}, e
	}
	if expected != s.record || expected.ReportSequence == math.MaxUint64 || now.Location() != time.UTC || now.Unix() <= 0 || now.Year() > 9999 {
		return journalgeneration.Report{}, ErrBinding
	}
	r := expected
	r.ReportSequence++
	if e := s.write(ctx, r); e != nil {
		return journalgeneration.Report{}, e
	}
	return journalgeneration.Report{SchemaVersion: journalgeneration.ReportVersion, Tuple: r.PolicyGeneration, Sequence: r.ReportSequence, ObservedAt: now}, nil
}
func (s *State) Close() error {
	if s == nil || s.state == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.store.close()
}
