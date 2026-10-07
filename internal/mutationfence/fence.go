// Package mutationfence serializes all locally approved package/service mutations.
// It never executes an operation or reconstructs permission to retry one.
package mutationfence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
)

const (
	DefaultDirectory = "/var/lib/tracebolt/mutations"
	Version          = "tracebolt.endpoint-mutation-fence.v1"
	MaxEntries       = 256
	MaxBytes         = 256 << 10
	Prepare          = "package.prepare-selected"
	Package          = "package.upgrade-selected"
	Service          = "service.try-restart"
)

var (
	ErrInvalid     = errors.New("mutation_fence_invalid")
	ErrBusy        = errors.New("mutation_fence_busy")
	ErrUncertain   = errors.New("mutation_fence_uncertain")
	ErrConflict    = errors.New("mutation_fence_conflict")
	ErrNotFound    = errors.New("mutation_fence_not_found")
	ErrUnavailable = errors.New("mutation_fence_unavailable")
)

type Binding struct {
	ManagerID         string `json:"managerId"`
	EndpointID        string `json:"endpointId"`
	IncarnationDigest string `json:"incarnationDigest"`
}
type Owner struct {
	Action         string `json:"action"`
	JobID          string `json:"jobId"`
	Sequence       uint64 `json:"sequence,string"`
	EnvelopeDigest string `json:"envelopeDigest"`
}
type Entry struct {
	Owner       Owner  `json:"owner"`
	AdmittedAt  int64  `json:"admittedAt"`
	CompletedAt int64  `json:"completedAt"`
	Outcome     string `json:"outcome"`
}
type State struct {
	Version    string  `json:"version"`
	Binding    Binding `json:"binding"`
	ClockFloor int64   `json:"clockFloor"`
	Entries    []Entry `json:"entries"`
}
type Fence struct{ inner *handle }
type handle struct {
	mu            sync.Mutex
	directory     string
	binding       Binding
	lock          *os.File
	directoryInfo os.FileInfo
	closed        bool
	poisoned      bool
	owner         uint32
}

func (Fence) String() string               { return "mutationfence.Fence{state:redacted}" }
func (f Fence) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, f.String()) }
func (Fence) MarshalJSON() ([]byte, error) { return []byte(`{"stateRedacted":true}`), nil }
func validBinding(b Binding) bool {
	return enrollmentcrypto.ValidID(b.ManagerID, "manager_") && enrollmentcrypto.ValidID(b.EndpointID, "agent_") && actionpermit.ValidDigest(b.IncarnationDigest)
}
func validTime(t int64) bool { return t > 0 && t <= 253402300799 }
func validOwner(o Owner) bool {
	prefix := "update_"
	if o.Action == Service {
		prefix = "action_"
	} else if o.Action != Prepare && o.Action != Package {
		return false
	}
	return enrollmentcrypto.ValidID(o.JobID, prefix) && o.Sequence > 0 && actionpermit.ValidDigest(o.EnvelopeDigest)
}
func valid(s State) bool {
	if s.Version != Version || !validBinding(s.Binding) || !validTime(s.ClockFloor) || s.Entries == nil || len(s.Entries) > MaxEntries {
		return false
	}
	floors := map[string]uint64{}
	ids := map[string]bool{}
	for i, e := range s.Entries {
		if !validOwner(e.Owner) || !validTime(e.AdmittedAt) || e.AdmittedAt > s.ClockFloor || e.Owner.Sequence <= floors[e.Owner.Action] || ids[e.Owner.Action+e.Owner.JobID] {
			return false
		}
		floors[e.Owner.Action] = e.Owner.Sequence
		ids[e.Owner.Action+e.Owner.JobID] = true
		if e.CompletedAt == 0 {
			if e.Outcome != "unknown" || i != len(s.Entries)-1 {
				return false
			}
		} else if !validTime(e.CompletedAt) || e.CompletedAt < e.AdmittedAt || e.CompletedAt > s.ClockFloor || (e.Outcome != "completed" && e.Outcome != "not_started") {
			return false
		}
		if i > 0 && e.AdmittedAt < s.Entries[i-1].CompletedAt {
			return false
		}
	}
	return true
}
func decode(raw []byte) (State, error) {
	var s State
	if len(raw) == 0 || len(raw) > MaxBytes || json.Unmarshal(raw, &s) != nil || !valid(s) {
		return State{}, ErrInvalid
	}
	canonical, _ := json.Marshal(s)
	if !bytes.Equal(raw, canonical) {
		return State{}, ErrInvalid
	}
	return s, nil
}
func encode(s State) ([]byte, error) {
	if !valid(s) {
		return nil, ErrInvalid
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > MaxBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}

// Create is an explicit new-state initialization seam. It never creates its
// directory or replaces/adopts existing lock/state/intent files. No runtime calls it.
func Create(ctx context.Context, dir string, b Binding, now int64) (*Fence, error) {
	return open(ctx, dir, b, now, true)
}
func Open(ctx context.Context, dir string, b Binding) (*Fence, error) {
	return open(ctx, dir, b, 0, false)
}
func open(ctx context.Context, dir string, b Binding, now int64, create bool) (*Fence, error) {
	if ctx == nil || !validBinding(b) || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	info, owner, e := checkDirectory(dir)
	if e != nil {
		return nil, e
	}
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, e := openPrivate(filepath.Join(dir, "fence.lock"), flags, owner)
	if e != nil {
		return nil, e
	}
	f := &Fence{inner: &handle{directory: dir, binding: b, lock: file, directoryInfo: info, owner: owner}}
	fail := func(e error) (*Fence, error) { _ = file.Close(); return nil, e }
	if create {
		if !validTime(now) {
			return fail(ErrInvalid)
		}
		e = f.locked(ctx, func() error {
			for _, name := range []string{"state.json", "intent", "state.next"} {
				if _, e := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(e) {
					return ErrConflict
				}
			}
			raw, e := encode(State{Version: Version, Binding: b, ClockFloor: now, Entries: []Entry{}})
			if e != nil {
				return e
			}
			return f.persist(raw)
		})
		if e != nil {
			return fail(e)
		}
	} else {
		e = f.locked(ctx, func() error { _, e := f.read(); return e })
		if e != nil {
			return fail(e)
		}
	}
	return f, nil
}
func (f *Fence) locked(ctx context.Context, fn func() error) error {
	if f == nil || f.inner == nil || ctx == nil {
		return ErrInvalid
	}
	x := f.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return ErrUnavailable
	}
	if x.poisoned {
		return ErrUncertain
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	current, owner, e := checkDirectory(x.directory)
	if e != nil || owner != x.owner || !os.SameFile(current, x.directoryInfo) {
		x.poisoned = true
		return ErrUncertain
	}
	if e = lockFile(x.lock); e != nil {
		return e
	}
	defer unlockFile(x.lock)
	if e = checkNamedFile(x.lock, filepath.Join(x.directory, "fence.lock"), x.owner); e != nil {
		x.poisoned = true
		return ErrUncertain
	}
	return fn()
}
func (f *Fence) read() (State, error) {
	x := f.inner
	if _, e := os.Lstat(filepath.Join(x.directory, "intent")); !os.IsNotExist(e) {
		x.poisoned = true
		return State{}, ErrUncertain
	}
	file, e := openPrivate(filepath.Join(x.directory, "state.json"), os.O_RDONLY, x.owner)
	if e != nil {
		x.poisoned = true
		return State{}, ErrUncertain
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	if e != nil {
		return State{}, ErrUncertain
	}
	s, e := decode(raw)
	if e != nil || s.Binding != x.binding {
		x.poisoned = true
		return State{}, ErrUncertain
	}
	return s, nil
}
func (f *Fence) persist(raw []byte) error {
	x := f.inner
	fail := func() error { x.poisoned = true; return ErrUncertain }
	intent, e := openPrivate(filepath.Join(x.directory, "intent"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, x.owner)
	if e != nil {
		return fail()
	}
	if _, e = intent.Write([]byte(actionpermit.Digest(raw))); e != nil {
		_ = intent.Close()
		return fail()
	}
	if e = intent.Sync(); e != nil {
		_ = intent.Close()
		return fail()
	}
	if e = intent.Close(); e != nil {
		return fail()
	}
	if e = syncDirectory(x.directory); e != nil {
		return fail()
	}
	next, e := openPrivate(filepath.Join(x.directory, "state.next"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, x.owner)
	if e != nil {
		return fail()
	}
	if _, e = next.Write(raw); e != nil {
		_ = next.Close()
		return fail()
	}
	if e = next.Sync(); e != nil {
		_ = next.Close()
		return fail()
	}
	if e = next.Close(); e != nil {
		return fail()
	}
	if e = os.Rename(filepath.Join(x.directory, "state.next"), filepath.Join(x.directory, "state.json")); e != nil {
		return fail()
	}
	if e = syncDirectory(x.directory); e != nil {
		return fail()
	}
	if e = os.Remove(filepath.Join(x.directory, "intent")); e != nil {
		return fail()
	}
	if e = syncDirectory(x.directory); e != nil {
		return fail()
	}
	return nil
}

// Acquire commits at-most-once admission. Fresh is true only for this new commit;
// replay/status recovery never returns fresh, even if the old operation completed.
func (f *Fence) Acquire(ctx context.Context, o Owner, now int64) (entry Entry, fresh bool, err error) {
	if !validOwner(o) || !validTime(now) {
		return Entry{}, false, ErrInvalid
	}
	err = f.locked(ctx, func() error {
		s, e := f.read()
		if e != nil {
			return e
		}
		if now < s.ClockFloor {
			return ErrConflict
		}
		var floor uint64
		for _, old := range s.Entries {
			if old.Owner.Action == o.Action {
				floor = old.Owner.Sequence
				if old.Owner.JobID == o.JobID {
					if old.Owner != o {
						return ErrConflict
					}
					entry = old
					return nil
				}
			}
		}
		if o.Sequence <= floor {
			return ErrConflict
		}
		if len(s.Entries) >= MaxEntries {
			return ErrUnavailable
		}
		if len(s.Entries) > 0 && s.Entries[len(s.Entries)-1].CompletedAt == 0 {
			return ErrBusy
		}
		entry = Entry{Owner: o, AdmittedAt: now, Outcome: "unknown"}
		s.ClockFloor = now
		s.Entries = append(s.Entries, entry)
		raw, e := encode(s)
		if e != nil {
			return e
		}
		if e = f.persist(raw); e != nil {
			return e
		}
		fresh = true
		return nil
	})
	return
}

// Complete is for trusted local post-verification or a proven pre-start refusal.
// An uncertain/failed mutation MUST NOT call it. There is no force-clear/reset.
func (f *Fence) Complete(ctx context.Context, o Owner, outcome string, now int64) error {
	if !validOwner(o) || !validTime(now) || (outcome != "completed" && outcome != "not_started") {
		return ErrInvalid
	}
	return f.locked(ctx, func() error {
		s, e := f.read()
		if e != nil {
			return e
		}
		if now < s.ClockFloor {
			return ErrConflict
		}
		for i := range s.Entries {
			old := &s.Entries[i]
			if old.Owner.Action != o.Action || old.Owner.JobID != o.JobID {
				continue
			}
			if old.Owner != o {
				return ErrConflict
			}
			if old.CompletedAt != 0 {
				if old.Outcome != outcome {
					return ErrConflict
				}
				return nil
			}
			if i != len(s.Entries)-1 {
				return ErrConflict
			}
			old.CompletedAt = now
			old.Outcome = outcome
			s.ClockFloor = now
			raw, e := encode(s)
			if e != nil {
				return e
			}
			return f.persist(raw)
		}
		return ErrNotFound
	})
}
func (f *Fence) Status(ctx context.Context, o Owner) (entry Entry, err error) {
	if !validOwner(o) {
		return Entry{}, ErrInvalid
	}
	err = f.locked(ctx, func() error {
		s, e := f.read()
		if e != nil {
			return e
		}
		for _, x := range s.Entries {
			if x.Owner.Action == o.Action && x.Owner.JobID == o.JobID {
				if x.Owner != o {
					return ErrConflict
				}
				entry = x
				return nil
			}
		}
		return ErrNotFound
	})
	return
}
func (f *Fence) Close() error {
	if f == nil || f.inner == nil {
		return ErrUnavailable
	}
	x := f.inner
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.closed {
		return ErrUnavailable
	}
	x.closed = true
	return x.lock.Close()
}
