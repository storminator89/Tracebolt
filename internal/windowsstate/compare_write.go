package windowsstate

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
)

// ErrCompare is a stale or mismatched expected file value. A comparison
// failure performs no write and does not poison an otherwise healthy handle.
var ErrCompare = errors.New("protected Windows state comparison failed")

// RequireInstallerSchema verifies an already-open store's fixed installer-only
// schema and current protected state. It never creates a file or grants access.
// The caller must independently protect the original used-state marker; the
// method cannot detect a complete rollback or replacement of all state.
func (s *Store) RequireInstallerSchema(names []string, lock, temp string, max int64) error {
	if s == nil {
		return ErrPolicy
	}
	want := Options{InstallerOnly: true, Names: slices.Clone(names), LockName: lock, TempName: temp, MaxBytes: max}
	if validateOptions(want) != nil {
		return ErrPolicy
	}
	slices.Sort(want.Names)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.available(); e != nil {
		return e
	}
	if !s.options.InstallerOnly || s.options.RuntimeSID != "" || len(s.options.Directories) != 0 || s.options.LockName != lock || s.options.TempName != temp || s.options.MaxBytes != max || !slices.Equal(s.options.Names, want.Names) {
		return ErrPolicy
	}
	if e := s.verify(); e != nil {
		return s.fail(e)
	}
	return nil
}

// CompareAndWrite atomically compares one protected file against its exact
// prior bytes, then uses the ordinary pending-manifest, flush and replacement
// protocol under the same Store mutex. expectedAbsent distinguishes a never-
// initialized name from an initialized empty file; it is not evidence that an
// entire missing store is fresh. Any write/verification error poisons the store
// and may leave an uncertain outcome; callers must not blindly retry it.
func (s *Store) CompareAndWrite(name string, expected []byte, expectedAbsent bool, nextData []byte) error {
	if s == nil {
		return ErrPolicy
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.available(); e != nil {
		return e
	}
	i := s.index(name)
	if i < 0 || int64(len(nextData)) > s.options.MaxBytes || int64(len(expected)) > s.options.MaxBytes || (expectedAbsent && expected != nil) {
		return ErrPolicy
	}
	if e := s.verify(); e != nil {
		return s.fail(e)
	}
	r := s.state.Files[i]
	if r.Present == expectedAbsent {
		return ErrCompare
	}
	if r.Present {
		data, id, e := s.b.read(name, s.options.MaxBytes)
		if e != nil || id != r.ID || sha256.Sum256(data) != r.Hash {
			clear(data)
			return s.fail(ErrIntegrity)
		}
		equal := bytes.Equal(data, expected)
		clear(data)
		if !equal {
			return ErrCompare
		}
	}
	next, e := s.begin()
	if e != nil {
		return e
	}
	id, tid, e := s.b.replace(name, nextData)
	if e != nil {
		return s.fail(e)
	}
	next.TempID = tid
	next.Files = slices.Clone(s.state.Files)
	next.Files[i] = record{Name: name, ID: id, Hash: sha256.Sum256(nextData), Present: true}
	if e = s.commit(next); e != nil {
		return s.fail(e)
	}
	if e = s.verify(); e != nil {
		return s.fail(e)
	}
	return nil
}
