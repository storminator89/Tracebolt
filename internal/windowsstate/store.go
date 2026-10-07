package windowsstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"sync"
)

type fileID [24]byte // Volume serial number + 128-bit file ID.
type record struct {
	Name    string   `json:"name"`
	ID      fileID   `json:"id"`
	Hash    [32]byte `json:"hash"`
	Present bool     `json:"present"`
}
type manifest struct {
	Version       uint32   `json:"version"`
	Path          string   `json:"path"`
	RuntimeSID    string   `json:"runtime_sid"`
	InstallerOnly bool     `json:"installer_only"`
	MaxBytes      int64    `json:"max_bytes"`
	LockName      string   `json:"lock_name"`
	TempName      string   `json:"temp_name"`
	Generation    uint64   `json:"generation"`
	Pending       bool     `json:"pending"`
	RootID        fileID   `json:"root_id"`
	LockID        fileID   `json:"lock_id"`
	TempID        fileID   `json:"temp_id"`
	Files         []record `json:"files"`
	Directories   []record `json:"directories"`
}

// backend owns pinned native handles. All methods return already bounded bytes
// and validate handle identity, object type, link count and security. Its only
// production implementation is Windows; fixtures never touch host state.
type backend interface {
	rootID() fileID
	verify() error
	list() ([]string, error)
	read(name string, max int64) ([]byte, fileID, error)
	writeLock([]byte) error
	replace(name string, data []byte) (fileID, fileID, error)
	directoryID(name string) (fileID, error)
	createChild(name string, o Options) (backend, error)
	close() error
}

// Store serializes callers and becomes permanently poisoned after any storage
// or integrity failure. It never exposes the native handles or secret bytes in
// formatting. Close is safe after poisoning.
type Store struct {
	mu               sync.Mutex
	b                backend
	options          Options
	state            manifest
	lockBytes        []byte
	poisoned, closed bool
}

func (*Store) String() string             { return "<protected Windows state>" }
func (*Store) GoString() string           { return "<protected Windows state>" }
func (*Store) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("<protected Windows state>")) }

// Open opens an existing store or, with Create, creates a fresh final directory.
// It returns fs.ErrNotExist only when that final directory genuinely does not
// exist during an existing-store open. Missing used lock/temp/manifest/files are
// integrity failures, never permission to reset or re-enroll.
func Open(path string, o Options) (*Store, error) {
	if _, e := splitPath(path); e != nil {
		return nil, e
	}
	if e := validateOptions(o); e != nil {
		return nil, e
	}
	o.Names = slices.Clone(o.Names)
	slices.Sort(o.Names)
	o.Directories = slices.Clone(o.Directories)
	slices.Sort(o.Directories)
	b, e := openNative(path, o)
	if e != nil {
		return nil, e
	}
	s, e := openBackend(path, o, b)
	if e != nil {
		_ = b.close()
		return nil, e
	}
	return s, nil
}

func openBackend(path string, o Options, b backend) (*Store, error) {
	s := &Store{b: b, options: o}
	lock, lid, e := b.read(o.LockName, maxManifestBytes)
	if e != nil {
		return nil, ErrIntegrity
	}
	if o.Create {
		temp, tid, e := b.read(o.TempName, o.MaxBytes)
		if e != nil || len(temp) != 0 || len(lock) != 0 {
			return nil, ErrIntegrity
		}
		s.state = manifest{Version: 1, Path: path, RuntimeSID: o.RuntimeSID, InstallerOnly: o.InstallerOnly, MaxBytes: o.MaxBytes, LockName: o.LockName, TempName: o.TempName, Generation: 1, RootID: b.rootID(), LockID: lid, TempID: tid, Files: []record{}, Directories: []record{}}
		for _, n := range o.Names {
			s.state.Files = append(s.state.Files, record{Name: n})
		}
		for _, n := range o.Directories {
			s.state.Directories = append(s.state.Directories, record{Name: n})
		}
		if e = s.checkObjects(); e != nil {
			return nil, e
		}
		if e = s.commit(s.state); e != nil {
			return nil, e
		}
	} else {
		s.state, e = decodeManifest(lock)
		if e != nil {
			return nil, e
		}
		if !sameSchema(s.state, path, o) || s.state.RootID != b.rootID() || s.state.LockID != lid {
			return nil, ErrIntegrity
		}
		s.lockBytes = slices.Clone(lock)
	}
	if e = s.verify(); e != nil {
		return nil, e
	}
	return s, nil
}

func sameSchema(m manifest, path string, o Options) bool {
	if m.Path != path || m.RuntimeSID != o.RuntimeSID || m.InstallerOnly != o.InstallerOnly || m.MaxBytes != o.MaxBytes || m.LockName != o.LockName || m.TempName != o.TempName || len(m.Files) != len(o.Names) || len(m.Directories) != len(o.Directories) {
		return false
	}
	for i, r := range m.Files {
		if r.Name != o.Names[i] {
			return false
		}
	}
	for i, r := range m.Directories {
		if r.Name != o.Directories[i] {
			return false
		}
	}
	return true
}
func (s *Store) available() error {
	if s.closed {
		return ErrClosed
	}
	if s.poisoned {
		return ErrPoisoned
	}
	return nil
}
func (s *Store) fail(e error) error {
	s.poisoned = true
	if e == ErrIntegrity || e == ErrPolicy {
		return e
	}
	return ErrStorage
}
func (s *Store) index(name string) int {
	return slices.IndexFunc(s.state.Files, func(r record) bool { return r.Name == name })
}

// Read returns a copy of a bounded file. fs.ErrNotExist means only that the
// manifest records this configured name as never initialized.
func (s *Store) Read(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.available(); e != nil {
		return nil, e
	}
	i := s.index(name)
	if i < 0 {
		return nil, ErrPolicy
	}
	if e := s.verify(); e != nil {
		return nil, s.fail(e)
	}
	r := s.state.Files[i]
	if !r.Present {
		return nil, fs.ErrNotExist
	}
	data, id, e := s.b.read(name, s.options.MaxBytes)
	if e != nil {
		return nil, s.fail(e)
	}
	if id != r.ID || sha256.Sum256(data) != r.Hash {
		clear(data)
		return nil, s.fail(ErrIntegrity)
	}
	return data, nil
}

// Write durably marks the store pending before modifying its pre-existing temp,
// flushes that file before a handle-relative atomic rename, then commits the
// new identities/hashes. Any interrupted write requires explicit recovery; it
// cannot be retried using this handle or treated as a fresh empty store.
func (s *Store) Write(name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.available(); e != nil {
		return e
	}
	i := s.index(name)
	if i < 0 || int64(len(data)) > s.options.MaxBytes {
		return ErrPolicy
	}
	if e := s.verify(); e != nil {
		return s.fail(e)
	}
	next, e := s.begin()
	if e != nil {
		return e
	}
	id, tid, e := s.b.replace(name, data)
	if e != nil {
		return s.fail(e)
	}
	next.TempID = tid
	next.Files = slices.Clone(s.state.Files)
	next.Files[i] = record{Name: name, ID: id, Hash: sha256.Sum256(data), Present: true}
	if e = s.commit(next); e != nil {
		return s.fail(e)
	}
	if e = s.verify(); e != nil {
		return s.fail(e)
	}
	return nil
}

func (s *Store) begin() (manifest, error) {
	next := s.state
	if next.Generation == ^uint64(0) {
		return manifest{}, s.fail(ErrIntegrity)
	}
	next.Generation++
	next.Pending = true
	data, e := encodeManifest(next)
	if e != nil {
		return manifest{}, s.fail(e)
	}
	if e = s.b.writeLock(data); e != nil {
		return manifest{}, s.fail(e)
	}
	next.Pending = false
	return next, nil
}
func (s *Store) commit(next manifest) error {
	data, e := encodeManifest(next)
	if e != nil {
		return e
	}
	if _, e = decodeManifest(data); e != nil {
		return e
	}
	if e = s.b.writeLock(data); e != nil {
		return e
	}
	s.state = next
	s.lockBytes = slices.Clone(data)
	return nil
}

// CreateDirectoryStore creates one configured, never-created child as a fully
// initialized store and binds its directory identity into the parent manifest.
// It never adopts an existing directory. Child contents can change independently;
// the parent continues to verify that child's identity and protected ACL.
func (s *Store) CreateDirectoryStore(name string, o Options) (*Store, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.available(); e != nil {
		return nil, e
	}
	i := slices.IndexFunc(s.state.Directories, func(r record) bool { return r.Name == name })
	if i < 0 || s.state.Directories[i].Present || validateOptions(o) != nil || o.RuntimeSID != s.options.RuntimeSID || o.InstallerOnly != s.options.InstallerOnly || !o.Create {
		return nil, ErrPolicy
	}
	if _, e := splitPath(s.state.Path + `\` + name); e != nil {
		return nil, e
	}
	o.Names = slices.Clone(o.Names)
	slices.Sort(o.Names)
	o.Directories = slices.Clone(o.Directories)
	slices.Sort(o.Directories)
	if e := s.verify(); e != nil {
		return nil, s.fail(e)
	}
	next, e := s.begin()
	if e != nil {
		return nil, e
	}
	b, e := s.b.createChild(name, o)
	if e != nil {
		return nil, s.fail(e)
	}
	child, e := openBackend(s.state.Path+`\`+name, o, b)
	if e != nil {
		_ = b.close()
		return nil, s.fail(e)
	}
	next.Directories = slices.Clone(s.state.Directories)
	next.Directories[i] = record{Name: name, ID: b.rootID(), Present: true}
	if e = s.commit(next); e != nil {
		_ = child.Close()
		return nil, s.fail(e)
	}
	if e = s.verify(); e != nil {
		_ = child.Close()
		return nil, s.fail(e)
	}
	return child, nil
}

// Verify checks the complete fixed schema, all recorded identities and hashes,
// all directory/ancestor pins, the exclusive lock, and the empty scratch file.
func (s *Store) Verify() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.available(); e != nil {
		return e
	}
	if e := s.verify(); e != nil {
		return s.fail(e)
	}
	return nil
}
func (s *Store) verify() error {
	if s.b.rootID() != s.state.RootID {
		return ErrIntegrity
	}
	if e := s.b.verify(); e != nil {
		return e
	}
	data, id, e := s.b.read(s.options.LockName, maxManifestBytes)
	if e != nil || id != s.state.LockID || !bytes.Equal(data, s.lockBytes) {
		return ErrIntegrity
	}
	return s.checkObjects()
}
func (s *Store) checkObjects() error {
	temp, tid, e := s.b.read(s.options.TempName, s.options.MaxBytes)
	if e != nil || len(temp) != 0 || tid != s.state.TempID {
		return ErrIntegrity
	}
	entries, e := s.b.list()
	if e != nil {
		return e
	}
	want := []string{s.options.LockName, s.options.TempName}
	for _, r := range s.state.Files {
		data, id, e := s.b.read(r.Name, s.options.MaxBytes)
		if !r.Present {
			if e != fs.ErrNotExist {
				return ErrIntegrity
			}
			continue
		}
		valid := e == nil && id == r.ID && sha256.Sum256(data) == r.Hash
		clear(data)
		if !valid {
			return ErrIntegrity
		}
		want = append(want, r.Name)
	}
	for _, r := range s.state.Directories {
		id, e := s.b.directoryID(r.Name)
		if !r.Present {
			if e != fs.ErrNotExist {
				return ErrIntegrity
			}
			continue
		}
		if e != nil || id != r.ID {
			return ErrIntegrity
		}
		want = append(want, r.Name)
	}
	slices.Sort(entries)
	slices.Sort(want)
	if !slices.Equal(entries, want) {
		return ErrIntegrity
	}
	return nil
}

// Entries returns sorted present data-file and child-directory names, excluding
// lock and scratch. It validates the whole store first.
func (s *Store) Entries() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.available(); e != nil {
		return nil, e
	}
	if e := s.verify(); e != nil {
		return nil, s.fail(e)
	}
	var names []string
	for _, r := range append(slices.Clone(s.state.Files), s.state.Directories...) {
		if r.Present {
			names = append(names, r.Name)
		}
	}
	slices.Sort(names)
	return names, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	clear(s.lockBytes)
	s.lockBytes = nil
	if e := s.b.close(); e != nil {
		return ErrStorage
	}
	return nil
}

func encodeManifest(m manifest) ([]byte, error) {
	b, e := json.Marshal(m)
	if e != nil {
		return nil, ErrIntegrity
	}
	sum := sha256.Sum256(b)
	out := append([]byte("TBWS1\n"+hex.EncodeToString(sum[:])+"\n"), b...)
	if int64(len(out)) > maxManifestBytes {
		return nil, ErrIntegrity
	}
	return out, nil
}
func decodeManifest(data []byte) (manifest, error) {
	var m manifest
	if len(data) < 71 || int64(len(data)) > maxManifestBytes || string(data[:6]) != "TBWS1\n" || data[70] != '\n' {
		return m, ErrIntegrity
	}
	sum := sha256.Sum256(data[71:])
	if string(data[6:70]) != hex.EncodeToString(sum[:]) {
		return m, ErrIntegrity
	}
	d := json.NewDecoder(bytes.NewReader(data[71:]))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return manifest{}, ErrIntegrity
	}
	canonical, e := encodeManifest(m)
	if e != nil || !bytes.Equal(canonical, data) || m.Version != 1 || m.Generation == 0 || m.Pending {
		return manifest{}, ErrIntegrity
	}
	o := Options{RuntimeSID: m.RuntimeSID, InstallerOnly: m.InstallerOnly, Names: []string{}, Directories: []string{}, LockName: m.LockName, TempName: m.TempName, MaxBytes: m.MaxBytes}
	for _, r := range m.Files {
		o.Names = append(o.Names, r.Name)
	}
	for _, r := range m.Directories {
		o.Directories = append(o.Directories, r.Name)
	}
	if validateOptions(o) != nil || !slices.IsSorted(o.Names) || !slices.IsSorted(o.Directories) {
		return manifest{}, ErrIntegrity
	}
	if _, e := splitPath(m.Path); e != nil {
		return manifest{}, ErrIntegrity
	}
	ids := map[fileID]bool{}
	add := func(id fileID) bool {
		if id == (fileID{}) || ids[id] {
			return false
		}
		ids[id] = true
		return true
	}
	if !add(m.RootID) || !add(m.LockID) || !add(m.TempID) {
		return manifest{}, ErrIntegrity
	}
	for _, r := range append(slices.Clone(m.Files), m.Directories...) {
		if r.Present {
			if !add(r.ID) {
				return manifest{}, ErrIntegrity
			}
		} else if r.ID != (fileID{}) || r.Hash != ([32]byte{}) {
			return manifest{}, ErrIntegrity
		}
	}
	for _, r := range m.Directories {
		if r.Hash != ([32]byte{}) {
			return manifest{}, ErrIntegrity
		}
	}
	return m, nil
}
