package macosinventorysender

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	state "localrmm/internal/macosinventorystate"
	wire "localrmm/internal/macosinventorywire"
)

var (
	ErrStorage            = errors.New("macos_inventory_storage_rejected")
	ErrStorageLocked      = errors.New("macos_inventory_storage_locked")
	ErrStorageUnsupported = errors.New("macos_inventory_storage_unsupported")
)

const (
	storageLockName       = "inventory.lock"
	storageUsedName       = "inventory-used.json"
	storageReadyName      = "inventory-ready.json"
	storageCheckpointName = "checkpoint.json"
	storageTempName       = ".inventory.tmp"
	storageMarkerMax      = 4096
)

// storageBackend is private. Only the Darwin implementation supplies protected
// disk operations; platform-independent tests supply a synthetic fault model.
// snapshot verifies descriptor identity and exact prior bytes for every file.
// publish may replace only the checkpoint, and requires exact expected bytes.
// An error or panic may follow durable publication and must poison its owner.
type storageBackend interface {
	snapshot() (map[string][]byte, error)
	publish(name string, expected, next []byte) error
	close() error
}

// Storage owns one exclusive protected directory until Close. Its independent
// immutable used/ready markers bind the exact original enable, not a current
// renewable certificate. Missing state never permits initialization or repair.
// This source candidate does not defend against root/runtime-UID compromise or
// restoration of an old complete private-state backup. Native acceptance is pending.
type Storage struct {
	mu          sync.Mutex
	backend     storageBackend
	original    []byte
	initialized bool
	poisoned    bool
	closed      bool
}

func (*Storage) String() string               { return "macOS inventory protected storage (contents redacted)" }
func (s *Storage) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.String()) }
func (*Storage) MarshalJSON() ([]byte, error) { return []byte(`{"contentsRedacted":true}`), nil }

var _ state.DurableCommitter = (*Storage)(nil)

// OpenFreshStorage consumes a new dedicated directory/lock domain. The caller
// must first establish authentic original identity and explicit fresh consent.
// A prior lock, marker, checkpoint, temporary or unknown entry is never adopted.
func OpenFreshStorage(path string, originalEnable []byte) (*Storage, error) {
	if !storageValidEnable(originalEnable) {
		return nil, ErrStorage
	}
	b, err := openStorageBackend(path, true)
	if err != nil {
		return nil, err
	}
	s, _, err := openStorageProtocol(b, originalEnable, true)
	return s, err
}

// OpenExistingStorage requires all original markers and a canonical nonempty
// checkpoint under exclusive ownership. It never creates missing paths or files.
// Restore must run before using the returned checkpoint as a live sender state.
func OpenExistingStorage(path string, originalEnable []byte) (*Storage, []byte, error) {
	if !storageValidEnable(originalEnable) {
		return nil, nil, ErrStorage
	}
	b, err := openStorageBackend(path, false)
	if err != nil {
		return nil, nil, err
	}
	return openStorageProtocol(b, originalEnable, false)
}

func storageValidEnable(raw []byte) bool {
	c, err := wire.DecodeControl(raw)
	return err == nil && c.Enabled
}

func storageMarker(name string, original []byte) []byte {
	version := "tracebolt.macos-read-inventory-storage-used.v1"
	if name == storageReadyName {
		version = "tracebolt.macos-read-inventory-storage-ready.v1"
	}
	raw, _ := json.Marshal(struct {
		SchemaVersion  string `json:"schemaVersion"`
		OriginalEnable []byte `json:"originalEnable"`
	}{version, original})
	return raw
}

func storageLayout(files map[string][]byte, original []byte, ready bool) bool {
	if !ready {
		return len(files) == 0
	}
	return len(files) == 3 &&
		bytes.Equal(files[storageUsedName], storageMarker(storageUsedName, original)) &&
		bytes.Equal(files[storageReadyName], storageMarker(storageReadyName, original)) &&
		state.ValidateCheckpoint(files[storageCheckpointName], original) == nil
}

func openStorageProtocol(b storageBackend, original []byte, fresh bool) (s *Storage, raw []byte, result error) {
	if b == nil {
		return nil, nil, ErrStorage
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = b.close()
		}
	}()
	if !storageValidEnable(original) {
		return nil, nil, ErrStorage
	}
	files, err := b.snapshot()
	if err != nil || !storageLayout(files, original, !fresh) {
		return nil, nil, ErrStorage
	}
	s = &Storage{backend: b, original: bytes.Clone(original), initialized: !fresh}
	accepted = true
	return s, bytes.Clone(files[storageCheckpointName]), nil
}

// storageInitialCapture compares against the pure initializer's exact shape.
// A valid historical or acknowledged checkpoint cannot be adopted as fresh.
type storageInitialCapture struct{ raw []byte }

func (c *storageInitialCapture) CreateFresh(raw []byte) error { c.raw = bytes.Clone(raw); return nil }
func (*storageInitialCapture) Commit([]byte, []byte) error    { return ErrStorage }
func storageFreshCheckpoint(raw, original []byte) bool {
	if state.ValidateCheckpoint(raw, original) != nil {
		return false
	}
	var clock struct {
		ClockAt time.Time `json:"clockAt"`
	}
	if json.Unmarshal(raw, &clock) != nil {
		return false
	}
	c := &storageInitialCapture{}
	pure, err := state.InitializeFresh(c, original, clock.ClockAt)
	if err != nil {
		return false
	}
	pure.Close()
	return bytes.Equal(c.raw, raw)
}

// CreateFresh durably publishes the irreversible used marker BEFORE checkpoint
// publication, then the independent ready marker. Neither marker is ever
// rewritten or removed. Interrupted initialization has no recovery/reset path.
func (s *Storage) CreateFresh(next []byte) error {
	if s == nil {
		return ErrStorage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || s.initialized || s.backend == nil {
		return ErrStorage
	}
	// Set before invoking any callback; even a recovered panic leaves it poisoned.
	s.poisoned = true
	if !storageFreshCheckpoint(next, s.original) {
		return ErrStorage
	}
	files, err := s.backend.snapshot()
	if err != nil || !storageLayout(files, s.original, false) {
		return ErrStorage
	}
	for _, item := range []struct {
		name string
		raw  []byte
	}{
		{storageUsedName, storageMarker(storageUsedName, s.original)},
		{storageCheckpointName, bytes.Clone(next)},
		{storageReadyName, storageMarker(storageReadyName, s.original)},
	} {
		if s.backend.publish(item.name, nil, item.raw) != nil {
			return ErrStorage
		}
	}
	files, err = s.backend.snapshot()
	if err != nil || !storageLayout(files, s.original, true) || !bytes.Equal(files[storageCheckpointName], next) {
		return ErrStorage
	}
	s.initialized, s.poisoned = true, false
	return nil
}

// Commit verifies the exact expected checkpoint and every immutable marker even
// for an identical-byte no-op. Any failure is uncertain and poisons this owner;
// only a new exclusive existing-state open may inspect the actual durable result.
func (s *Storage) Commit(expected, next []byte) error {
	if s == nil {
		return ErrStorage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned || !s.initialized || s.backend == nil {
		return ErrStorage
	}
	s.poisoned = true
	if state.ValidateCheckpoint(expected, s.original) != nil || state.ValidateCheckpoint(next, s.original) != nil {
		return ErrStorage
	}
	files, err := s.backend.snapshot()
	if err != nil || !storageLayout(files, s.original, true) || !bytes.Equal(files[storageCheckpointName], expected) {
		return ErrStorage
	}
	if !bytes.Equal(expected, next) && s.backend.publish(storageCheckpointName, bytes.Clone(expected), bytes.Clone(next)) != nil {
		return ErrStorage
	}
	files, err = s.backend.snapshot()
	if err != nil || !storageLayout(files, s.original, true) || !bytes.Equal(files[storageCheckpointName], next) {
		return ErrStorage
	}
	s.poisoned = false
	return nil
}

// Close releases ownership only; it never removes fences, temporaries or data.
// Callers must cancel and join their collectors/senders before releasing the lock.
func (s *Storage) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.backend == nil {
		return nil
	}
	if s.backend.close() != nil {
		return ErrStorage
	}
	return nil
}
