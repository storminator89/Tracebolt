package enrollmentconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
)

const MacOSInventoryInitializingFile = "identity-mode-macos-inventory-initializing-v1.json"
const MacOSInventoryReadyFile = "identity-mode-macos-inventory-ready-v1.json"

// Both markers are immutable and create-only. The first survives every failed
// or interrupted creation; the second is published only after ledger validation.
// A lone marker is intentionally not a recoverable fresh-initialization state.
func (m Material) macOSInventoryMarker(phase string) []byte {
	if m.value == nil || m.value.lan.Profile != lanconfig.TLS || m.value.config.Profile != lanconfig.TLS {
		return nil
	}
	cfg := m.StoreConfig()
	cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileMacOSInventory
	cfg.Platform = "darwin"
	raw, _ := json.Marshal(struct {
		SchemaVersion       string                 `json:"schemaVersion"`
		Phase               string                 `json:"phase"`
		PrimaryIdentityMode json.RawMessage        `json:"primaryIdentityMode"`
		StoreConfig         enrollmentstate.Config `json:"storeConfig"`
	}{"tracebolt.identity-mode.macos-inventory.v1", phase, m.marker(), cfg})
	return raw
}

// macOSInventoryState is read-only and also runs with the scope disabled. Once Mac state
// exists, disabling the flag cannot erase or bypass its initialization evidence.
func (m Material) macOSInventoryState(dir string) (bool, error) {
	exists := func(name string) (bool, error) {
		_, err := os.Lstat(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, ErrConfiguration
		}
		return true, nil
	}
	initializing, err := exists(MacOSInventoryInitializingFile)
	if err != nil {
		return false, err
	}
	ready, err := exists(MacOSInventoryReadyFile)
	if err != nil {
		return false, err
	}
	fragments := false
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		present, err := exists(MacOSInventoryDatabaseFile + suffix)
		if err != nil {
			return false, err
		}
		fragments = fragments || present
	}
	if !initializing && !ready && !fragments {
		return false, nil
	}
	if !initializing || !ready {
		return false, ErrConfiguration
	}
	for _, marker := range []struct{ name, phase string }{{MacOSInventoryInitializingFile, "initializing"}, {MacOSInventoryReadyFile, "ready"}} {
		expected := m.macOSInventoryMarker(marker.phase)
		raw, err := lanconfig.ReadProtected(filepath.Join(dir, marker.name), true, 8192)
		if len(expected) == 0 || err != nil || !bytes.Equal(raw, expected) {
			return false, ErrConfiguration
		}
	}
	path := filepath.Join(dir, MacOSInventoryDatabaseFile)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || lanstore.ValidateStateFile(path) != nil {
		return false, ErrConfiguration
	}
	return true, nil
}

// OpenMacOSInventoryStore owns the complete fresh initialization boundary. No caller can
// receive a new authority until the ready marker is durable. Existing markers
// always select the non-creating path; no missing used ledger is initialized.
func (m Material) OpenMacOSInventoryStore(dir string) (*enrollmentstore.Store, error) {
	cfg, err := m.MacOSInventoryStoreConfig()
	if err != nil || dir != m.value.lan.StateDirectory {
		return nil, ErrConfiguration
	}
	primary, err := lanconfig.ReadProtected(filepath.Join(dir, ModeFile), true, 8192)
	if err != nil || !bytes.Equal(primary, m.marker()) {
		return nil, ErrConfiguration
	}
	ready, err := m.macOSInventoryState(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, MacOSInventoryDatabaseFile)
	if ready {
		return enrollmentstore.OpenExisting(path, cfg, m.Issuer().IssuerDER())
	}
	if err = createMacOSMarker(dir, MacOSInventoryInitializingFile, m.macOSInventoryMarker("initializing")); err != nil {
		return nil, err
	}
	store, err := enrollmentstore.Create(path, cfg, m.Issuer().IssuerDER())
	if err != nil {
		return nil, err
	}
	if err = createMacOSMarker(dir, MacOSInventoryReadyFile, m.macOSInventoryMarker("ready")); err != nil {
		store.Close()
		return nil, err
	}
	if ready, err = m.macOSInventoryState(dir); err != nil || !ready {
		store.Close()
		return nil, ErrConfiguration
	}
	return store, nil
}

// OpenRetainedMacOSInventoryStore opens only already fenced state for retention
// maintenance. It never enables routes, allocates a new identity domain or
// creates missing state, including when the collection config flag is false.
func (m Material) OpenRetainedMacOSInventoryStore(dir string) (*enrollmentstore.Store, error) {
	if m.value == nil || dir != m.value.lan.StateDirectory {
		return nil, ErrConfiguration
	}
	ready, err := m.macOSInventoryState(dir)
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, nil
	}
	primary, err := lanconfig.ReadProtected(filepath.Join(dir, ModeFile), true, 8192)
	if err != nil || !bytes.Equal(primary, m.marker()) {
		return nil, ErrConfiguration
	}
	cfg := m.StoreConfig()
	cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileMacOSInventory
	cfg.Platform = "darwin"
	return enrollmentstore.OpenExisting(filepath.Join(dir, MacOSInventoryDatabaseFile), cfg, m.Issuer().IssuerDER())
}
