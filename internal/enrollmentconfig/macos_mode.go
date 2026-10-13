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

const MacOSInitializingFile = "identity-mode-macos-initializing-v1.json"
const MacOSReadyFile = "identity-mode-macos-ready-v1.json"

// Both markers are immutable and create-only. The first survives every failed
// or interrupted creation; the second is published only after ledger validation.
// A lone marker is intentionally not a recoverable fresh-initialization state.
func (m Material) macOSMarker(phase string) []byte {
	if m.value == nil || m.value.lan.Profile != lanconfig.TLS || m.value.config.Profile != lanconfig.TLS {
		return nil
	}
	cfg := m.StoreConfig()
	cfg.Binding.CollectionProfile = enrollmentcrypto.CollectionProfile
	cfg.Platform = "darwin"
	raw, _ := json.Marshal(struct {
		SchemaVersion       string                 `json:"schemaVersion"`
		Phase               string                 `json:"phase"`
		PrimaryIdentityMode json.RawMessage        `json:"primaryIdentityMode"`
		StoreConfig         enrollmentstate.Config `json:"storeConfig"`
	}{"tracebolt.identity-mode.macos.v1", phase, m.marker(), cfg})
	return raw
}

// macOSState is read-only and also runs with the scope disabled. Once Mac state
// exists, disabling the flag cannot erase or bypass its initialization evidence.
func (m Material) macOSState(dir string) (bool, error) {
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
	initializing, err := exists(MacOSInitializingFile)
	if err != nil {
		return false, err
	}
	ready, err := exists(MacOSReadyFile)
	if err != nil {
		return false, err
	}
	fragments := false
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		present, err := exists(MacOSDatabaseFile + suffix)
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
	for _, marker := range []struct{ name, phase string }{{MacOSInitializingFile, "initializing"}, {MacOSReadyFile, "ready"}} {
		expected := m.macOSMarker(marker.phase)
		raw, err := lanconfig.ReadProtected(filepath.Join(dir, marker.name), true, 8192)
		if len(expected) == 0 || err != nil || !bytes.Equal(raw, expected) {
			return false, ErrConfiguration
		}
	}
	path := filepath.Join(dir, MacOSDatabaseFile)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || lanstore.ValidateStateFile(path) != nil {
		return false, ErrConfiguration
	}
	return true, nil
}

func createMacOSMarker(dir, name string, raw []byte) error {
	path := filepath.Join(dir, name)
	if len(raw) == 0 || lanstore.ValidateStateFile(path) != nil {
		return ErrConfiguration
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrConfiguration
	}
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrConfiguration
	}
	parent, err := os.Open(dir)
	if err != nil {
		return ErrConfiguration
	}
	err = parent.Sync()
	closeErr = parent.Close()
	if err != nil || closeErr != nil {
		return ErrConfiguration
	}
	return nil
}

// OpenMacOSStore owns the complete fresh initialization boundary. No caller can
// receive a new authority until the ready marker is durable. Existing markers
// always select the non-creating path; no missing used ledger is initialized.
func (m Material) OpenMacOSStore(dir string) (*enrollmentstore.Store, error) {
	cfg, err := m.MacOSStoreConfig()
	if err != nil || dir != m.value.lan.StateDirectory {
		return nil, ErrConfiguration
	}
	primary, err := lanconfig.ReadProtected(filepath.Join(dir, ModeFile), true, 8192)
	if err != nil || !bytes.Equal(primary, m.marker()) {
		return nil, ErrConfiguration
	}
	ready, err := m.macOSState(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, MacOSDatabaseFile)
	if ready {
		return enrollmentstore.OpenExisting(path, cfg, m.Issuer().IssuerDER())
	}
	if err = createMacOSMarker(dir, MacOSInitializingFile, m.macOSMarker("initializing")); err != nil {
		return nil, err
	}
	store, err := enrollmentstore.Create(path, cfg, m.Issuer().IssuerDER())
	if err != nil {
		return nil, err
	}
	if err = createMacOSMarker(dir, MacOSReadyFile, m.macOSMarker("ready")); err != nil {
		store.Close()
		return nil, err
	}
	if ready, err = m.macOSState(dir); err != nil || !ready {
		store.Close()
		return nil, ErrConfiguration
	}
	return store, nil
}
