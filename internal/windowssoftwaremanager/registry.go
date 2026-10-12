package windowssoftwaremanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"

	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/windowssoftwarejob"
)

const RegistryVersion = "tracebolt.windows-prepared-msi-manager-registry.v2"
const maxRegistryBytes = 65536

type RegistryConfig struct {
	Version     string   `json:"version"`
	Enabled     bool     `json:"enabled"`
	ManagerID   string   `json:"managerId"`
	ConfigFiles []string `json:"configFiles"`
}

func validRegistry(c RegistryConfig, limit int) bool {
	if c.Version != RegistryVersion || !c.Enabled || limit <= 0 || len(c.ConfigFiles) == 0 || len(c.ConfigFiles) > limit || len(c.ConfigFiles) > windowssoftwarejob.MaxDevices {
		return false
	}
	seen := map[string]bool{}
	for _, p := range c.ConfigFiles {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}

// registryConfigFiles accepts one unchanged legacy v1 config, or one explicit
// bounded v2 manifest. Registries never nest or discover/adopt disk state.
func registryConfigFiles(path string, limit int) ([]string, error) {
	files, _, err := registryConfigFilesSnapshot(path, limit)
	return files, err
}
func registryConfigFilesSnapshot(path string, limit int) ([]string, []byte, error) {
	raw, e := lanconfig.ReadProtected(path, true, maxRegistryBytes)
	if e != nil {
		return nil, nil, ErrConfiguration
	}
	var head struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return nil, nil, ErrConfiguration
	}
	if head.Version == ConfigVersion {
		var c Config
		if strictManagerObject(raw, &c) != nil || !validConfig(c) || checkSetupReceipt(c) != nil {
			return nil, nil, ErrConfiguration
		}
		return []string{path}, raw, nil
	}
	var c RegistryConfig
	if strictManagerObject(raw, &c) != nil || !validRegistry(c, limit) {
		return nil, nil, ErrConfiguration
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(raw, canonical) {
		return nil, nil, ErrConfiguration
	}
	for _, p := range c.ConfigFiles {
		body, e := lanconfig.ReadProtected(p, true, 8192)
		if e != nil {
			return nil, nil, ErrConfiguration
		}
		var entry Config
		if strictManagerObject(body, &entry) != nil || !validConfig(entry) || entry.Binding.ManagerID != c.ManagerID || checkSetupReceipt(entry) != nil {
			return nil, nil, ErrConfiguration
		}
	}
	return append([]string(nil), c.ConfigFiles...), raw, nil
}

// LoadRegistry never upgrades a v1 config. Legacy files retain the existing
// single-device loader; a v2 file must be explicitly supplied at startup.
func LoadRegistry(ctx context.Context, store *enrollmentstore.Store, path string, forbidden ...ed25519.PublicKey) (*windowssoftwarejob.Registry, error) {
	if store == nil || ctx == nil {
		return nil, ErrConfiguration
	}
	files, raw, e := registryConfigFilesSnapshot(path, store.Config().RecordLimit)
	if e != nil {
		return nil, e
	}
	var header struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return nil, ErrConfiguration
	}
	check := func() error {
		current, e := lanconfig.ReadProtected(path, true, maxRegistryBytes)
		if e != nil || !bytes.Equal(raw, current) {
			return ErrConfiguration
		}
		return nil
	}
	managers := []*windowssoftwarejob.Manager{}
	fail := func(err error) (*windowssoftwarejob.Registry, error) {
		for _, m := range managers {
			m.Close()
		}
		return nil, err
	}
	for _, p := range files {
		var m *windowssoftwarejob.Manager
		if header.Version == ConfigVersion {
			m, e = Load(ctx, store, p, forbidden...)
		} else {
			m, e = load(ctx, store, p, true, check, forbidden...)
		}
		if e != nil {
			return fail(e)
		}
		managers = append(managers, m)
	}
	if e = check(); e != nil {
		return fail(e)
	}
	registry, e := windowssoftwarejob.NewRegistry(managers)
	if e != nil {
		return fail(e)
	}
	return registry, nil
}
