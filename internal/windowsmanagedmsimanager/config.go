package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	msi "localrmm/internal/windowsmanagedmsi"
	"path/filepath"
	"time"
)

const ConfigVersion = "tracebolt.windows-managed-msi-manager-config.v1"

var ErrConfiguration = errors.New("windows_managed_msi_manager_configuration_invalid")

type Config struct {
	Version                 string      `json:"version"`
	Enabled                 bool        `json:"enabled"`
	Binding                 msi.Binding `json:"binding"`
	StateDirectory          string      `json:"stateDirectory"`
	PrivateKeyFile          string      `json:"privateKeyFile"`
	SetupReceiptFile        string      `json:"setupReceiptFile"`
	SetupPlanDigest         string      `json:"setupPlanDigest"`
	SetupRegistrationDigest string      `json:"setupRegistrationDigest"`
}

func absolute(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }
func validConfig(c Config) bool {
	return c.Version == ConfigVersion && c.Enabled && c.Binding.Validate() == nil && absolute(c.StateDirectory) && c.PrivateKeyFile == setupPath(c.StateDirectory, "manager.key") && c.SetupReceiptFile == setupPath(c.StateDirectory, "complete.json") && msi.ValidDigest(c.SetupPlanDigest) && msi.ValidDigest(c.SetupRegistrationDigest)
}
func checkReceipt(c Config) error {
	var receipt setupComplete
	if _, e := canonicalRead(c.SetupReceiptFile, &receipt); e != nil {
		return ErrConfiguration
	}
	raw, _ := json.Marshal(c)
	if receipt.Version != SetupPlanVersion || receipt.PlanDigest != c.SetupPlanDigest || receipt.RegistrationDigest != c.SetupRegistrationDigest || receipt.ConfigurationDigest != msi.Digest(raw) {
		return ErrConfiguration
	}
	return nil
}
func Load(ctx context.Context, store *enrollmentstore.Store, path, stateDirectory string, forbidden ...ed25519.PublicKey) (*Manager, error) {
	if store == nil || ctx == nil || !absolute(path) || !absolute(stateDirectory) {
		return nil, ErrConfiguration
	}
	var c Config
	raw, e := canonicalRead(path, &c)
	if e != nil || !validConfig(c) || c.StateDirectory != stateDirectory || checkReceipt(c) != nil {
		return nil, ErrConfiguration
	}
	key, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, ed25519.PrivateKeySize)
	defer clear(key)
	if e != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32])) {
		return nil, ErrConfiguration
	}
	hash := sha256.Sum256(key)
	for _, other := range forbidden {
		if bytes.Equal(other, key[32:]) {
			return nil, ErrConfiguration
		}
	}
	if e = store.OpenWindowsManagedMSI(ctx, ed25519.PublicKey(key[32:])); e != nil {
		return nil, e
	}
	spool, e := OpenSpool(stateDirectory)
	if e != nil {
		return nil, e
	}
	check := func() error {
		current, e := lanconfig.ReadProtected(path, true, 32768)
		if e != nil || !bytes.Equal(current, raw) {
			return ErrConfiguration
		}
		currentKey, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, ed25519.PrivateKeySize)
		defer clear(currentKey)
		if e != nil || sha256.Sum256(currentKey) != hash || checkReceipt(c) != nil {
			return ErrConfiguration
		}
		return nil
	}
	m, e := Open(ctx, store, c.Binding, ed25519.PrivateKey(key), spool, time.Now, check)
	if e != nil {
		return nil, e
	}
	for _, pub := range m.PublicKeys() {
		for _, other := range forbidden {
			if bytes.Equal(pub, other) {
				m.Close()
				return nil, ErrConfiguration
			}
		}
	}
	return m, nil
}
