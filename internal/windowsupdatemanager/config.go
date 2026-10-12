// Package windowsupdatemanager opens explicitly provisioned selected WUA job
// source state. Load never creates keys or grants; the explicit local setup
// command is the separate create-only provisioning entry point.
package windowsupdatemanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanconfig"
	"localrmm/internal/windowsupdatejob"
)

const ConfigVersion = "tracebolt.windows-selected-update-manager-config.v1"

var ErrConfiguration = errors.New("windows_update_manager_configuration_invalid")

type Config struct {
	Version                 string                   `json:"version"`
	Enabled                 bool                     `json:"enabled"`
	Binding                 windowsupdatejob.Binding `json:"binding"`
	PrivateKeyFile          string                   `json:"privateKeyFile"`
	SetupReceiptFile        string                   `json:"setupReceiptFile,omitempty"`
	SetupPlanDigest         string                   `json:"setupPlanDigest,omitempty"`
	SetupRegistrationDigest string                   `json:"setupRegistrationDigest,omitempty"`
}

func validConfig(c Config) bool {
	return c.Version == ConfigVersion && c.Enabled && windowsupdatejob.ValidBinding(c.Binding) && filepath.IsAbs(c.PrivateKeyFile) && filepath.Clean(c.PrivateKeyFile) == c.PrivateKeyFile && (!hasSetupReceipt(c) || filepath.IsAbs(c.SetupReceiptFile) && filepath.Clean(c.SetupReceiptFile) == c.SetupReceiptFile && actionpermit.ValidDigest(c.SetupPlanDigest) && actionpermit.ValidDigest(c.SetupRegistrationDigest))
}
func Load(ctx context.Context, store *enrollmentstore.Store, path string, forbidden ...ed25519.PublicKey) (*windowsupdatejob.Manager, error) {
	return load(ctx, store, path, false, nil, forbidden...)
}
func load(ctx context.Context, store *enrollmentstore.Store, path string, registered bool, registryCheck func() error, forbidden ...ed25519.PublicKey) (*windowsupdatejob.Manager, error) {
	if store == nil || ctx == nil || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || store.Config().Binding.Profile != "tls" || store.Config().Binding.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory {
		return nil, ErrConfiguration
	}
	raw, e := lanconfig.ReadProtected(path, true, 8192)
	if e != nil {
		return nil, ErrConfiguration
	}
	var c Config
	if strictManagerObject(raw, &c) != nil || !validConfig(c) || c.Binding.ManagerID != store.Config().Binding.InstanceID {
		return nil, ErrConfiguration
	}
	if hasSetupReceipt(c) {
		canonical, _ := json.Marshal(c)
		if !bytes.Equal(raw, canonical) || checkSetupReceipt(c) != nil {
			return nil, ErrConfiguration
		}
	}
	key, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, ed25519.PrivateKeySize)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return nil, ErrConfiguration
	}
	defer clear(key)
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(derived, key) {
		return nil, ErrConfiguration
	}
	keyHash := sha256.Sum256(key)
	for _, other := range forbidden {
		if bytes.Equal(derived.Public().(ed25519.PublicKey), other) {
			return nil, ErrConfiguration
		}
	}
	if e = store.OpenWindowsUpdateJobs(ctx, derived.Public().(ed25519.PublicKey)); e != nil {
		return nil, e
	}
	check := func() error {
		if registryCheck != nil {
			if e := registryCheck(); e != nil {
				return e
			}
		}
		current, e := lanconfig.ReadProtected(path, true, 8192)
		if e != nil || !bytes.Equal(current, raw) {
			return ErrConfiguration
		}
		loaded, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, ed25519.PrivateKeySize)
		defer clear(loaded)
		if e != nil || len(loaded) != ed25519.PrivateKeySize || sha256.Sum256(loaded) != keyHash {
			return ErrConfiguration
		}
		if checkSetupReceipt(c) != nil {
			return ErrConfiguration
		}
		return nil
	}
	var m *windowsupdatejob.Manager
	if registered {
		m, e = windowsupdatejob.OpenRegisteredTransactional(ctx, store, c.Binding, derived, time.Now, check)
	} else {
		m, e = windowsupdatejob.OpenTransactional(ctx, store, c.Binding, derived, time.Now, check)
	}
	if e != nil {
		return nil, e
	}
	for _, other := range forbidden {
		if bytes.Equal(m.ExecutorPublicKey(), other) {
			m.Close()
			return nil, ErrConfiguration
		}
	}
	return m, nil
}

func hasSetupReceipt(c Config) bool {
	return c.SetupReceiptFile != "" || c.SetupPlanDigest != "" || c.SetupRegistrationDigest != ""
}

// Setup-created configs cannot activate from a partial finalization. The exact
// receipt binds the reviewed plan, public registration, and canonical config.
func checkSetupReceipt(c Config) error {
	if !hasSetupReceipt(c) {
		return nil
	}
	if !validConfig(c) {
		return ErrConfiguration
	}
	var receipt setupComplete
	if _, e := canonicalRead(c.SetupReceiptFile, &receipt); e != nil {
		return ErrConfiguration
	}
	raw, _ := json.Marshal(c)
	if receipt.Version != SetupPlanVersion || receipt.PlanDigest != c.SetupPlanDigest || receipt.RegistrationDigest != c.SetupRegistrationDigest || receipt.ConfigurationDigest != actionpermit.Digest(raw) {
		return ErrConfiguration
	}
	return nil
}
