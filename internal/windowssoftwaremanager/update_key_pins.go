package windowssoftwaremanager

import (
	"bytes"
	"encoding/json"
	"path/filepath"

	"localrmm/internal/actionpermit"
	"localrmm/internal/lanconfig"
	"localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatemanager"
)

// Read configured WUA public key identifiers without opening its writable job
// runtime, adopting a domain, or creating state. The snapshot is repeated in
// setup's final configuration fence. Store transactions independently compare
// the immutable markers even for an unconfigured but previously granted domain.
func configuredUpdateKeyIDs(path, manager string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	raw, e := lanconfig.ReadProtected(path, true, maxRegistryBytes)
	if e != nil {
		return nil, ErrSetup
	}
	var head struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return nil, ErrSetup
	}
	files := []string{path}
	if head.Version == windowsupdatemanager.RegistryVersion {
		var registry windowsupdatemanager.RegistryConfig
		if strictManagerObject(raw, &registry) != nil || registry.Version != windowsupdatemanager.RegistryVersion || !registry.Enabled || registry.ManagerID != manager || len(registry.ConfigFiles) == 0 || len(registry.ConfigFiles) > windowsupdatejob.MaxDevices {
			return nil, ErrSetup
		}
		canonical, _ := json.Marshal(registry)
		if !bytes.Equal(raw, canonical) {
			return nil, ErrSetup
		}
		files = registry.ConfigFiles
	} else if head.Version != windowsupdatemanager.ConfigVersion {
		return nil, ErrSetup
	}
	seen := map[string]bool{}
	ids := []string{}
	for _, file := range files {
		if !filepath.IsAbs(file) || filepath.Clean(file) != file || seen[file] {
			return nil, ErrSetup
		}
		seen[file] = true
		body, e := lanconfig.ReadProtected(file, true, 8192)
		if e != nil {
			return nil, ErrSetup
		}
		var c windowsupdatemanager.Config
		if strictManagerObject(body, &c) != nil || c.Version != windowsupdatemanager.ConfigVersion || !c.Enabled || !windowsupdatejob.ValidBinding(c.Binding) || c.Binding.ManagerID != manager || !filepath.IsAbs(c.PrivateKeyFile) || filepath.Clean(c.PrivateKeyFile) != c.PrivateKeyFile {
			return nil, ErrSetup
		}
		key, e := publicFromPrivate(c.PrivateKeyFile)
		if e != nil || actionpermit.Digest(key) != c.Binding.KeyID {
			return nil, ErrSetup
		}
		if c.SetupReceiptFile != "" || c.SetupPlanDigest != "" || c.SetupRegistrationDigest != "" {
			if !filepath.IsAbs(c.SetupReceiptFile) || filepath.Clean(c.SetupReceiptFile) != c.SetupReceiptFile || !actionpermit.ValidDigest(c.SetupPlanDigest) || !actionpermit.ValidDigest(c.SetupRegistrationDigest) {
				return nil, ErrSetup
			}
			var receipt setupComplete
			if _, e = canonicalRead(c.SetupReceiptFile, &receipt); e != nil || receipt.Version != windowsupdatemanager.SetupPlanVersion || receipt.PlanDigest != c.SetupPlanDigest || receipt.RegistrationDigest != c.SetupRegistrationDigest {
				return nil, ErrSetup
			}
			canonical, _ := json.Marshal(c)
			if !bytes.Equal(body, canonical) || receipt.ConfigurationDigest != actionpermit.Digest(canonical) {
				return nil, ErrSetup
			}
		}
		ids = append(ids, c.Binding.KeyID, c.Binding.ExecutorKeyID)
	}
	again, e := lanconfig.ReadProtected(path, true, maxRegistryBytes)
	if e != nil || !bytes.Equal(raw, again) {
		return nil, ErrSetup
	}
	return ids, nil
}
func distinctFromPlan(pub []byte, p SetupPlan) bool {
	digest := actionpermit.Digest(pub)
	for _, other := range p.OtherPurposeKeyIDs {
		if !actionpermit.ValidDigest(other) || digest == other {
			return false
		}
	}
	return true
}
