package lanclient

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/inventorystate"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanconfig"
	"os"
	"path/filepath"
)

const (
	completeUpdatesConsentName     = "complete-cached-updates-consent.json"
	completeUpdatesInitName        = ".complete-cached-updates-initialization"
	maxCompleteUpdatesConsentBytes = cachedupdates.MaxConsentBytes
	completeUpdatesDisclosure      = "All known newer cached APT candidate rows: package names, architectures, installed and candidate versions, dpkg holds, checked and unknown counts, and original local package-index modification age; fixed six-hour capture cadence. Existing agent permissions only. No repository URLs, refresh, installation, CVE classification or dependency, phasing or installability guarantees. Unknown comparisons remain unknown. Index modification time cannot prove repository freshness. HTTP-test content is unencrypted and the manager is unauthenticated."
)

func completeUpdatesStateDirectory(c Config) string {
	return filepath.Join(c.StateDirectory, "cached-updates")
}
func completeUpdatesStateBinding(m Material) string {
	sum := sha256.Sum256([]byte("tracebolt.cached-updates-spool-binding.v1\x00" + m.binding + "\x00" + cachedupdates.CompleteSchemaVersion + "\x00" + cachedupdates.CompleteScope))
	return hex.EncodeToString(sum[:])
}
func completeUpdatesConsentFor(m Material) cachedupdates.CompleteLocalConsent {
	return cachedupdates.CompleteLocalConsent{SchemaVersion: cachedupdates.CompleteConsentVersion, ExtensionVersion: cachedupdates.CompleteSchemaVersion, Scope: cachedupdates.CompleteScope, SenderBinding: m.binding, Acknowledged: true}
}
func readCompleteUpdatesConsent(m Material) (cachedupdates.CompleteLocalConsent, bool) {
	if !m.valid() || !m.config.complete() || completeUpdatesInitializationState(m) != nil {
		return cachedupdates.CompleteLocalConsent{}, false
	}
	raw, e := lanconfig.ReadProtected(filepath.Join(m.config.StateDirectory, completeUpdatesConsentName), true, maxCompleteUpdatesConsentBytes)
	if e != nil {
		return cachedupdates.CompleteLocalConsent{}, false
	}
	c, e := cachedupdates.DecodeCompleteLocalConsent(raw, m.binding)
	return c, e == nil
}

type CompleteUpdatesConsentResult struct {
	SchemaVersion          string `json:"schemaVersion"`
	Mode                   string `json:"mode"`
	ExtensionVersion       string `json:"extensionVersion"`
	Scope                  string `json:"scope"`
	Disclosure             string `json:"disclosure"`
	CaptureIntervalSeconds uint32 `json:"captureIntervalSeconds"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureCompleteCachedUpdates is a separately acknowledged, stopped-service
// local extension. It never promotes preview consent, resets existing floors,
// collects, installs, grants privileges or contacts the manager.
func ConfigureCompleteCachedUpdates(path, mode string, acknowledged bool) (CompleteUpdatesConsentResult, error) {
	return configureCompleteCachedUpdates(path, mode, acknowledged, journalAgentIdentity)
}
func configureCompleteCachedUpdates(path, mode string, acknowledged bool, identity func() (uint32, uint32, bool)) (CompleteUpdatesConsentResult, error) {
	var zero CompleteUpdatesConsentResult
	if mode != "preview" && mode != "enable" && mode != "disable" || acknowledged != (mode == "enable") || identity == nil {
		return zero, ErrConfiguration
	}
	if _, _, ok := identity(); !ok {
		return zero, ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return zero, ErrState
	}
	m, e := Load(path)
	if e != nil || !m.config.complete() {
		return zero, ErrConfiguration
	}
	lease, e := lanclientstate.AcquireInspection(m.config.StateDirectory, m.binding)
	if e != nil {
		return zero, ErrState
	}
	defer lease.Close()
	if mode == "enable" {
		if completeUpdatesInitializationState(m) != nil {
			return zero, ErrState
		}
		raw, e := cachedupdates.EncodeCompleteLocalConsent(completeUpdatesConsentFor(m), m.binding)
		if e != nil {
			return zero, ErrConfiguration
		}
		existed := false
		if _, e := os.Lstat(filepath.Join(m.config.StateDirectory, completeUpdatesConsentName)); e == nil {
			existed = true
			if _, ok := readCompleteUpdatesConsent(m); !ok {
				return zero, ErrState
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return zero, ErrState
		}
		_, e = os.Lstat(completeUpdatesStateDirectory(m.config))
		if errors.Is(e, os.ErrNotExist) {
			if existed {
				return zero, ErrState
			}
			if beginCompleteUpdatesInitialization(m) != nil {
				return zero, ErrState
			}
			state, e := inventorystate.InitializeCachedUpdatesNew(completeUpdatesStateDirectory(m.config), completeUpdatesStateBinding(m), m.config.AgentID)
			if e != nil {
				return zero, ErrState
			}
			if state.Close() != nil {
				return zero, ErrState
			}
			if writeCompleteUpdatesConsent(m, raw) != nil || finishCompleteUpdatesInitialization(m) != nil {
				return zero, ErrState
			}
		} else {
			if e != nil || inventorystate.ValidateCachedUpdatesExisting(completeUpdatesStateDirectory(m.config), completeUpdatesStateBinding(m), m.config.AgentID) != nil {
				return zero, ErrState
			}
			if writeCompleteUpdatesConsent(m, raw) != nil {
				return zero, ErrState
			}
		}
	} else if mode == "disable" {
		// Exact pending bytes and consumed floors remain dormant until a fresh grant.
		if removeCompleteUpdatesConsent(m) != nil {
			return zero, ErrState
		}
	}
	_, enabled := readCompleteUpdatesConsent(m)
	if mode == "enable" && !enabled || mode == "disable" && enabled {
		return zero, ErrState
	}
	if lease.Close() != nil {
		return zero, ErrState
	}
	return CompleteUpdatesConsentResult{"tracebolt.complete-cached-updates-consent-result.v1", mode, cachedupdates.CompleteSchemaVersion, cachedupdates.CompleteScope, completeUpdatesDisclosure, uint32(inventoryCaptureInterval.Seconds()), enabled, true}, nil
}
