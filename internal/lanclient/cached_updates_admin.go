package lanclient

import (
	"localrmm/internal/cachedupdates"
	"localrmm/internal/lanclientstate"
)

const cachedUpdatesDisclosure = "Read-only installed package names, architectures and versions; newer native APT candidate versions, dpkg holds, bounded candidate sample and counts, and local package-index modification age. Existing agent permissions only. No repository URLs, refresh, installation, CVE classification or dependency, phasing or installability guarantees. Index modification time cannot prove repository freshness. HTTP-test content is unencrypted and the manager is unauthenticated."

// CachedUpdatesConsentResult contains public scope/status only, never actual update
// metadata or credentials. Previewing is not an acknowledgement or write.
type CachedUpdatesConsentResult struct {
	SchemaVersion          string `json:"schemaVersion"`
	Mode                   string `json:"mode"`
	ExtensionVersion       string `json:"extensionVersion"`
	Scope                  string `json:"scope"`
	Disclosure             string `json:"disclosure"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureCachedUpdates is local-only and must run as the dedicated state
// owner after the CLI verifies the explicit numeric UID:GID. The ready marker
// and all existing v3 ledgers are checked; none is initialized or reset. Holding
// the existing metrics ownership domain refuses an active foreground sender.
func ConfigureCachedUpdates(path, mode string, acknowledged bool) (CachedUpdatesConsentResult, error) {
	zero := CachedUpdatesConsentResult{}
	if mode != "preview" && mode != "enable" && mode != "disable" || acknowledged != (mode == "enable") {
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
		c := cachedupdates.LocalConsent{SchemaVersion: cachedupdates.ConsentVersion, ExtensionVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, SenderBinding: m.binding, Acknowledged: true}
		raw, e := cachedupdates.EncodeLocalConsent(c, m.binding)
		if e != nil {
			return zero, ErrConfiguration
		}
		if e = writeCachedUpdatesConsent(m, raw); e != nil {
			return zero, e
		}
	} else if mode == "disable" {
		if e = removeCachedUpdatesConsent(m); e != nil {
			return zero, e
		}
	}
	_, enabled := readCachedUpdatesConsent(m)
	if mode == "enable" && !enabled || mode == "disable" && enabled {
		return zero, ErrState
	}
	if lease.Close() != nil {
		return zero, ErrState
	}
	return CachedUpdatesConsentResult{SchemaVersion: "tracebolt.cached-updates-consent-result.v1", Mode: mode, ExtensionVersion: cachedupdates.SchemaVersion, Scope: cachedupdates.Scope, Disclosure: cachedUpdatesDisclosure, Enabled: enabled, ExistingStatePreserved: true}, nil
}
