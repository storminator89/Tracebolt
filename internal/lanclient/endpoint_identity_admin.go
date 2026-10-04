package lanclient

import (
	"localrmm/internal/endpointidentity"
	"localrmm/internal/lanclientstate"
)

// EndpointConsentResult contains public scope/status only, never actual host
// metadata or credentials. Previewing is not an acknowledgement or write.
type EndpointConsentResult struct {
	SchemaVersion          string `json:"schemaVersion"`
	Mode                   string `json:"mode"`
	ExtensionVersion       string `json:"extensionVersion"`
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureEndpointIdentity is local-only and must run as the dedicated state
// owner after the CLI verifies the explicit numeric UID:GID. The ready marker
// and all existing v3 ledgers are checked; none is initialized or reset. Holding
// the existing metrics ownership domain refuses an active foreground sender.
func ConfigureEndpointIdentity(path, mode string, acknowledged bool) (EndpointConsentResult, error) {
	zero := EndpointConsentResult{}
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
		c := endpointidentity.LocalConsent{SchemaVersion: endpointidentity.ConsentVersion, ExtensionVersion: endpointidentity.SchemaVersion, Scope: endpointidentity.Scope, SenderBinding: m.binding, Acknowledged: true}
		raw, e := endpointidentity.EncodeLocalConsent(c, m.binding)
		if e != nil {
			return zero, ErrConfiguration
		}
		if e = writeEndpointConsent(m, raw); e != nil {
			return zero, e
		}
	} else if mode == "disable" {
		if e = removeEndpointConsent(m); e != nil {
			return zero, e
		}
	}
	_, enabled := readEndpointConsent(m)
	if mode == "enable" && !enabled || mode == "disable" && enabled {
		return zero, ErrState
	}
	if lease.Close() != nil {
		return zero, ErrState
	}
	return EndpointConsentResult{SchemaVersion: "tracebolt.endpoint-identity-consent-result.v1", Mode: mode, ExtensionVersion: endpointidentity.SchemaVersion, Scope: endpointidentity.Scope, Enabled: enabled, ExistingStatePreserved: true}, nil
}
