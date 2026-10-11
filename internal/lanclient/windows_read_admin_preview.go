package lanclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"localrmm/internal/windowsadapters"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsvolumes"
)

// WindowsReadAdminScopeError exposes only an exact selected scope, never paths or native error prose.
type WindowsReadAdminScopeError struct{ Scope string }

func (*WindowsReadAdminScopeError) Error() string {
	return "windows_read_admin_existing_scope_unavailable"
}

type WindowsReadAdminScopeState struct {
	Scope   string `json:"scope"`
	Enabled bool   `json:"enabled"`
	// Empty for disabled/absent; enabled original grants must retain exact bytes.
	SHA256 string `json:"sha256,omitempty"`
}

// Preview validates every existing selected grant, including missing-used-state
// fences, before any new grant or receipt may be created. No provider is queried.
func PreviewWindowsReadAdmin(path string, c WindowsCapabilityConsent, guard func() error) ([]WindowsReadAdminScopeState, error) {
	if !validWindowsReadAdminConsent(c) || guard == nil {
		return nil, ErrConfiguration
	}
	binding, e := WindowsCapabilityIdentity(path, c)
	if e != nil {
		return nil, e
	}
	states := []WindowsReadAdminScopeState{}
	for _, scope := range c.Scopes[1:] {
		if guard() != nil {
			return nil, ErrState
		}
		current, e := WindowsCapabilityIdentity(path, c)
		if e != nil || current != binding {
			return nil, ErrState
		}
		enabled, e := previewWindowsReadAdminScope(path, scope, c.InsecureHTTPAcknowledged)
		if e != nil {
			return nil, &WindowsReadAdminScopeError{Scope: scope}
		}
		s := WindowsReadAdminScopeState{Scope: scope, Enabled: enabled}
		if enabled {
			m, e := Load(path)
			if e != nil || m.binding != binding {
				return nil, ErrState
			}
			s.SHA256, e = windowsReadAdminGrantDigest(m, scope)
			if e != nil {
				return nil, &WindowsReadAdminScopeError{Scope: scope}
			}
		}
		if guard() != nil {
			return nil, ErrState
		}
		states = append(states, s)
	}
	return states, nil
}

func windowsReadAdminGrantDigest(m Material, scope string) (string, error) {
	c, ok := readWindowsCapabilityConsent(m, scope)
	if !ok || c == nil {
		return "", ErrState
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return "", ErrState
	}
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:]), nil
}

func VerifyWindowsReadAdminPreservedGrants(path string, c WindowsCapabilityConsent, states []WindowsReadAdminScopeState) error {
	if !validWindowsReadAdminConsent(c) || len(states) != len(c.Scopes)-1 {
		return ErrConfiguration
	}
	binding, e := WindowsCapabilityIdentity(path, c)
	if e != nil {
		return e
	}
	m, e := Load(path)
	if e != nil || m.binding != binding {
		return ErrState
	}
	for i, state := range states {
		if state.Scope != c.Scopes[i+1] {
			return ErrConfiguration
		}
		if !state.Enabled {
			if state.SHA256 != "" {
				return ErrState
			}
			continue
		}
		d, e := windowsReadAdminGrantDigest(m, state.Scope)
		if e != nil || d != state.SHA256 {
			return ErrState
		}
	}
	return nil
}

func previewWindowsReadAdminScope(path, scope string, insecure bool) (bool, error) {
	switch scope {
	case windowseventhealth.Scope:
		r, e := ConfigureWindowsEventMetadata(path, "preview", false, insecure)
		return r.Enabled, e
	case windowsvolumes.Scope:
		r, e := ConfigureWindowsVolumes(path, "preview", false, insecure)
		return r.Enabled, e
	case windowsprocessmetrics.Scope:
		r, e := ConfigureWindowsProcessMetrics(path, "preview", false, insecure)
		return r.Enabled, e
	case windowsnetwork.Scope:
		r, e := ConfigureWindowsNetwork(path, "preview", false, insecure)
		return r.Enabled, e
	case windowsmanaged.ServiceStartupScope:
		r, e := ConfigureWindowsServiceStartup(path, "preview", false, insecure)
		return r.Enabled, e
	case windowsfullservices.Scope:
		r, e := ConfigureWindowsFullServices(path, "preview", false, insecure)
		return r.Enabled, e
	case windowsfullprocesses.Scope:
		r, e := ConfigureWindowsFullProcesses(path, "preview", false, insecure)
		return r.Enabled, e
	case windowsfullsoftware.Scope:
		r, e := ConfigureWindowsFullSoftware(path, "preview", false, insecure)
		return r.Enabled, e
	case windowsadapters.Scope:
		r, e := ConfigureWindowsAdapterContext(path, "preview", false, insecure)
		return r.Enabled, e
	case windowspatchcontext.Scope:
		r, e := ConfigureWindowsPatchContext(path, "preview", false, insecure)
		return r.Enabled, e
	case windowssecurity.Scope:
		r, e := ConfigureWindowsSecurityPosture(path, "preview", false, insecure)
		return r.Enabled, e
	case windowssessions.Scope:
		r, e := ConfigureWindowsSessionContext(path, "preview", false, insecure)
		return r.Enabled, e
	}
	return false, ErrConfiguration
}
