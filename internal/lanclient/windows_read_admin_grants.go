package lanclient

import (
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"os"
)

// Inspection requires the primary irreversible used marker and validates the
// independent generation state. It never calls Mark, Scope, Burst or Collect.
func readWindowsFullServicesGrant(m Material) (windowsfullservices.Consent, bool) {
	zero := windowsfullservices.Consent{}
	if !currentWindowsContextMaterial(m, Load) {
		return zero, false
	}
	primary, e := lanclientstate.AcquireWindowsFullServicesInitialization(m.config.StateDirectory, m.binding)
	if e != nil {
		return zero, false
	}
	defer primary.Close()
	used, e := primary.Used()
	if e != nil || !used {
		return zero, false
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return zero, false
	}
	store, e := windowsstate.Open(windowsFullServicesDirectory(m), windowsFullServicesOptions(sid, false))
	if e != nil {
		return zero, false
	}
	defer store.Close()
	state, e := windowsfullservices.OpenState(store, m.config.AgentID, m.binding)
	if e != nil {
		return zero, false
	}
	defer state.Close()
	raw, e := store.Read("consent.json")
	if e != nil {
		return zero, false
	}
	c, e := windowsfullservices.DecodeConsent(raw)
	if e != nil || c.SenderBinding != m.binding || !c.Enabled || state.Close() != nil || primary.Close() != nil {
		return zero, false
	}
	return c, true
}
func readWindowsFullSoftwareGrant(m Material) (windowsfullsoftware.Consent, bool) {
	zero := windowsfullsoftware.Consent{}
	if !currentWindowsContextMaterial(m, Load) {
		return zero, false
	}
	primary, e := lanclientstate.AcquireWindowsFullSoftwareInitialization(m.config.StateDirectory, m.binding)
	if e != nil {
		return zero, false
	}
	defer primary.Close()
	used, e := primary.Used()
	if e != nil || !used {
		return zero, false
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return zero, false
	}
	store, e := windowsstate.Open(windowsFullSoftwareDirectory(m), windowsFullSoftwareOptions(sid, false))
	if e != nil {
		return zero, false
	}
	defer store.Close()
	state, e := windowsfullsoftware.OpenState(store, m.config.AgentID, m.binding)
	if e != nil {
		return zero, false
	}
	defer state.Close()
	raw, e := store.Read("consent.json")
	if e != nil {
		return zero, false
	}
	c, e := windowsfullsoftware.DecodeConsent(raw)
	if e != nil || c.SenderBinding != m.binding || !c.Enabled || state.Close() != nil || primary.Close() != nil {
		return zero, false
	}
	return c, true
}

// The old four-root absence check remains exact. V5 adds seven independent
// roots; malformed, denied or present state is never adopted by fresh Setup.
func WindowsReadAdminScopesAbsent(root, sid string) error {
	return windowsReadAdminScopesAbsent(root, sid, func(path string, options windowsstate.Options) (capabilityInspectionStore, error) {
		s, e := windowsstate.Open(path, options)
		if e != nil {
			return nil, e
		}
		return s, nil
	})
}
func windowsReadAdminScopesAbsent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	if windowsCapabilityScopesAbsent(root, sid, open) != nil {
		return ErrState
	}
	for _, item := range []struct {
		suffix  string
		options windowsstate.Options
	}{
		{"-service-startup", windowsServiceStartupOptions(sid, false)},
		{"-full-services", windowsFullServicesOptions(sid, false)},
		{"-full-software", windowsFullSoftwareOptions(sid, false)},
		{"-adapter-context", windowsAdapterContextOptions(sid, false)},
		{"-patch-context", windowsPatchContextOptions(sid, false)},
		{"-security-posture", windowsSecurityPostureOptions(sid, false)},
		{"-session-context", windowsSessionContextOptions(sid, false)},
	} {
		s, e := open(root+item.suffix, item.options)
		if s != nil {
			_ = s.Close()
			return ErrState
		}
		if !errors.Is(e, os.ErrNotExist) {
			return ErrState
		}
	}
	return nil
}
