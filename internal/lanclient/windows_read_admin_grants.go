package lanclient

import (
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsfullprocesses"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsfullsoftware"
	"localrmm/internal/windowsnetworkcontext"
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

// WindowsReadAdminScopesV6Absent retains the exact V5 absence checks and adds
// the independently protected hardware root. Existing state is never adopted.
func WindowsReadAdminScopesV6Absent(root, sid string) error {
	return windowsReadAdminScopesV6Absent(root, sid, func(path string, options windowsstate.Options) (capabilityInspectionStore, error) {
		s, e := windowsstate.Open(path, options)
		if e != nil {
			return nil, e
		}
		return s, nil
	})
}
func windowsReadAdminScopesV6Absent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	if windowsReadAdminScopesAbsent(root, sid, open) != nil {
		return ErrState
	}
	s, e := open(root+"-hardware-context", windowsHardwareContextOptions(sid, false))
	if s != nil {
		_ = s.Close()
		return ErrState
	}
	if !errors.Is(e, os.ErrNotExist) {
		return ErrState
	}
	return nil
}

func WindowsReadAdminScopesV7Absent(root, sid string) error {
	return windowsReadAdminScopesV7Absent(root, sid, func(path string, options windowsstate.Options) (capabilityInspectionStore, error) {
		s, e := windowsstate.Open(path, options)
		if e != nil {
			return nil, e
		}
		return s, nil
	})
}
func windowsReadAdminScopesV7Absent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	if windowsReadAdminScopesV6Absent(root, sid, open) != nil {
		return ErrState
	}
	s, e := open(root+"-storage-context", windowsStorageContextOptions(sid, false))
	if s != nil {
		_ = s.Close()
		return ErrState
	}
	if !errors.Is(e, os.ErrNotExist) {
		return ErrState
	}
	return nil
}

func WindowsReadAdminScopesV8Absent(root, sid string) error {
	return windowsReadAdminScopesV8Absent(root, sid, func(path string, options windowsstate.Options) (capabilityInspectionStore, error) {
		s, e := windowsstate.Open(path, options)
		if e != nil {
			return nil, e
		}
		return s, nil
	})
}
func windowsReadAdminScopesV8Absent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	if windowsReadAdminScopesV7Absent(root, sid, open) != nil {
		return ErrState
	}
	s, e := open(root+"-security-coverage", windowsSecurityCoverageOptions(sid, false))
	if s != nil {
		_ = s.Close()
		return ErrState
	}
	if !errors.Is(e, os.ErrNotExist) {
		return ErrState
	}
	return nil
}

func readWindowsFullProcessesGrant(m Material) (windowsfullprocesses.Consent, bool) {
	zero := windowsfullprocesses.Consent{}
	if !currentWindowsContextMaterial(m, Load) {
		return zero, false
	}
	primary, e := lanclientstate.AcquireWindowsFullProcessesInitialization(m.config.StateDirectory, m.binding)
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
	store, e := windowsstate.Open(windowsFullProcessesDirectory(m), windowsFullProcessesOptions(sid, false))
	if e != nil {
		return zero, false
	}
	defer store.Close()
	state, e := windowsfullprocesses.OpenState(store, m.config.AgentID, m.binding)
	if e != nil {
		return zero, false
	}
	defer state.Close()
	raw, e := store.Read("consent.json")
	if e != nil {
		return zero, false
	}
	c, e := windowsfullprocesses.DecodeConsent(raw)
	if e != nil || c.SenderBinding != m.binding || !c.Enabled || state.Close() != nil || primary.Close() != nil {
		return zero, false
	}
	return c, true
}

func WindowsReadAdminScopesV9Absent(root, sid string) error {
	return windowsReadAdminScopesV9Absent(root, sid, func(path string, options windowsstate.Options) (capabilityInspectionStore, error) {
		s, e := windowsstate.Open(path, options)
		if e != nil {
			return nil, e
		}
		return s, nil
	})
}
func windowsReadAdminScopesV9Absent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	if windowsReadAdminScopesV8Absent(root, sid, open) != nil {
		return ErrState
	}
	s, e := open(root+"-full-processes", windowsFullProcessesOptions(sid, false))
	if s != nil {
		_ = s.Close()
		return ErrState
	}
	if !errors.Is(e, os.ErrNotExist) {
		return ErrState
	}
	return nil
}

func readWindowsNetworkContextGrant(m Material) (windowsnetworkcontext.Consent, bool) {
	zero := windowsnetworkcontext.Consent{}
	if !currentWindowsContextMaterial(m, Load) {
		return zero, false
	}
	primary, e := lanclientstate.AcquireWindowsNetworkContextInitialization(m.config.StateDirectory, m.binding)
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
	store, e := windowsstate.Open(windowsNetworkContextDirectory(m), windowsNetworkContextOptions(sid, false))
	if e != nil {
		return zero, false
	}
	defer store.Close()
	state, e := windowsnetworkcontext.OpenState(store, m.config.AgentID, m.binding)
	if e != nil {
		return zero, false
	}
	defer state.Close()
	raw, e := store.Read("consent.json")
	if e != nil {
		return zero, false
	}
	c, e := windowsnetworkcontext.DecodeConsent(raw)
	if e != nil || c.SenderBinding != m.binding || !c.Enabled || state.Close() != nil || primary.Close() != nil {
		return zero, false
	}
	return c, true
}

func WindowsReadAdminScopesV10Absent(root, sid string) error {
	return windowsReadAdminScopesV10Absent(root, sid, func(path string, options windowsstate.Options) (capabilityInspectionStore, error) {
		s, e := windowsstate.Open(path, options)
		if e != nil {
			return nil, e
		}
		return s, nil
	})
}
func windowsReadAdminScopesV10Absent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	if windowsReadAdminScopesV9Absent(root, sid, open) != nil {
		return ErrState
	}
	s, e := open(root+"-network-context", windowsNetworkContextOptions(sid, false))
	if s != nil {
		_ = s.Close()
		return ErrState
	}
	if !errors.Is(e, os.ErrNotExist) {
		return ErrState
	}
	return nil
}

func WindowsReadAdminScopesV11Absent(root, sid string) error {
	return windowsReadAdminScopesV11Absent(root, sid, func(path string, options windowsstate.Options) (capabilityInspectionStore, error) {
		s, e := windowsstate.Open(path, options)
		if e != nil {
			return nil, e
		}
		return s, nil
	})
}
func windowsReadAdminScopesV11Absent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	if windowsReadAdminScopesV10Absent(root, sid, open) != nil {
		return ErrState
	}
	s, e := open(root+"-resource-context", windowsResourceContextOptions(sid, false))
	if s != nil {
		_ = s.Close()
		return ErrState
	}
	if !errors.Is(e, os.ErrNotExist) {
		return ErrState
	}
	return nil
}

func WindowsReadAdminScopesV12Absent(root, sid string) error {
	return windowsReadAdminScopesV12Absent(root, sid, func(path string, options windowsstate.Options) (capabilityInspectionStore, error) {
		s, e := windowsstate.Open(path, options)
		if e != nil {
			return nil, e
		}
		return s, nil
	})
}
func windowsReadAdminScopesV12Absent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	if windowsReadAdminScopesV11Absent(root, sid, open) != nil {
		return ErrState
	}
	s, e := open(root+"-storage-io", windowsStorageIOOptions(sid, false))
	if s != nil {
		_ = s.Close()
		return ErrState
	}
	if !errors.Is(e, os.ErrNotExist) {
		return ErrState
	}
	return nil
}

// History uses the same protected software root and irreversible used marker.
// Checking the V12 roots also excludes any existing history-bearing software grant.
func WindowsReadAdminScopesV13Absent(root, sid string) error {
	return WindowsReadAdminScopesV12Absent(root, sid)
}
func windowsReadAdminScopesV13Absent(root, sid string, open func(string, windowsstate.Options) (capabilityInspectionStore, error)) error {
	return windowsReadAdminScopesV12Absent(root, sid, open)
}
