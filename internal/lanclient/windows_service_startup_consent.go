package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"os"
	"path/filepath"
)

// This sibling has its own immutable protected manifest. No name is added to
// the existing enrollment or sender manifest, and no used ledger is migrated.
func windowsServiceStartupConsentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-service-startup"
}
func windowsServiceStartupOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "service-startup.lock", TempName: "service-startup.tmp", MaxBytes: 1024, Create: create}
}
func readWindowsServiceStartupConsent(m Material) (windowsmanaged.ServiceStartupConsent, bool) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowsmanaged.ServiceStartupConsent{}, false
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return windowsmanaged.ServiceStartupConsent{}, false
	}
	s, e := windowsstate.Open(windowsServiceStartupConsentDirectory(m), windowsServiceStartupOptions(sid, false))
	if e != nil {
		return windowsmanaged.ServiceStartupConsent{}, false
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowsmanaged.ServiceStartupConsent{}, false
	}
	c, e := windowsmanaged.DecodeServiceStartupConsent(raw, m.binding)
	if e != nil || s.Close() != nil {
		return windowsmanaged.ServiceStartupConsent{}, false
	}
	return c, c.Enabled
}

type WindowsServiceStartupConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureWindowsServiceStartup is local-only, after the lifecycle command has
// verified the owned service is stopped. The sender's exclusive ledger lock is
// held through the separate consent write; no sequence or identity is reset.
// Future combined installers can reuse this exact explicit-acknowledgement API.
func ConfigureWindowsServiceStartup(path, mode string, acknowledged, insecure bool) (WindowsServiceStartupConsentResult, error) {
	zero := WindowsServiceStartupConsentResult{}
	if mode != "preview" && mode != "enable" && mode != "disable" || acknowledged != (mode == "enable") {
		return zero, ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return zero, ErrState
	}
	m, e := Load(path)
	if e != nil || !m.config.windowsInventory() || insecure != (m.config.Profile == "http-test") {
		return zero, ErrConfiguration
	}
	state, e := lanclientstate.AcquireInspection(m.config.StateDirectory, m.binding)
	if e != nil {
		return zero, ErrState
	}
	defer state.Close()
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return zero, ErrState
	}
	result, e := updateWindowsServiceStartupConsent(m.binding, mode, func(create bool) (serviceStartupConsentStore, error) {
		return windowsstate.Open(windowsServiceStartupConsentDirectory(m), windowsServiceStartupOptions(sid, create))
	})
	if e != nil {
		return zero, e
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}

type serviceStartupConsentStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}

// Creation is explicit and create-only. A missing consent in a previously
// opened manifest is unfinished state, never permission to adopt a grant.
func updateWindowsServiceStartupConsent(binding, mode string, open func(bool) (serviceStartupConsentStore, error)) (WindowsServiceStartupConsentResult, error) {
	zero := WindowsServiceStartupConsentResult{}
	if open == nil || mode != "preview" && mode != "enable" && mode != "disable" {
		return zero, ErrConfiguration
	}
	s, e := open(false)
	fresh := false
	if errors.Is(e, os.ErrNotExist) && mode == "enable" {
		s, e = open(true)
		fresh = e == nil
	}
	if errors.Is(e, os.ErrNotExist) && mode != "enable" {
		return WindowsServiceStartupConsentResult{windowsmanaged.ServiceStartupScope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowsmanaged.ServiceStartupConsent
	if e == nil {
		c, e = windowsmanaged.DecodeServiceStartupConsent(raw, binding)
	} else if errors.Is(e, os.ErrNotExist) && fresh {
		e = nil
	}
	if e != nil {
		return zero, ErrState
	}
	if mode == "enable" && !c.Enabled {
		var id [16]byte
		if _, e = rand.Read(id[:]); e != nil {
			return zero, ErrState
		}
		c = windowsmanaged.ServiceStartupConsent{SchemaVersion: windowsmanaged.ServiceStartupConsentVersion, Scope: windowsmanaged.ServiceStartupScope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Enabled: true}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowsmanaged.EncodeServiceStartupConsent(c, binding)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsServiceStartupConsentResult{windowsmanaged.ServiceStartupScope, c.Enabled, true}, nil
}
