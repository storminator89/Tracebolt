package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowshardware"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"os"
	"path/filepath"
)

// This sibling has its own immutable protected manifest. No name is added to
// the existing enrollment or sender manifest, and no used ledger is migrated.
func windowsHardwareContextConsentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-hardware-context"
}
func windowsHardwareContextOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "hardware-context.lock", TempName: "hardware-context.tmp", MaxBytes: 1024, Create: create}
}
func readWindowsHardwareContextConsent(m Material) (windowshardware.Consent, bool) {
	return readWindowsHardwareContextConsentWithDependencies(m, windowsContextConsentDependencies{Load, openWindowsContextConsent})
}
func readWindowsHardwareContextConsentWithDependencies(m Material, d windowsContextConsentDependencies) (windowshardware.Consent, bool) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowshardware.Consent{}, false
	}
	// Pending retries do not start the native child. Recheck activated identity
	// here too, before reading consent, at every sender authority boundary.
	if !currentWindowsContextMaterial(m, d.reload) {
		return windowshardware.Consent{}, false
	}
	if d.open == nil {
		return windowshardware.Consent{}, false
	}
	s, e := d.open(windowsHardwareContextConsentDirectory(m), windowsHardwareContextOptions("", false))
	if e != nil {
		return windowshardware.Consent{}, false
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowshardware.Consent{}, false
	}
	c, e := windowshardware.DecodeConsent(raw, m.binding)
	if e != nil || s.Close() != nil {
		return windowshardware.Consent{}, false
	}
	return c, c.Enabled
}

type WindowsHardwareContextConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureWindowsHardwareContext is local-only, after the lifecycle command has
// verified the owned service is stopped. The sender's exclusive ledger lock is
// held through the separate consent write; no sequence or identity is reset.
// Future combined installers can reuse this exact explicit-acknowledgement API.
func ConfigureWindowsHardwareContext(path, mode string, acknowledged, insecure bool) (WindowsHardwareContextConsentResult, error) {
	zero := WindowsHardwareContextConsentResult{}
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
	result, e := updateWindowsHardwareContextConsent(m.binding, mode, func(create bool) (hardwareContextConsentStore, error) {
		return windowsstate.Open(windowsHardwareContextConsentDirectory(m), windowsHardwareContextOptions(sid, create))
	})
	if e != nil {
		return zero, e
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}

type hardwareContextConsentStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}

// Creation is explicit and create-only. A missing consent in a previously
// opened manifest is unfinished state, never permission to adopt a grant.
func updateWindowsHardwareContextConsent(binding, mode string, open func(bool) (hardwareContextConsentStore, error)) (WindowsHardwareContextConsentResult, error) {
	zero := WindowsHardwareContextConsentResult{}
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
		return WindowsHardwareContextConsentResult{windowshardware.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowshardware.Consent
	if e == nil {
		c, e = windowshardware.DecodeConsent(raw, binding)
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
		c = windowshardware.Consent{SchemaVersion: windowshardware.ConsentVersion, Scope: windowshardware.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Enabled: true}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowshardware.EncodeConsent(c, binding)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsHardwareContextConsentResult{windowshardware.Scope, c.Enabled, true}, nil
}
