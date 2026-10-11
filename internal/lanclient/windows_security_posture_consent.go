package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowssecurity"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"os"
	"path/filepath"
)

// This sibling has its own immutable protected manifest. No name is added to
// the existing enrollment or sender manifest, and no used ledger is migrated.
func windowsSecurityPostureConsentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-security-posture"
}
func windowsSecurityPostureOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "security-posture.lock", TempName: "security-posture.tmp", MaxBytes: 1024, Create: create}
}
func readWindowsSecurityPostureConsent(m Material) (windowssecurity.Consent, bool) {
	return readWindowsSecurityPostureConsentWithDependencies(m, windowsContextConsentDependencies{Load, openWindowsContextConsent})
}
func readWindowsSecurityPostureConsentWithDependencies(m Material, d windowsContextConsentDependencies) (windowssecurity.Consent, bool) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowssecurity.Consent{}, false
	}
	// Pending retries do not start the native child. Recheck activated identity
	// here too, before reading consent, at every sender authority boundary.
	if !currentWindowsContextMaterial(m, d.reload) {
		return windowssecurity.Consent{}, false
	}
	if d.open == nil {
		return windowssecurity.Consent{}, false
	}
	s, e := d.open(windowsSecurityPostureConsentDirectory(m), windowsSecurityPostureOptions("", false))
	if e != nil {
		return windowssecurity.Consent{}, false
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowssecurity.Consent{}, false
	}
	c, e := windowssecurity.DecodeConsent(raw, m.binding)
	if e != nil || s.Close() != nil {
		return windowssecurity.Consent{}, false
	}
	return c, c.Enabled
}

type WindowsSecurityPostureConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureWindowsSecurityPosture is local-only, after the lifecycle command has
// verified the owned service is stopped. The sender's exclusive ledger lock is
// held through the separate consent write; no sequence or identity is reset.
// Future combined installers can reuse this exact explicit-acknowledgement API.
func ConfigureWindowsSecurityPosture(path, mode string, acknowledged, insecure bool) (WindowsSecurityPostureConsentResult, error) {
	zero := WindowsSecurityPostureConsentResult{}
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
	result, e := updateWindowsSecurityPostureConsent(m.binding, mode, func(create bool) (securityPostureConsentStore, error) {
		return windowsstate.Open(windowsSecurityPostureConsentDirectory(m), windowsSecurityPostureOptions(sid, create))
	})
	if e != nil {
		return zero, e
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}

type securityPostureConsentStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}

// Creation is explicit and create-only. A missing consent in a previously
// opened manifest is unfinished state, never permission to adopt a grant.
func updateWindowsSecurityPostureConsent(binding, mode string, open func(bool) (securityPostureConsentStore, error)) (WindowsSecurityPostureConsentResult, error) {
	zero := WindowsSecurityPostureConsentResult{}
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
		return WindowsSecurityPostureConsentResult{windowssecurity.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowssecurity.Consent
	if e == nil {
		c, e = windowssecurity.DecodeConsent(raw, binding)
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
		c = windowssecurity.Consent{SchemaVersion: windowssecurity.ConsentVersion, Scope: windowssecurity.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Enabled: true}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowssecurity.EncodeConsent(c, binding)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsSecurityPostureConsentResult{windowssecurity.Scope, c.Enabled, true}, nil
}
