package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowssessions"
	"localrmm/internal/windowsstate"
	"os"
	"path/filepath"
)

// This sibling has its own immutable protected manifest. No name is added to
// the existing enrollment or sender manifest, and no used ledger is migrated.
func windowsSessionContextConsentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-session-context"
}
func windowsSessionContextOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "session-context.lock", TempName: "session-context.tmp", MaxBytes: 1024, Create: create}
}
func readWindowsSessionContextConsent(m Material) (windowssessions.Consent, bool) {
	return readWindowsSessionContextConsentWithDependencies(m, windowsContextConsentDependencies{Load, openWindowsContextConsent})
}
func readWindowsSessionContextConsentWithDependencies(m Material, d windowsContextConsentDependencies) (windowssessions.Consent, bool) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowssessions.Consent{}, false
	}
	// Pending retries do not start the native child. Recheck activated identity
	// here too, before reading consent, at every sender authority boundary.
	if !currentWindowsContextMaterial(m, d.reload) {
		return windowssessions.Consent{}, false
	}
	if d.open == nil {
		return windowssessions.Consent{}, false
	}
	s, e := d.open(windowsSessionContextConsentDirectory(m), windowsSessionContextOptions("", false))
	if e != nil {
		return windowssessions.Consent{}, false
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowssessions.Consent{}, false
	}
	c, e := windowssessions.DecodeConsent(raw, m.binding)
	if e != nil || s.Close() != nil {
		return windowssessions.Consent{}, false
	}
	return c, c.Enabled
}

type WindowsSessionContextConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureWindowsSessionContext is local-only, after the lifecycle command has
// verified the owned service is stopped. The sender's exclusive ledger lock is
// held through the separate consent write; no sequence or identity is reset.
// Future combined installers can reuse this exact explicit-acknowledgement API.
func ConfigureWindowsSessionContext(path, mode string, acknowledged, insecure bool) (WindowsSessionContextConsentResult, error) {
	zero := WindowsSessionContextConsentResult{}
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
	result, e := updateWindowsSessionContextConsent(m.binding, mode, func(create bool) (sessionContextConsentStore, error) {
		return windowsstate.Open(windowsSessionContextConsentDirectory(m), windowsSessionContextOptions(sid, create))
	})
	if e != nil {
		return zero, e
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}

type sessionContextConsentStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}

// Creation is explicit and create-only. A missing consent in a previously
// opened manifest is unfinished state, never permission to adopt a grant.
func updateWindowsSessionContextConsent(binding, mode string, open func(bool) (sessionContextConsentStore, error)) (WindowsSessionContextConsentResult, error) {
	zero := WindowsSessionContextConsentResult{}
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
		return WindowsSessionContextConsentResult{windowssessions.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowssessions.Consent
	if e == nil {
		c, e = windowssessions.DecodeConsent(raw, binding)
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
		c = windowssessions.Consent{SchemaVersion: windowssessions.ConsentVersion, Scope: windowssessions.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Enabled: true}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowssessions.EncodeConsent(c, binding)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsSessionContextConsentResult{windowssessions.Scope, c.Enabled, true}, nil
}
