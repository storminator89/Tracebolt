package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsresourcecontext"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"os"
	"path/filepath"
)

// This sibling has its own immutable protected manifest. No name is added to
// the existing enrollment or sender manifest, and no used ledger is migrated.
func windowsResourceContextConsentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-resource-context"
}
func windowsResourceContextOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "resource-context.lock", TempName: "resource-context.tmp", MaxBytes: 1024, Create: create}
}
func readWindowsResourceContextConsent(m Material) (windowsresourcecontext.Consent, bool) {
	return readWindowsResourceContextConsentWithDependencies(m, windowsContextConsentDependencies{Load, openWindowsContextConsent})
}
func readWindowsResourceContextConsentWithDependencies(m Material, d windowsContextConsentDependencies) (windowsresourcecontext.Consent, bool) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowsresourcecontext.Consent{}, false
	}
	// Pending retries do not start the native child. Recheck activated identity
	// here too, before reading consent, at every sender authority boundary.
	if !currentWindowsContextMaterial(m, d.reload) {
		return windowsresourcecontext.Consent{}, false
	}
	if d.open == nil {
		return windowsresourcecontext.Consent{}, false
	}
	s, e := d.open(windowsResourceContextConsentDirectory(m), windowsResourceContextOptions("", false))
	if e != nil || s == nil {
		return windowsresourcecontext.Consent{}, false
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowsresourcecontext.Consent{}, false
	}
	c, e := windowsresourcecontext.DecodeConsent(raw, m.binding)
	if e != nil || s.Close() != nil {
		return windowsresourcecontext.Consent{}, false
	}
	return c, c.Enabled
}

type WindowsResourceContextConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureWindowsResourceContext is local-only, after the lifecycle command has
// verified the owned service is stopped. The sender's exclusive ledger lock is
// held through the separate consent write; no sequence or identity is reset.
// Future combined installers can reuse this exact explicit-acknowledgement API.
func ConfigureWindowsResourceContext(path, mode string, acknowledged, insecure bool) (WindowsResourceContextConsentResult, error) {
	zero := WindowsResourceContextConsentResult{}
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
	result, e := updateWindowsResourceContextConsent(m.binding, mode, func(create bool) (resourceContextConsentStore, error) {
		return windowsstate.Open(windowsResourceContextConsentDirectory(m), windowsResourceContextOptions(sid, create))
	})
	if e != nil {
		return zero, e
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}

type resourceContextConsentStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}

// Creation is explicit and create-only. A missing consent in a previously
// opened manifest is unfinished state, never permission to adopt a grant.
func updateWindowsResourceContextConsent(binding, mode string, open func(bool) (resourceContextConsentStore, error)) (WindowsResourceContextConsentResult, error) {
	zero := WindowsResourceContextConsentResult{}
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
		return WindowsResourceContextConsentResult{windowsresourcecontext.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowsresourcecontext.Consent
	if e == nil {
		c, e = windowsresourcecontext.DecodeConsent(raw, binding)
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
		c = windowsresourcecontext.Consent{SchemaVersion: windowsresourcecontext.ConsentVersion, Scope: windowsresourcecontext.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Enabled: true}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowsresourcecontext.EncodeConsent(c, binding)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsResourceContextConsentResult{windowsresourcecontext.Scope, c.Enabled, true}, nil
}
