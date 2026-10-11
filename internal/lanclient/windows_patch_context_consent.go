package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowspatchcontext"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"os"
	"path/filepath"
)

// This sibling has its own immutable protected manifest. No name is added to
// the existing enrollment or sender manifest, and no used ledger is migrated.
func windowsPatchContextConsentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-patch-context"
}
func windowsPatchContextOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "patch-context.lock", TempName: "patch-context.tmp", MaxBytes: 1024, Create: create}
}
func readWindowsPatchContextConsent(m Material) (windowspatchcontext.Consent, bool) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowspatchcontext.Consent{}, false
	}
	// Pending retries do not start the native child. Recheck activated identity
	// here too, before reading consent, at every sender authority boundary.
	if !currentWindowsPatchContextMaterial(m, Load) {
		return windowspatchcontext.Consent{}, false
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return windowspatchcontext.Consent{}, false
	}
	s, e := windowsstate.Open(windowsPatchContextConsentDirectory(m), windowsPatchContextOptions(sid, false))
	if e != nil {
		return windowspatchcontext.Consent{}, false
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowspatchcontext.Consent{}, false
	}
	c, e := windowspatchcontext.DecodeConsent(raw, m.binding)
	if e != nil || s.Close() != nil {
		return windowspatchcontext.Consent{}, false
	}
	return c, c.Enabled
}

type WindowsPatchContextConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureWindowsPatchContext is local-only, after the lifecycle command has
// verified the owned service is stopped. The sender's exclusive ledger lock is
// held through the separate consent write; no sequence or identity is reset.
// Future combined installers can reuse this exact explicit-acknowledgement API.
func ConfigureWindowsPatchContext(path, mode string, acknowledged, insecure bool) (WindowsPatchContextConsentResult, error) {
	zero := WindowsPatchContextConsentResult{}
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
	result, e := updateWindowsPatchContextConsent(m.binding, mode, func(create bool) (patchContextConsentStore, error) {
		return windowsstate.Open(windowsPatchContextConsentDirectory(m), windowsPatchContextOptions(sid, create))
	})
	if e != nil {
		return zero, e
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}

type patchContextConsentStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}

// Creation is explicit and create-only. A missing consent in a previously
// opened manifest is unfinished state, never permission to adopt a grant.
func updateWindowsPatchContextConsent(binding, mode string, open func(bool) (patchContextConsentStore, error)) (WindowsPatchContextConsentResult, error) {
	zero := WindowsPatchContextConsentResult{}
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
		return WindowsPatchContextConsentResult{windowspatchcontext.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowspatchcontext.Consent
	if e == nil {
		c, e = windowspatchcontext.DecodeConsent(raw, binding)
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
		c = windowspatchcontext.Consent{SchemaVersion: windowspatchcontext.ConsentVersion, Scope: windowspatchcontext.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Enabled: true}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowspatchcontext.EncodeConsent(c, binding)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsPatchContextConsentResult{windowspatchcontext.Scope, c.Enabled, true}, nil
}

// reload is a private test seam; production always uses Load. The protected
// config/ready receipt is read again even after Load to catch replacement races.
func currentWindowsPatchContextMaterial(m Material, reload func(string) (Material, error)) bool {
	if !m.valid() || !m.config.windowsInventory() || reload == nil {
		return false
	}
	current, e := reload(m.configPath)
	return e == nil && current.binding == m.binding && current.config == m.config && validateUpdatesActivatedMaterial(m.configPath, current) == nil
}
