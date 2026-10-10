package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsupdates"
	"os"
	"path/filepath"
)

// This sibling has its own immutable protected manifest. No name is added to
// the existing enrollment or sender manifest, and no used ledger is migrated.
func windowsUpdatesConsentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-updates"
}
func windowsUpdatesOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "updates.lock", TempName: "updates.tmp", MaxBytes: 1024, Create: create}
}
func readWindowsUpdatesConsent(m Material) (windowsupdates.Consent, bool) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowsupdates.Consent{}, false
	}
	// Reread the activated identity without taking the parent's sender-ledger
	// lock. A replaced certificate/config/ready receipt suppresses this scope.
	current, e := Load(m.configPath)
	if e != nil || current.binding != m.binding || current.config != m.config || validateUpdatesActivatedMaterial(m.configPath, current) != nil {
		return windowsupdates.Consent{}, false
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return windowsupdates.Consent{}, false
	}
	s, e := windowsstate.Open(windowsUpdatesConsentDirectory(m), windowsUpdatesOptions(sid, false))
	if e != nil {
		return windowsupdates.Consent{}, false
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowsupdates.Consent{}, false
	}
	c, e := windowsupdates.DecodeConsent(raw, m.binding)
	if e != nil || s.Close() != nil {
		return windowsupdates.Consent{}, false
	}
	return c, c.Enabled
}

type WindowsUpdatesConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureWindowsUpdates is local-only, after the lifecycle command has
// verified the owned service is stopped. The sender's exclusive ledger lock is
// held through the separate consent write; no sequence or identity is reset.
// The existing five-scope installer does not call this independent API.
func ConfigureWindowsUpdates(path, mode string, acknowledged, insecure bool) (WindowsUpdatesConsentResult, error) {
	zero := WindowsUpdatesConsentResult{}
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
	result, e := updateWindowsUpdatesConsent(m.binding, mode, func(create bool) (updatesConsentStore, error) {
		return windowsstate.Open(windowsUpdatesConsentDirectory(m), windowsUpdatesOptions(sid, create))
	})
	if e != nil {
		return zero, e
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}

type updatesConsentStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}

// Creation is explicit and create-only. A missing consent in a previously
// opened manifest is unfinished state, never permission to adopt a grant.
func updateWindowsUpdatesConsent(binding, mode string, open func(bool) (updatesConsentStore, error)) (WindowsUpdatesConsentResult, error) {
	zero := WindowsUpdatesConsentResult{}
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
		return WindowsUpdatesConsentResult{windowsupdates.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowsupdates.Consent
	if e == nil {
		c, e = windowsupdates.DecodeConsent(raw, binding)
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
		c = windowsupdates.Consent{SchemaVersion: windowsupdates.ConsentVersion, Scope: windowsupdates.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Enabled: true}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowsupdates.EncodeConsent(c, binding)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsUpdatesConsentResult{windowsupdates.Scope, c.Enabled, true}, nil
}
