package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsstorageio"
	"os"
	"path/filepath"
)

// This sibling has its own immutable protected manifest. No name is added to
// the existing enrollment or sender manifest, and no used ledger is migrated.
func windowsStorageIOConsentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-storage-io"
}
func windowsStorageIOOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "storage-io.lock", TempName: "storage-io.tmp", MaxBytes: 1024, Create: create}
}
func readWindowsStorageIOConsent(m Material) (windowsstorageio.Consent, bool) {
	return readWindowsStorageIOConsentWithDependencies(m, windowsContextConsentDependencies{Load, openWindowsContextConsent})
}
func readWindowsStorageIOConsentWithDependencies(m Material, d windowsContextConsentDependencies) (windowsstorageio.Consent, bool) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowsstorageio.Consent{}, false
	}
	// Pending retries do not start the native child. Recheck activated identity
	// here too, before reading consent, at every sender authority boundary.
	if !currentWindowsContextMaterial(m, d.reload) {
		return windowsstorageio.Consent{}, false
	}
	if d.open == nil {
		return windowsstorageio.Consent{}, false
	}
	s, e := d.open(windowsStorageIOConsentDirectory(m), windowsStorageIOOptions("", false))
	if e != nil || s == nil {
		return windowsstorageio.Consent{}, false
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowsstorageio.Consent{}, false
	}
	c, e := windowsstorageio.DecodeConsent(raw, m.binding)
	if e != nil || s.Close() != nil {
		return windowsstorageio.Consent{}, false
	}
	return c, c.Enabled
}

type WindowsStorageIOConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureWindowsStorageIO is local-only, after the lifecycle command has
// verified the owned service is stopped. The sender's exclusive ledger lock is
// held through the separate consent write; no sequence or identity is reset.
// Future combined installers can reuse this exact explicit-acknowledgement API.
func ConfigureWindowsStorageIO(path, mode string, acknowledged, insecure bool) (WindowsStorageIOConsentResult, error) {
	zero := WindowsStorageIOConsentResult{}
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
	result, e := updateWindowsStorageIOConsent(m.binding, mode, func(create bool) (storageIOConsentStore, error) {
		return windowsstate.Open(windowsStorageIOConsentDirectory(m), windowsStorageIOOptions(sid, create))
	})
	if e != nil {
		return zero, e
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}

type storageIOConsentStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}

// Creation is explicit and create-only. A missing consent in a previously
// opened manifest is unfinished state, never permission to adopt a grant.
func updateWindowsStorageIOConsent(binding, mode string, open func(bool) (storageIOConsentStore, error)) (WindowsStorageIOConsentResult, error) {
	zero := WindowsStorageIOConsentResult{}
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
		return WindowsStorageIOConsentResult{windowsstorageio.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowsstorageio.Consent
	if e == nil {
		c, e = windowsstorageio.DecodeConsent(raw, binding)
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
		c = windowsstorageio.Consent{SchemaVersion: windowsstorageio.ConsentVersion, Scope: windowsstorageio.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Enabled: true}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowsstorageio.EncodeConsent(c, binding)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsStorageIOConsentResult{windowsstorageio.Scope, c.Enabled, true}, nil
}
