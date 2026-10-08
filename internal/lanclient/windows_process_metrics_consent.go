package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"os"
	"path/filepath"
)

// This sibling has its own immutable protected manifest. No name is added to
// the existing enrollment or sender manifest, and no used ledger is migrated.
func windowsProcessMetricsConsentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-process-metrics"
}
func windowsProcessMetricsOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: "process-metrics.lock", TempName: "process-metrics.tmp", MaxBytes: 1024, Create: create}
}
func readWindowsProcessMetricsConsent(m Material) (windowsprocessmetrics.Consent, bool) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowsprocessmetrics.Consent{}, false
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return windowsprocessmetrics.Consent{}, false
	}
	s, e := windowsstate.Open(windowsProcessMetricsConsentDirectory(m), windowsProcessMetricsOptions(sid, false))
	if e != nil {
		return windowsprocessmetrics.Consent{}, false
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowsprocessmetrics.Consent{}, false
	}
	c, e := windowsprocessmetrics.DecodeConsent(raw, m.binding)
	if e != nil || s.Close() != nil {
		return windowsprocessmetrics.Consent{}, false
	}
	return c, c.Enabled
}

type WindowsProcessMetricsConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}

// ConfigureWindowsProcessMetrics is local-only, after the lifecycle command has
// verified the owned service is stopped. The sender's exclusive ledger lock is
// held through the separate consent write; no sequence or identity is reset.
// Future combined installers can reuse this exact explicit-acknowledgement API.
func ConfigureWindowsProcessMetrics(path, mode string, acknowledged, insecure bool) (WindowsProcessMetricsConsentResult, error) {
	zero := WindowsProcessMetricsConsentResult{}
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
	result, e := updateWindowsProcessMetricsConsent(m.binding, mode, func(create bool) (processMetricsConsentStore, error) {
		return windowsstate.Open(windowsProcessMetricsConsentDirectory(m), windowsProcessMetricsOptions(sid, create))
	})
	if e != nil {
		return zero, e
	}
	if state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}

type processMetricsConsentStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
}

// Creation is explicit and create-only. A missing consent in a previously
// opened manifest is unfinished state, never permission to adopt a grant.
func updateWindowsProcessMetricsConsent(binding, mode string, open func(bool) (processMetricsConsentStore, error)) (WindowsProcessMetricsConsentResult, error) {
	zero := WindowsProcessMetricsConsentResult{}
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
		return WindowsProcessMetricsConsentResult{windowsprocessmetrics.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowsprocessmetrics.Consent
	if e == nil {
		c, e = windowsprocessmetrics.DecodeConsent(raw, binding)
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
		c = windowsprocessmetrics.Consent{SchemaVersion: windowsprocessmetrics.ConsentVersion, Scope: windowsprocessmetrics.Scope, SenderBinding: binding, GrantID: hex.EncodeToString(id[:]), Enabled: true}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowsprocessmetrics.EncodeConsent(c, binding)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsProcessMetricsConsentResult{windowsprocessmetrics.Scope, c.Enabled, true}, nil
}
