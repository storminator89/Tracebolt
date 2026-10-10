package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventstate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

func windowsEventContentDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-event-content"
}
func windowsEventContentOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, Directories: []string{"reports", "consumption"}, LockName: "event-content.lock", TempName: "event-content.tmp", MaxBytes: 2048, Create: create}
}
func windowsEventContentReportsOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"reports.json"}, LockName: "reports.lock", TempName: "reports.tmp", MaxBytes: windowseventstate.MaxBytes, Create: create}
}
func windowsEventContentConsumeOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consumed.json"}, LockName: "consumed.lock", TempName: "consumed.tmp", MaxBytes: windowseventstate.MaxBytes, Create: create}
}
func windowsEventContentContext(m Material) windowseventrequest.LocalContext {
	return windowseventrequest.LocalContext{SenderBinding: m.binding, Profile: m.config.Profile, DeviceID: m.config.AgentID, CertificateHash: journalLeaf(m)}
}

type WindowsEventContentConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}
type eventContentGrantStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
	Initialize(windowseventrequest.LocalContext) error
	Verify(windowseventrequest.LocalContext) error
}
type eventContentNativeGrant struct {
	root      *windowsstate.Store
	path, sid string
}

func (s *eventContentNativeGrant) Read(n string) ([]byte, error)  { return s.root.Read(n) }
func (s *eventContentNativeGrant) Write(n string, b []byte) error { return s.root.Write(n, b) }
func (s *eventContentNativeGrant) Close() error                   { return s.root.Close() }
func (s *eventContentNativeGrant) Initialize(local windowseventrequest.LocalContext) error {
	reports, e := s.root.CreateDirectoryStore("reports", windowsEventContentReportsOptions(s.sid, true))
	if e != nil {
		return ErrState
	}
	r, e := windowseventstate.NewReports(local)
	raw, e2 := windowseventstate.EncodeReports(r)
	if e != nil || e2 != nil || reports.Write("reports.json", raw) != nil {
		reports.Close()
		return ErrState
	}
	if reports.Close() != nil {
		return ErrState
	}
	consumed, e := s.root.CreateDirectoryStore("consumption", windowsEventContentConsumeOptions(s.sid, true))
	if e != nil {
		return ErrState
	}
	c, e := windowseventstate.NewConsumption(local)
	raw, e2 = windowseventstate.EncodeConsumption(c)
	if e != nil || e2 != nil || consumed.Write("consumed.json", raw) != nil {
		consumed.Close()
		return ErrState
	}
	if consumed.Close() != nil {
		return ErrState
	}
	return nil
}
func (s *eventContentNativeGrant) Verify(local windowseventrequest.LocalContext) error {
	reports, e := windowsstate.Open(filepath.Join(s.path, "reports"), windowsEventContentReportsOptions(s.sid, false))
	if e != nil {
		return ErrState
	}
	_, e = windowseventstate.ReadReports(reports, local)
	ce := reports.Close()
	if e != nil || ce != nil {
		return ErrState
	}
	consumed, e := windowsstate.Open(filepath.Join(s.path, "consumption"), windowsEventContentConsumeOptions(s.sid, false))
	if e != nil {
		return ErrState
	}
	_, e = windowseventstate.ReadConsumption(consumed, local)
	ce = consumed.Close()
	if e != nil || ce != nil {
		return ErrState
	}
	return nil
}

// ConfigureWindowsEventContent is selected only by the independent, stopped
// owned-service lifecycle operation. Existing combined/header grants do not call
// this function. It holds the existing sender ledger without changing it.
func ConfigureWindowsEventContent(path, mode string, acknowledged, insecure bool) (WindowsEventContentConsentResult, error) {
	zero := WindowsEventContentConsentResult{}
	if mode != "preview" && mode != "enable" && mode != "disable" || acknowledged != (mode == "enable") {
		return zero, ErrConfiguration
	}
	if ValidateGuidedHandoff(path) != nil {
		return zero, ErrState
	}
	m, e := Load(path)
	if e != nil || !m.config.windowsInventory() || insecure != (m.config.Profile == "http-test") || validateUpdatesActivatedMaterial(path, m) != nil {
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
	result, e := updateWindowsEventContentConsent(windowsEventContentContext(m), mode, func(create bool) (eventContentGrantStore, error) {
		p := windowsEventContentDirectory(m)
		root, e := windowsstate.Open(p, windowsEventContentOptions(sid, create))
		if e != nil {
			return nil, e
		}
		return &eventContentNativeGrant{root, p, sid}, nil
	})
	if e != nil || state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}
func updateWindowsEventContentConsent(local windowseventrequest.LocalContext, mode string, open func(bool) (eventContentGrantStore, error)) (WindowsEventContentConsentResult, error) {
	zero := WindowsEventContentConsentResult{}
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
		return WindowsEventContentConsentResult{windowseventrequest.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowseventrequest.Consent
	if e == nil {
		c, e = windowseventrequest.DecodeConsent(raw, local.SenderBinding, local.Profile)
	} else if errors.Is(e, os.ErrNotExist) && fresh {
		e = s.Initialize(local)
	}
	if e != nil {
		return zero, ErrState
	}
	if s.Verify(local) != nil {
		return zero, ErrState
	}
	if mode == "enable" && !c.Enabled {
		var id [16]byte
		if _, e = rand.Read(id[:]); e != nil {
			return zero, ErrState
		}
		c = windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: local.SenderBinding, GrantID: hex.EncodeToString(id[:]), Profile: local.Profile, Enabled: true, ContentAcknowledged: true, HTTPPlaintextAcknowledged: local.Profile == "http-test"}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowseventrequest.EncodeConsent(c, local.SenderBinding, local.Profile)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsEventContentConsentResult{windowseventrequest.Scope, c.Enabled, true}, nil
}

var errEventContentDisabled = errors.New("windows_event_content_disabled")

// No sender lock is acquired here: the installed parent retains it. Missing
// sidecar means off; missing used records, ACL/identity faults mean denial.
func readWindowsEventContentLocal(m Material) (windowseventrequest.Consent, error) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowseventrequest.Consent{}, errEventContentDisabled
	}
	current, e := Load(m.configPath)
	if e != nil || current.binding != m.binding || current.config != m.config || journalLeaf(current) != journalLeaf(m) || validateUpdatesActivatedMaterial(m.configPath, current) != nil {
		return windowseventrequest.Consent{}, ErrState
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return windowseventrequest.Consent{}, ErrState
	}
	s, e := windowsstate.Open(windowsEventContentDirectory(m), windowsEventContentOptions(sid, false))
	if errors.Is(e, os.ErrNotExist) {
		return windowseventrequest.Consent{}, errEventContentDisabled
	}
	if e != nil {
		return windowseventrequest.Consent{}, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowseventrequest.Consent{}, ErrState
	}
	c, e := windowseventrequest.DecodeConsent(raw, m.binding, m.config.Profile)
	if e != nil || s.Close() != nil {
		return windowseventrequest.Consent{}, ErrState
	}
	return c, nil
}

// withWindowsEventReports holds only the independent parent metadata lock, and
// always releases it before spawning a child. The child never acquires sender.
func withWindowsEventReports(m Material, c windowseventrequest.Consent, fn func(windowseventstate.Storage) error) error {
	current, e := readWindowsEventContentLocal(m)
	if e != nil || current != c || fn == nil {
		return ErrState
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return ErrState
	}
	s, e := windowsstate.Open(filepath.Join(windowsEventContentDirectory(m), "reports"), windowsEventContentReportsOptions(sid, false))
	if e != nil {
		return ErrState
	}
	defer s.Close()
	if e = fn(s); e != nil {
		return e
	}
	if s.Close() != nil {
		return ErrState
	}
	current, e = readWindowsEventContentLocal(m)
	if e != nil || current != c {
		return ErrState
	}
	return nil
}
