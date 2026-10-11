package lanclient

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"localrmm/internal/lanclientstate"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorystate"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
)

func windowsEventHistoryDirectory(m Material) string {
	return filepath.Dir(filepath.Dir(m.config.StateDirectory)) + "-event-history"
}
func windowsEventHistoryOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, Directories: []string{"reports", "consumption"}, LockName: "event-history.lock", TempName: "event-history.tmp", MaxBytes: 2048, Create: create}
}
func windowsEventHistoryReportsOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"reports.json"}, LockName: "reports.lock", TempName: "reports.tmp", MaxBytes: windowshistorystate.MaxBytes, Create: create}
}
func windowsEventHistoryConsumeOptions(sid string, create bool) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consumed.json"}, LockName: "consumed.lock", TempName: "consumed.tmp", MaxBytes: windowshistorystate.MaxBytes, Create: create}
}
func windowsEventHistoryContext(m Material) windowshistoryrequest.LocalContext {
	return windowshistoryrequest.LocalContext{SenderBinding: m.binding, Profile: m.config.Profile, DeviceID: m.config.AgentID, CertificateHash: journalLeaf(m)}
}

type WindowsEventHistoryConsentResult struct {
	Scope                  string `json:"scope"`
	Enabled                bool   `json:"enabled"`
	ExistingStatePreserved bool   `json:"existingStatePreserved"`
}
type eventHistoryGrantStore interface {
	Read(string) ([]byte, error)
	Write(string, []byte) error
	Close() error
	Initialize(windowshistoryrequest.LocalContext) error
	Verify(windowshistoryrequest.LocalContext) error
}
type eventHistoryNativeGrant struct {
	root      *windowsstate.Store
	path, sid string
}

func (s *eventHistoryNativeGrant) Read(n string) ([]byte, error)  { return s.root.Read(n) }
func (s *eventHistoryNativeGrant) Write(n string, b []byte) error { return s.root.Write(n, b) }
func (s *eventHistoryNativeGrant) Close() error                   { return s.root.Close() }
func (s *eventHistoryNativeGrant) Initialize(local windowshistoryrequest.LocalContext) error {
	reports, e := s.root.CreateDirectoryStore("reports", windowsEventHistoryReportsOptions(s.sid, true))
	if e != nil {
		return ErrState
	}
	r, e := windowshistorystate.NewReports(local)
	raw, e2 := windowshistorystate.EncodeReports(r)
	if e != nil || e2 != nil || reports.Write("reports.json", raw) != nil {
		reports.Close()
		return ErrState
	}
	if reports.Close() != nil {
		return ErrState
	}
	consumed, e := s.root.CreateDirectoryStore("consumption", windowsEventHistoryConsumeOptions(s.sid, true))
	if e != nil {
		return ErrState
	}
	c, e := windowshistorystate.NewConsumption(local)
	raw, e2 = windowshistorystate.EncodeConsumption(c)
	if e != nil || e2 != nil || consumed.Write("consumed.json", raw) != nil {
		consumed.Close()
		return ErrState
	}
	if consumed.Close() != nil {
		return ErrState
	}
	return nil
}
func (s *eventHistoryNativeGrant) Verify(local windowshistoryrequest.LocalContext) error {
	reports, e := windowsstate.Open(filepath.Join(s.path, "reports"), windowsEventHistoryReportsOptions(s.sid, false))
	if e != nil {
		return ErrState
	}
	_, e = windowshistorystate.ReadReports(reports, local)
	ce := reports.Close()
	if e != nil || ce != nil {
		return ErrState
	}
	consumed, e := windowsstate.Open(filepath.Join(s.path, "consumption"), windowsEventHistoryConsumeOptions(s.sid, false))
	if e != nil {
		return ErrState
	}
	_, e = windowshistorystate.ReadConsumption(consumed, local)
	ce = consumed.Close()
	if e != nil || ce != nil {
		return ErrState
	}
	return nil
}

// ConfigureWindowsEventHistory is selected only by its explicit stopped-owned
// service operation or fresh v14 receipt-guarded Setup. Historical combined,
// header and sampled-content grants never call it. The existing sender ledger
// is held without changing its state.
func ConfigureWindowsEventHistory(path, mode string, acknowledged, insecure bool) (WindowsEventHistoryConsentResult, error) {
	zero := WindowsEventHistoryConsentResult{}
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
	result, e := updateWindowsEventHistoryConsent(windowsEventHistoryContext(m), mode, func(create bool) (eventHistoryGrantStore, error) {
		p := windowsEventHistoryDirectory(m)
		root, e := windowsstate.Open(p, windowsEventHistoryOptions(sid, create))
		if e != nil {
			return nil, e
		}
		return &eventHistoryNativeGrant{root, p, sid}, nil
	})
	if e != nil || state.Close() != nil {
		return zero, ErrState
	}
	return result, nil
}
func updateWindowsEventHistoryConsent(local windowshistoryrequest.LocalContext, mode string, open func(bool) (eventHistoryGrantStore, error)) (WindowsEventHistoryConsentResult, error) {
	zero := WindowsEventHistoryConsentResult{}
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
		return WindowsEventHistoryConsentResult{windowshistoryrequest.Scope, false, true}, nil
	}
	if e != nil || s == nil {
		return zero, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	var c windowshistoryrequest.Consent
	if e == nil {
		c, e = windowshistoryrequest.DecodeConsent(raw, local.SenderBinding, local.Profile)
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
		c = windowshistoryrequest.Consent{SchemaVersion: windowshistoryrequest.ConsentVersion, Scope: windowshistoryrequest.Scope, SenderBinding: local.SenderBinding, GrantID: hex.EncodeToString(id[:]), Profile: local.Profile, Enabled: true, ContentAcknowledged: true, HistoryAcknowledged: true, HTTPPlaintextAcknowledged: local.Profile == "http-test"}
	} else if mode == "disable" {
		c.Enabled = false
	}
	if mode != "preview" {
		raw, e = windowshistoryrequest.EncodeConsent(c, local.SenderBinding, local.Profile)
		if e != nil || s.Write("consent.json", raw) != nil {
			return zero, ErrState
		}
	}
	if s.Close() != nil {
		return zero, ErrState
	}
	return WindowsEventHistoryConsentResult{windowshistoryrequest.Scope, c.Enabled, true}, nil
}

var errEventHistoryDisabled = errors.New("windows_event_history_disabled")

// No sender lock is acquired here: the installed parent retains it. Missing
// sidecar means off; missing used records, ACL/identity faults mean denial.
func readWindowsEventHistoryLocal(m Material) (windowshistoryrequest.Consent, error) {
	if !m.valid() || !m.config.windowsInventory() {
		return windowshistoryrequest.Consent{}, errEventHistoryDisabled
	}
	current, e := Load(m.configPath)
	if e != nil || current.binding != m.binding || current.config != m.config || journalLeaf(current) != journalLeaf(m) || validateUpdatesActivatedMaterial(m.configPath, current) != nil {
		return windowshistoryrequest.Consent{}, ErrState
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return windowshistoryrequest.Consent{}, ErrState
	}
	s, e := windowsstate.Open(windowsEventHistoryDirectory(m), windowsEventHistoryOptions(sid, false))
	if errors.Is(e, os.ErrNotExist) {
		return windowshistoryrequest.Consent{}, errEventHistoryDisabled
	}
	if e != nil {
		return windowshistoryrequest.Consent{}, ErrState
	}
	defer s.Close()
	raw, e := s.Read("consent.json")
	if e != nil {
		return windowshistoryrequest.Consent{}, ErrState
	}
	c, e := windowshistoryrequest.DecodeConsent(raw, m.binding, m.config.Profile)
	if e != nil || s.Close() != nil {
		return windowshistoryrequest.Consent{}, ErrState
	}
	return c, nil
}

// withWindowsHistoryReports holds only the independent parent metadata lock, and
// always releases it before spawning a child. The child never acquires sender.
func withWindowsHistoryReports(m Material, c windowshistoryrequest.Consent, fn func(windowshistorystate.Storage) error) error {
	current, e := readWindowsEventHistoryLocal(m)
	if e != nil || current != c || fn == nil {
		return ErrState
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return ErrState
	}
	s, e := windowsstate.Open(filepath.Join(windowsEventHistoryDirectory(m), "reports"), windowsEventHistoryReportsOptions(sid, false))
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
	current, e = readWindowsEventHistoryLocal(m)
	if e != nil || current != c {
		return ErrState
	}
	return nil
}

// Setup verifies consent and both initialized floors before recording its exact
// history grant digest. Reading the consent alone cannot prove usable authority.
func readWindowsEventHistoryGrant(m Material) (windowshistoryrequest.Consent, bool) {
	c, e := readWindowsEventHistoryLocal(m)
	if e != nil || !c.Enabled {
		return windowshistoryrequest.Consent{}, false
	}
	sid, e := windowsservice.LookupServiceSID()
	if e != nil {
		return windowshistoryrequest.Consent{}, false
	}
	root, e := windowsstate.Open(windowsEventHistoryDirectory(m), windowsEventHistoryOptions(sid, false))
	if e != nil {
		return windowshistoryrequest.Consent{}, false
	}
	defer root.Close()
	s := &eventHistoryNativeGrant{root, windowsEventHistoryDirectory(m), sid}
	if s.Verify(windowsEventHistoryContext(m)) != nil || s.Close() != nil {
		return windowshistoryrequest.Consent{}, false
	}
	current, e := readWindowsEventHistoryLocal(m)
	return c, e == nil && current == c
}
