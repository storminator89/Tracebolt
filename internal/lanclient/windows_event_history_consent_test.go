package lanclient

import (
	"bytes"
	"os"
	"testing"

	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowshistorystate"
)

// Reuse only the inert storage mechanics, not old-scope consent/state types.
type historyGrantMemory struct{ eventGrantMemory }

func (s *historyGrantMemory) Initialize(l windowshistoryrequest.LocalContext) error {
	s.initializations++
	if s.failInit || s.initialized {
		return ErrState
	}
	r, e := windowshistorystate.NewReports(l)
	if e != nil {
		return e
	}
	s.reports, e = windowshistorystate.EncodeReports(r)
	if e != nil {
		return e
	}
	c, e := windowshistorystate.NewConsumption(l)
	if e != nil {
		return e
	}
	s.consumed, e = windowshistorystate.EncodeConsumption(c)
	s.initialized = e == nil
	return e
}
func (s *historyGrantMemory) Verify(l windowshistoryrequest.LocalContext) error {
	return s.eventGrantMemory.Verify(windowseventrequest.LocalContext{SenderBinding: l.SenderBinding, Profile: l.Profile, DeviceID: l.DeviceID, CertificateHash: l.CertificateHash})
}
func historyGrantLocal() windowshistoryrequest.LocalContext {
	l := eventGrantLocal()
	return windowshistoryrequest.LocalContext{SenderBinding: l.SenderBinding, Profile: l.Profile, DeviceID: l.DeviceID, CertificateHash: l.CertificateHash}
}
func TestEventHistoryConsentIndependentCreateDisableReenable(t *testing.T) {
	s := &historyGrantMemory{}
	exists := false
	creates := 0
	open := func(create bool) (eventHistoryGrantStore, error) {
		if create {
			creates++
			if exists {
				return nil, os.ErrExist
			}
			exists = true
		} else if !exists {
			return nil, os.ErrNotExist
		}
		return s, nil
	}
	l := historyGrantLocal()
	for _, mode := range []string{"preview", "disable"} {
		r, e := updateWindowsEventHistoryConsent(l, mode, open)
		if e != nil || r.Enabled || s.writes != 0 || creates != 0 {
			t.Fatal("missing scope changed")
		}
	}
	r, e := updateWindowsEventHistoryConsent(l, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || s.initializations != 1 {
		t.Fatal("fresh enable", e)
	}
	c, e := windowshistoryrequest.DecodeConsent(s.raw, l.SenderBinding, l.Profile)
	if e != nil || !c.HistoryAcknowledged || !c.ContentAcknowledged || !c.HTTPPlaintextAcknowledged {
		t.Fatal("missing independent acknowledgement")
	}
	if _, e := windowseventrequest.DecodeConsent(s.raw, l.SenderBinding, l.Profile); e == nil {
		t.Fatal("history grant promoted to sampled message scope")
	}
	reports, consumed := bytes.Clone(s.reports), bytes.Clone(s.consumed)
	if _, e := updateWindowsEventHistoryConsent(l, "disable", open); e != nil {
		t.Fatal(e)
	}
	if _, e := updateWindowsEventHistoryConsent(l, "enable", open); e != nil {
		t.Fatal(e)
	}
	next, e := windowshistoryrequest.DecodeConsent(s.raw, l.SenderBinding, l.Profile)
	if e != nil || next.GrantID == c.GrantID || creates != 1 || s.initializations != 1 || !bytes.Equal(reports, s.reports) || !bytes.Equal(consumed, s.consumed) {
		t.Fatal("reenable reset floors")
	}
}
func TestEventHistoryConsentRejectsOldAndMissingUsedAuthority(t *testing.T) {
	l := historyGrantLocal()
	old := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: l.SenderBinding, GrantID: "11111111111111111111111111111111", Profile: l.Profile, Enabled: true, ContentAcknowledged: true, HTTPPlaintextAcknowledged: true}
	raw, e := windowseventrequest.EncodeConsent(old, l.SenderBinding, l.Profile)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"preview", "enable", "disable"} {
		for _, data := range [][]byte{nil, raw} {
			s := &historyGrantMemory{eventGrantMemory: eventGrantMemory{raw: data, initialized: true}}
			_, e := updateWindowsEventHistoryConsent(l, mode, func(create bool) (eventHistoryGrantStore, error) {
				if create {
					t.Fatal("adopted used store")
				}
				return s, nil
			})
			if e == nil || s.writes != 0 || s.initializations != 0 {
				t.Fatal("old/missing grant adopted")
			}
		}
	}
	for _, failure := range []string{"init", "verify", "write", "close"} {
		s := &historyGrantMemory{}
		s.failInit = failure == "init"
		s.failVerify = failure == "verify"
		s.failWrite = failure == "write"
		s.failClose = failure == "close"
		_, e := updateWindowsEventHistoryConsent(l, "enable", func(create bool) (eventHistoryGrantStore, error) {
			if !create {
				return nil, os.ErrNotExist
			}
			return s, nil
		})
		if e == nil {
			t.Fatal("uncertain state accepted", failure)
		}
	}
	if windowsEventHistoryOptions("fixture", false).LockName == windowsEventContentOptions("fixture", false).LockName {
		t.Fatal("scope locks alias")
	}
	for _, mode := range []string{"enable", "preview", "disable"} {
		if _, e := ConfigureWindowsEventHistory("never-opened", mode, mode != "enable", false); e != ErrConfiguration {
			t.Fatal("invalid acknowledgement reached host")
		}
	}
}
