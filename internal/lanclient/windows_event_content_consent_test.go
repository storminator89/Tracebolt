package lanclient

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventstate"
)

type eventGrantMemory struct {
	raw                                                  []byte
	initialized                                          bool
	initializations, writes                              int
	reports, consumed                                    []byte
	failRead, failWrite, failInit, failVerify, failClose bool
}

func (s *eventGrantMemory) Read(n string) ([]byte, error) {
	if s.failRead {
		return nil, ErrState
	}
	if n != "consent.json" {
		return nil, ErrState
	}
	if s.raw == nil {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(s.raw), nil
}
func (s *eventGrantMemory) Write(n string, b []byte) error {
	s.writes++
	if s.failWrite || n != "consent.json" {
		return ErrState
	}
	s.raw = bytes.Clone(b)
	return nil
}
func (s *eventGrantMemory) Close() error {
	if s.failClose {
		return ErrState
	}
	return nil
}
func (s *eventGrantMemory) Initialize(l windowseventrequest.LocalContext) error {
	s.initializations++
	if s.failInit || s.initialized {
		return ErrState
	}
	r, e := windowseventstate.NewReports(l)
	if e != nil {
		return e
	}
	s.reports, e = windowseventstate.EncodeReports(r)
	if e != nil {
		return e
	}
	c, e := windowseventstate.NewConsumption(l)
	if e != nil {
		return e
	}
	s.consumed, e = windowseventstate.EncodeConsumption(c)
	s.initialized = e == nil
	return e
}
func (s *eventGrantMemory) Verify(windowseventrequest.LocalContext) error {
	if s.failVerify || !s.initialized || len(s.reports) == 0 || len(s.consumed) == 0 {
		return ErrState
	}
	return nil
}
func eventGrantLocal() windowseventrequest.LocalContext {
	return windowseventrequest.LocalContext{SenderBinding: strings.Repeat("a", 64), Profile: "http-test", DeviceID: "agent_" + strings.Repeat("b", 32), CertificateHash: strings.Repeat("c", 64)}
}
func TestEventContentConsentCreateOnlyRetainsIndependentFloors(t *testing.T) {
	s := &eventGrantMemory{}
	exists := false
	creates := 0
	open := func(create bool) (eventContentGrantStore, error) {
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
	l := eventGrantLocal()
	for _, mode := range []string{"preview", "disable"} {
		r, e := updateWindowsEventContentConsent(l, mode, open)
		if e != nil || r.Enabled || creates != 0 || s.writes != 0 {
			t.Fatal("nonmutating missing grant failed")
		}
	}
	r, e := updateWindowsEventContentConsent(l, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || s.initializations != 1 {
		t.Fatal("enable failed", e)
	}
	c, e := windowseventrequest.DecodeConsent(s.raw, l.SenderBinding, l.Profile)
	if e != nil || !c.ContentAcknowledged || !c.HTTPPlaintextAcknowledged {
		t.Fatal("scope disclosure not bound")
	}
	first := bytes.Clone(s.raw)
	if _, e := updateWindowsEventContentConsent(l, "preview", open); e != nil || s.writes != 1 || !bytes.Equal(first, s.raw) {
		t.Fatal("preview mutated state")
	}
	s.reports = []byte("fixture retained report floor")
	s.consumed = []byte("fixture retained consume floor")
	reports, consumed := bytes.Clone(s.reports), bytes.Clone(s.consumed)
	if _, e := updateWindowsEventContentConsent(l, "enable", open); e != nil || !bytes.Equal(first, s.raw) {
		t.Fatal("enable replaced active grant")
	}
	if r, e = updateWindowsEventContentConsent(l, "disable", open); e != nil || r.Enabled {
		t.Fatal("disable failed")
	}
	off, _ := windowseventrequest.DecodeConsent(s.raw, l.SenderBinding, l.Profile)
	if off.GrantID != c.GrantID || !off.ContentAcknowledged || !off.HTTPPlaintextAcknowledged {
		t.Fatal("disable erased receipt")
	}
	if r, e = updateWindowsEventContentConsent(l, "enable", open); e != nil || !r.Enabled {
		t.Fatal("reenable failed")
	}
	on, _ := windowseventrequest.DecodeConsent(s.raw, l.SenderBinding, l.Profile)
	if on.GrantID == c.GrantID || creates != 1 || s.initializations != 1 || !bytes.Equal(reports, s.reports) || !bytes.Equal(consumed, s.consumed) {
		t.Fatal("reenable reset state")
	}
}
func TestEventContentConsentUsedMissingAmbiguousStateNeverRepaired(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		s := &eventGrantMemory{initialized: true}
		creates := 0
		_, e := updateWindowsEventContentConsent(eventGrantLocal(), mode, func(create bool) (eventContentGrantStore, error) {
			if create {
				creates++
			}
			return s, nil
		})
		if e == nil || creates != 0 || s.initializations != 0 || s.writes != 0 {
			t.Fatal("missing existing consent adopted", mode)
		}
	}
	for _, failure := range []string{"init", "verify", "write", "close"} {
		s := &eventGrantMemory{}
		switch failure {
		case "init":
			s.failInit = true
		case "verify":
			s.failVerify = true
		case "write":
			s.failWrite = true
		case "close":
			s.failClose = true
		}
		_, e := updateWindowsEventContentConsent(eventGrantLocal(), "enable", func(create bool) (eventContentGrantStore, error) {
			if !create {
				return nil, os.ErrNotExist
			}
			return s, nil
		})
		if e == nil {
			t.Fatal("uncertain write reported success", failure)
		}
	}
	for _, err := range []error{os.ErrPermission, ErrState} {
		_, e := updateWindowsEventContentConsent(eventGrantLocal(), "enable", func(create bool) (eventContentGrantStore, error) {
			if create {
				t.Fatal("access denial recreated state")
			}
			return nil, err
		})
		if !errors.Is(e, ErrState) {
			t.Fatal(e)
		}
	}
}
func TestEventContentConsentManifestIndependentAndFixed(t *testing.T) {
	root := windowsEventContentOptions("fixture", false)
	reports := windowsEventContentReportsOptions("fixture", false)
	consume := windowsEventContentConsumeOptions("fixture", false)
	if len(root.Names) != 1 || len(root.Directories) != 2 || root.MaxBytes != 2048 || reports.MaxBytes != windowseventstate.MaxBytes || consume.MaxBytes != windowseventstate.MaxBytes || root.LockName == windowsUpdatesOptions("fixture", false).LockName || reports.LockName == consume.LockName {
		t.Fatal("state manifests alias")
	}
	for _, mode := range []string{"enable", "preview", "disable"} {
		if _, e := ConfigureWindowsEventContent("never-opened", mode, mode != "enable", false); e != ErrConfiguration {
			t.Fatal("invalid acknowledgement touched host")
		}
	}
}
