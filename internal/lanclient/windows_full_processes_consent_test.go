package lanclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"localrmm/internal/windowsfullprocesses"
)

// Portable, invented protected-store seam. This grants no native collection.
type fullProcessesConsentMemory struct {
	files  map[string][]byte
	writes int
}

func (s *fullProcessesConsentMemory) Read(n string) ([]byte, error) {
	b, ok := s.files[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(b), nil
}
func (s *fullProcessesConsentMemory) Write(n string, b []byte) error {
	s.files[n] = bytes.Clone(b)
	s.writes++
	return nil
}
func (s *fullProcessesConsentMemory) Close() error { return nil }
func TestWindowsFullProcessesConsentFreshOnlyDefaultOffAndIndependent(t *testing.T) {
	device, binding := "agent_"+strings.Repeat("1", 32), strings.Repeat("2", 64)
	at := time.Date(2026, 10, 11, 1, 0, 0, 0, time.UTC)
	exists := false
	st := &fullProcessesConsentMemory{files: map[string][]byte{}}
	created := 0
	marker := &fullProcessesTestMarker{}
	open := func(create bool) (windowsfullprocesses.Storage, error) {
		if !exists {
			if !create {
				return nil, os.ErrNotExist
			}
			created++
			exists = true
		} else if create {
			return nil, errors.New("already exists")
		}
		return st, nil
	}
	configure := func(mode string) (WindowsFullProcessesConsentResult, error) {
		return updateWindowsFullProcessesConsent(device, binding, mode, open, func() time.Time { return at }, marker)
	}
	for _, mode := range []string{"preview", "disable"} {
		r, e := configure(mode)
		if e != nil || r.Enabled || created != 0 {
			t.Fatal("ungranted read initialized", mode, e)
		}
	}
	r, e := configure("enable")
	if e != nil || !r.Enabled || created != 1 || len(st.files) != 3 {
		t.Fatal("fresh initialization failed", r, e)
	}
	c, e := windowsfullprocesses.DecodeConsent(st.files["consent.json"])
	if e != nil || c.Revision != 1 || c.SenderBinding != binding {
		t.Fatal(e)
	}
	originalSender, originalPack := bytes.Clone(st.files["sender.json"]), bytes.Clone(st.files["pack.json"])
	writes := st.writes
	r, e = configure("preview")
	if e != nil || !r.Enabled || st.writes != writes {
		t.Fatal("preview mutated")
	}
	r, e = configure("enable")
	if e != nil || st.writes != writes {
		t.Fatal("idempotent enable changed grant")
	}
	at = at.Add(time.Second)
	r, e = configure("disable")
	disabled, _ := windowsfullprocesses.DecodeConsent(st.files["consent.json"])
	if e != nil || r.Enabled || disabled.Revision != 2 || disabled.GrantID != c.GrantID || !bytes.Equal(originalSender, st.files["sender.json"]) || !bytes.Equal(originalPack, st.files["pack.json"]) {
		t.Fatal("disable reset floor/pending")
	}
	at = at.Add(time.Second)
	r, e = configure("enable")
	enabled, _ := windowsfullprocesses.DecodeConsent(st.files["consent.json"])
	if e != nil || !r.Enabled || enabled.Revision != 3 || enabled.GrantID == c.GrantID {
		t.Fatal("reenable adopted old grant")
	}
	delete(st.files, "pack.json")
	if _, e = configure("enable"); e == nil || created != 1 {
		t.Fatal("used missing state recreated")
	}
	if s, e := openWindowsFullProcessesSender(Material{}, nil); e != nil || s != nil {
		t.Fatal("non-Windows default opened state")
	}
}
func TestWindowsFullProcessesSchedulingIsolation(t *testing.T) {
	r := Report{}
	if e := runWindowsFullProcessesAttempt(context.Background(), nil, &r); e != nil || r.WindowsFullProcessesStatus != "" {
		t.Fatal("ungranted scope changed old report")
	}
}

type fullProcessesTestMarker struct {
	used bool
	fail bool
}

func (m *fullProcessesTestMarker) Used() (bool, error) { return m.used, nil }
func (m *fullProcessesTestMarker) Mark() error {
	if m.fail {
		return errors.New("fixture marker write failed")
	}
	m.used = true
	return nil
}

func TestWindowsFullProcessesWholeRootLossAndInterruptedInitStayFenced(t *testing.T) {
	device, binding := "agent_"+strings.Repeat("1", 32), strings.Repeat("2", 64)
	at := time.Date(2026, 10, 11, 1, 0, 0, 0, time.UTC)
	for _, mode := range []string{"preview", "enable", "disable"} {
		marker := &fullProcessesTestMarker{used: true}
		creates := 0
		open := func(create bool) (windowsfullprocesses.Storage, error) {
			if create {
				creates++
			}
			return nil, os.ErrNotExist
		}
		if _, e := updateWindowsFullProcessesConsent(device, binding, mode, open, func() time.Time { return at }, marker); e == nil || creates != 0 {
			t.Fatal("whole-root loss recreated or disguised", mode)
		}
	}
	marker := &fullProcessesTestMarker{}
	creates := 0
	open := func(create bool) (windowsfullprocesses.Storage, error) {
		if create {
			creates++
			return nil, errors.New("injected root creation failure")
		}
		return nil, os.ErrNotExist
	}
	if _, e := updateWindowsFullProcessesConsent(device, binding, "enable", open, func() time.Time { return at }, marker); e == nil || !marker.used || creates != 1 {
		t.Fatal("marker not durable before root creation")
	}
	if _, e := updateWindowsFullProcessesConsent(device, binding, "enable", open, func() time.Time { return at }, marker); e == nil || creates != 1 {
		t.Fatal("interrupted init retried used root")
	}
	marker = &fullProcessesTestMarker{fail: true}
	creates = 0
	if _, e := updateWindowsFullProcessesConsent(device, binding, "enable", open, func() time.Time { return at }, marker); e == nil || creates != 0 {
		t.Fatal("marker failure still created scope")
	}
	// An unmarked pre-existing sidecar is not adopted as an unused grant.
	st := &fullProcessesConsentMemory{files: map[string][]byte{}}
	marker = &fullProcessesTestMarker{}
	if _, e := updateWindowsFullProcessesConsent(device, binding, "enable", func(bool) (windowsfullprocesses.Storage, error) { return st, nil }, func() time.Time { return at }, marker); e == nil || marker.used || st.writes != 0 {
		t.Fatal("orphan sidecar adopted")
	}
}
